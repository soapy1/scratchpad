import asyncio
from asyncio import StreamReader, StreamWriter
import datetime
import ipaddress
import logging
import re
import ssl
import tempfile
import zlib
from compression import zstd
from pathlib import Path

import brotli
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

logging.basicConfig(level=logging.INFO)

CERT_DIR = Path(__file__).parent / 'certs'
CA_CERT_PATH = CERT_DIR / 'ca.crt'
CA_KEY_PATH = CERT_DIR / 'ca.key'
STREAM_LIMIT = 1 << 20  # max header size
CAPTURE_LIMIT = 1 << 20  # bytes of each response body kept in memory for printing
PRINT_LIMIT = 5000  # max characters of each response body printed; None = no limit

# ---------------------------------------------------------------------------
# certificates


def load_or_create_ca():
    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), None)
        return cert, key

    CERT_DIR.mkdir(exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'proxy2 MITM CA')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    CA_KEY_PATH.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    CA_KEY_PATH.chmod(0o600)
    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f'Created new CA certificate at {CA_CERT_PATH} - install it on clients')
    return cert, key


CA_CERT, CA_KEY = load_or_create_ca()
LEAF_KEY = ec.generate_private_key(ec.SECP256R1())  # one key shared by all host certs
LEAF_DIR = Path(tempfile.mkdtemp(prefix='proxy2-'))
_server_ctx_cache: dict[str, ssl.SSLContext] = {}


def server_context_for(host: str) -> ssl.SSLContext:
    """TLS context presented to the client, with a cert for `host` signed by our CA."""
    if host in _server_ctx_cache:
        return _server_ctx_cache[host]

    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
        .issuer_name(CA_CERT.subject)
        .public_key(LEAF_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(CA_KEY.public_key()), critical=False)
        .sign(CA_KEY, hashes.SHA256())
    )

    # ssl only loads certs from files
    safe = ''.join(c if c.isalnum() or c in '.-' else '_' for c in host)
    cert_path = LEAF_DIR / f'{safe}.pem'
    cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + CA_CERT.public_bytes(serialization.Encoding.PEM)
        + LEAF_KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path)
    ctx.set_alpn_protocols(['http/1.1'])  # we only parse HTTP/1.x
    _server_ctx_cache[host] = ctx
    return ctx


# TLS context for talking to the real server; verifies its certificate normally
UPSTREAM_CTX = ssl.create_default_context()
UPSTREAM_CTX.set_alpn_protocols(['http/1.1'])

# ---------------------------------------------------------------------------
# forwarding


async def pipe(r: StreamReader, w: StreamWriter):
    try:
        while not r.at_eof():
            w.write(await r.read(4096))
            await w.drain()
    finally:
        w.close()


def keep(capture: bytearray | None, data: bytes):
    """Save the start of a body for printing, up to CAPTURE_LIMIT bytes."""
    if capture is not None and len(capture) < CAPTURE_LIMIT:
        capture += data[:CAPTURE_LIMIT - len(capture)]


async def copy_exact(r: StreamReader, w: StreamWriter, n: int,
                     capture: bytearray | None = None) -> int:
    """Copy exactly n bytes without holding them all in memory."""
    total = n
    while n > 0:
        data = await r.readexactly(min(n, 65536))
        w.write(data)
        await w.drain()
        keep(capture, data)
        n -= len(data)
    return total


async def copy_chunked(r: StreamReader, w: StreamWriter,
                       capture: bytearray | None = None) -> int:
    """Copy a Transfer-Encoding: chunked body, including trailers."""
    total = 0
    while True:
        size_line = await r.readuntil(b'\r\n')
        w.write(size_line)
        size = int(size_line.split(b';')[0].strip(), 16)
        if size == 0:
            # trailers, terminated by an empty line
            while (line := await r.readuntil(b'\r\n')) != b'\r\n':
                w.write(line)
            w.write(b'\r\n')
            return total
        total += await copy_exact(r, w, size, capture)
        await copy_exact(r, w, 2)  # CRLF after each chunk


async def copy_until_eof(r: StreamReader, w: StreamWriter,
                         capture: bytearray | None = None) -> int:
    total = 0
    while data := await r.read(65536):
        w.write(data)
        await w.drain()
        keep(capture, data)
        total += len(data)
    return total


def decompress(data: bytes, content_encoding: str) -> bytes:
    """Undo Content-Encoding. Works on truncated data (returns what it can)."""
    encodings = [e.strip().lower() for e in content_encoding.split(',') if e.strip()]
    for enc in reversed(encodings):  # applied in order listed, so undo in reverse
        if enc in ('gzip', 'x-gzip'):
            data = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data)
        elif enc == 'deflate':
            try:
                data = zlib.decompressobj().decompress(data)
            except zlib.error:  # some servers send raw deflate without zlib header
                data = zlib.decompressobj(-zlib.MAX_WBITS).decompress(data)
        elif enc == 'br':
            data = brotli.Decompressor().process(data)
        elif enc == 'zstd':
            data = zstd.ZstdDecompressor().decompress(data)
        elif enc != 'identity':
            raise ValueError(f'unsupported Content-Encoding {enc!r}')
    return data


TEXT_TYPES = ('json', 'xml', 'javascript', 'x-www-form-urlencoded', 'graphql', 'yaml', 'csv')


def print_body(prefix: str, headers: dict[str, str], body: bytes, total: int):
    if total == 0:
        return
    ctype = headers.get('content-type', '')
    try:
        data = decompress(body, headers.get('content-encoding', ''))
    except Exception as e:
        print(f'{prefix} body: {total} bytes, could not decompress ({e})', flush=True)
        return

    textual = ctype.startswith('text/') or any(t in ctype for t in TEXT_TYPES)
    charset = re.search(r'charset="?([\w-]+)', ctype)
    try:
        text = data.decode(charset.group(1) if charset else 'utf-8',
                           errors='replace' if textual else 'strict')
    except (UnicodeDecodeError, LookupError):
        text = None
    if text is None or (not textual and '\x00' in text):
        print(f'{prefix} body: {total} bytes of {ctype or "binary data"} (not shown)', flush=True)
        return

    truncated = total > len(body) or (PRINT_LIMIT is not None and len(text) > PRINT_LIMIT)
    if PRINT_LIMIT is not None:
        text = text[:PRINT_LIMIT]
    print(f'{prefix} body: {total} bytes' + (' (truncated)' if truncated else '') + ':\n'
          + '\n'.join(f'    | {line}' for line in text.splitlines()), flush=True)


def parse_headers(lines: list[str]) -> dict[str, str]:
    headers = {}
    for line in lines:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return headers


async def forward_responses(client_ip: str, rr: StreamReader, lw: StreamWriter,
                            pending: asyncio.Queue):
    """Forward server->client traffic one HTTP response at a time, logging each status."""
    try:
        while True:
            try:
                head = await rr.readuntil(b'\r\n\r\n')
            except asyncio.IncompleteReadError as e:
                lw.write(e.partial)
                break  # server closed the connection

            lines = head.decode('latin-1').split('\r\n')
            parts = lines[0].split(' ', 2)
            code = int(parts[1])
            reason = parts[2] if len(parts) > 2 else ''
            headers = parse_headers(lines[1:])
            lw.write(head)

            if 100 <= code < 200 and code != 101:
                continue  # interim response (e.g. 100 Continue); real one follows

            method, url = pending.get_nowait() if not pending.empty() else ('?', '?')
            prefix = f'{client_ip} {code} {reason} <- {method} {url}'
            print(prefix, flush=True)
            for line in lines[1:]:
                if line:
                    print(f'    {line}', flush=True)

            body = bytearray()
            if method == 'HEAD' or code in (204, 304):
                continue  # no body
            elif code == 101:
                await pipe(rr, lw)  # switched protocols: raw bytes from here on
                return
            elif 'chunked' in headers.get('transfer-encoding', '').lower():
                total = await copy_chunked(rr, lw, body)
            elif 'content-length' in headers:
                total = await copy_exact(rr, lw, int(headers['content-length']), body)
            else:
                total = await copy_until_eof(rr, lw, body)  # body runs until server closes
                print_body(prefix, headers, body, total)
                return
            await lw.drain()
            print_body(prefix, headers, body, total)
    finally:
        lw.close()


async def forward_requests(client_ip: str, lr: StreamReader, rw: StreamWriter, base_url: str,
                           pending: asyncio.Queue):
    """Forward client->server traffic one HTTP request at a time, logging each URL."""
    try:
        while True:
            try:
                head = await lr.readuntil(b'\r\n\r\n')
            except asyncio.IncompleteReadError:
                break  # client closed the connection

            lines = head.decode('latin-1').split('\r\n')
            method, target = lines[0].split(' ')[:2]
            url = target if '://' in target else base_url + target
            header_lines = [line for line in lines[1:] if line]
            print(f'{client_ip} {method} {url}', flush=True)
            for line in header_lines:
                print(f'    {line}', flush=True)

            headers = parse_headers(lines[1:])

            pending.put_nowait((method, url))  # so the response can be matched up
            rw.write(head)
            if 'chunked' in headers.get('transfer-encoding', '').lower():
                await copy_chunked(lr, rw)
            elif 'content-length' in headers:
                await copy_exact(lr, rw, int(headers['content-length']))
            await rw.drain()

            if 'upgrade' in headers:
                # e.g. websockets: no longer HTTP after this, so just copy bytes
                await pipe(lr, rw)
                return
    finally:
        rw.close()


# handle every connection


async def conn_handler(lr: StreamReader, lw: StreamWriter):
    client_ip = lw.get_extra_info("peername")[0]
    try:
        # for HTTPS: decrypt with our own cert, re-encrypt to the real server
        first = await lr.readuntil(b'\r\n\r\n')
        request_line = first.decode('latin-1').split('\r\n', 1)[0]
        if request_line.startswith('CONNECT'):
            host, port = request_line.split(' ')[1].rsplit(':', 1)
            host = host.strip('[]')  # IPv6 literals
            rr, rw = await asyncio.open_connection(
                host, int(port), ssl=UPSTREAM_CTX, server_hostname=host, limit=STREAM_LIMIT)
            lw.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await lw.drain()
            await lw.start_tls(server_context_for(host))
            base_url = f'https://{host}' + ('' if port == '443' else f':{port}')
            pending = asyncio.Queue()
            await asyncio.gather(
                forward_requests(client_ip, lr, rw, base_url, pending),
                forward_responses(client_ip, rr, lw, pending))
        # for HTTP
        else:
            host_header = next(
                line.split(':', 1)[1].strip()
                for line in first.decode('latin-1').split('\r\n')
                if line.lower().startswith('host:'))
            host, _, port = host_header.partition(':')
            rr, rw = await asyncio.open_connection(host, int(port or 80), limit=STREAM_LIMIT)
            # put the already-read request back in front of the stream
            buffered = StreamReader(limit=STREAM_LIMIT)
            buffered.feed_data(first)

            async def rest():
                try:
                    while not lr.at_eof():
                        buffered.feed_data(await lr.read(4096))
                finally:
                    buffered.feed_eof()

            pending = asyncio.Queue()
            await asyncio.gather(
                rest(),
                forward_requests(client_ip, buffered, rw, f'http://{host_header}', pending),
                forward_responses(client_ip, rr, lw, pending))
    except ConnectionError as e:
        logging.debug(f'{client_ip}: {e!r}')  # normal client/server hangups
    except ssl.SSLError as e:
        logging.error(f'{client_ip}: {e!r}')
    except Exception as e:
        logging.error(f'{client_ip}: {e!r}')
    finally:
        lw.close()


async def main():
    server = await asyncio.start_server(conn_handler, '0.0.0.0', 5000, limit=STREAM_LIMIT)
    print(
        f'Server ready listen at port {server.sockets[0].getsockname()[1]}')
    print(f'Clients must trust {CA_CERT_PATH} for HTTPS interception')
    await server.serve_forever()
try:
    asyncio.run(main())
except KeyboardInterrupt:
    exit(1)
except Exception as e:
    logging.error(e)
