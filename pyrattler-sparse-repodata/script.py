import asyncio
from rattler import solve, SparseRepoData, Channel

async def main() -> None:
    # Setup sparse repodata object to represent a slice of repodata
    # originating from a local channel that has been sharded
    chn = Channel("http://127.0.0.1:40093/noarch")
    repo = SparseRepoData(chn, "noarch", "./sparse_repodata.json")

    solved_records = await solve(
        # Sources (channels or custom RepoDataSource) to use for solving
        sources=[repo, "conda-forge"],
        # The specs to solve for
        specs=["tzdata", "foo ==1"],
    )
    print("solved required dependencies:")
    for rec in solved_records:
        print(f"  * {rec.name.normalized} v{rec.version}")


if __name__ == "__main__":
    asyncio.run(main())
