#!/usr/bin/env python3
"""Report open upstream pull requests for conda-forge feedstocks that soapy1 maintains.

Steps:
1. List soapy1's GitHub repos suffixed with "-feedstock" (forks used to submit PRs
   to conda-forge feedstocks).
2. For each, read .recipe_maintainers.json to see if soapy1 is listed as a maintainer.
3. For feedstocks soapy1 maintains, list open PRs on the upstream conda-forge/<repo>.
4. Print a report of each maintained feedstock and its open upstream PRs.
"""

import base64
import json
import subprocess
import sys

GITHUB_USER = "soapy1"
UPSTREAM_ORG = "conda-forge"


def gh_json(args):
    """Run a gh CLI command and parse its JSON stdout."""
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)


def get_feedstock_repos(user):
    """Return names of the user's repos ending in '-feedstock'."""
    result = subprocess.run(
        [
            "gh",
            "api",
            f"users/{user}/repos",
            "--paginate",
            "-q",
            ".[].name",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    names = result.stdout.splitlines()
    return sorted(name for name in names if name.endswith("-feedstock"))


def get_recipe_maintainers(user, repo):
    """Return the set of maintainer usernames from .recipe_maintainers.json, or None if absent."""
    result = subprocess.run(
        ["gh", "api", f"repos/{user}/{repo}/contents/.recipe_maintainers.json", "-q", ".content"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        content = base64.b64decode(result.stdout.strip()).decode("utf-8")
        maintainers = json.loads(content)
    except (ValueError, json.JSONDecodeError):
        return None
    return set(maintainers.keys())


def get_open_upstream_prs(repo):
    """Return open PRs (number, title, url) on conda-forge/<repo>."""
    return gh_json(
        [
            "pr",
            "list",
            "--repo",
            f"{UPSTREAM_ORG}/{repo}",
            "--state",
            "open",
            "--json",
            "number,title,url",
        ]
    )


def main():
    print(f"Finding -feedstock repos owned by {GITHUB_USER}...", file=sys.stderr)
    feedstocks = get_feedstock_repos(GITHUB_USER)

    maintained = []
    for repo in feedstocks:
        maintainers = get_recipe_maintainers(GITHUB_USER, repo)
        if maintainers and GITHUB_USER in maintainers:
            maintained.append(repo)

    print(f"\n{GITHUB_USER} maintains {len(maintained)} feedstock(s):\n")

    for repo in maintained:
        upstream = f"{UPSTREAM_ORG}/{repo}"
        prs = get_open_upstream_prs(repo)
        print(f"## {repo}")
        print(f"Upstream: https://github.com/{upstream}")
        if prs:
            print(f"Open PRs ({len(prs)}):")
            for pr in prs:
                print(f"  - #{pr['number']} {pr['title']}: {pr['url']}")
        else:
            print(f"Open PRs: none — https://github.com/{upstream}/pulls")
        print()


if __name__ == "__main__":
    main()
