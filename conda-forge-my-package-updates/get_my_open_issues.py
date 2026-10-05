#!/usr/bin/env python3
"""Report open upstream pull requests for conda-forge feedstocks that soapy1 maintains.

Steps:
1. List soapy1's forked GitHub repos suffixed with "-feedstock" (forks used to submit
   PRs to conda-forge feedstocks).
2. For each, in batched GraphQL queries against the upstream conda-forge/<repo>, read
   .recipe_maintainers.json and the open PRs.
3. Print a report of each feedstock soapy1 maintains and its open upstream PRs.
"""

import json
import subprocess
import sys

GITHUB_USER = "soapy1"
UPSTREAM_ORG = "conda-forge"
# Number of repositories looked up per GraphQL query. Larger batches risk HTTP 504s.
BATCH_SIZE = 50
MAX_PRS = 100

FORKS_QUERY = """
query($login: String!, $endCursor: String) {
  user(login: $login) {
    repositories(first: 100, isFork: true, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { name }
    }
  }
}
"""

REPO_FRAGMENT = """
  r{index}: repository(owner: {owner}, name: {name}) {{
    name
    maintainers: object(expression: "HEAD:.recipe_maintainers.json") {{ ... on Blob {{ text }} }}
    pullRequests(states: OPEN, first: {max_prs}, orderBy: {{field: CREATED_AT, direction: ASC}}) {{
      totalCount
      nodes {{ number title url }}
    }}
  }}
"""


def gh_graphql(query, variables=None, paginate=False):
    """Run a GraphQL query via the gh CLI and parse its JSON stdout.

    With paginate=True, returns a list of response pages.
    """
    args = ["gh", "api", "graphql", "-f", f"query={query}"]
    for key, value in (variables or {}).items():
        args += ["-F", f"{key}={value}"]
    if paginate:
        args += ["--paginate", "--slurp"]
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def get_feedstock_forks(user):
    """Return names of the user's forked repos ending in '-feedstock'."""
    pages = gh_graphql(FORKS_QUERY, {"login": user}, paginate=True)
    names = (
        node["name"]
        for page in pages
        for node in page["data"]["user"]["repositories"]["nodes"]
    )
    return sorted(name for name in names if name.endswith("-feedstock"))


def get_upstream_feedstocks(repos):
    """Return upstream repo info (name, maintainers, pullRequests) for each repo.

    Repos that don't exist upstream are omitted.
    """
    results = []
    for start in range(0, len(repos), BATCH_SIZE):
        batch = repos[start : start + BATCH_SIZE]
        fragments = "".join(
            REPO_FRAGMENT.format(
                index=i,
                owner=json.dumps(UPSTREAM_ORG),
                name=json.dumps(repo),
                max_prs=MAX_PRS,
            )
            for i, repo in enumerate(batch)
        )
        # A missing upstream repo makes gh exit non-zero but still returns the
        # other repos' data, with null for the missing one.
        result = subprocess.run(
            ["gh", "api", "graphql", "-f", f"query={{{fragments}}}"],
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout).get("data") if result.stdout else None
        if data is None:
            sys.exit(f"GraphQL query failed: {result.stderr.strip()}")
        results.extend(repo for repo in data.values() if repo)
    return results


def parse_maintainers(blob):
    """Return the set of maintainer usernames from a .recipe_maintainers.json blob."""
    if not blob:
        return set()
    try:
        return set(json.loads(blob["text"]).keys())
    except (ValueError, AttributeError, TypeError):
        return set()


def main():
    print(f"Finding -feedstock forks owned by {GITHUB_USER}...", file=sys.stderr)
    feedstocks = get_feedstock_forks(GITHUB_USER)

    print(f"Querying {len(feedstocks)} upstream feedstock(s)...", file=sys.stderr)
    maintained = [
        repo
        for repo in get_upstream_feedstocks(feedstocks)
        if GITHUB_USER in parse_maintainers(repo["maintainers"])
    ]

    print(f"\n{GITHUB_USER} maintains {len(maintained)} feedstock(s):\n")

    for repo in maintained:
        upstream = f"{UPSTREAM_ORG}/{repo['name']}"
        prs = repo["pullRequests"]["nodes"]
        total = repo["pullRequests"]["totalCount"]
        print(f"## {repo['name']}")
        print(f"Upstream: https://github.com/{upstream}")
        if prs:
            print(f"Open PRs ({total}):")
            for pr in prs:
                print(f"  - #{pr['number']} {pr['title']}: {pr['url']}")
            if total > len(prs):
                print(f"  ... and {total - len(prs)} more: https://github.com/{upstream}/pulls")
        else:
            print(f"Open PRs: none — https://github.com/{upstream}/pulls")
        print()


if __name__ == "__main__":
    main()
