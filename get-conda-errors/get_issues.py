#!/usr/bin/env python3
"""
Collect "Tests failed" issues from conda/conda over the past month, dig into
the linked GitHub Actions run for each one, and report the individual pytest
test failures (name + failure message) found in the logs of failed jobs.

Requires the `gh` CLI, authenticated with access to conda/conda.


You can see that most failures are from not being able to download 
repodata because of a server failure.

The summary of failures is:
    non repodata related failures - 2
    repodata download failure - 10
    other download failure - 1

"""

import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

REPO = "conda/conda"
LOOKBACK_DAYS = 30

RUN_URL_RE = re.compile(r"/actions/runs/(\d+)")
# Log lines look like: 2026-08-04T19:37:29.7774285Z FAILED tests/foo.py::bar - SomeError: message
LOG_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+FAILED\s+(?P<test>\S+::\S+)(?:\s+-\s+(?P<message>.*))?$"
)


def gh_json(*args):
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)


def gh_text(*args):
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=True
    )
    return result.stdout


def get_recent_test_failure_issues():
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    issues = gh_json(
        "issue", "list",
        "--repo", REPO,
        "--search", "Tests failed in:title",
        "--state", "open",
        "--limit", "100",
        "--json", "number,title,createdAt,url,body",
    )
    return [
        issue for issue in issues
        if datetime.fromisoformat(issue["createdAt"].replace("Z", "+00:00")) >= cutoff
    ]


def get_run_id(issue_body):
    match = RUN_URL_RE.search(issue_body or "")
    return match.group(1) if match else None


def get_failed_jobs(run_id):
    jobs = gh_json("api", f"repos/{REPO}/actions/runs/{run_id}/jobs", "--paginate")["jobs"]
    return [job for job in jobs if job["conclusion"] == "failure"]


def get_test_failures(job_id):
    try:
        log = gh_text("api", f"repos/{REPO}/actions/jobs/{job_id}/logs")
    except subprocess.CalledProcessError:
        return []

    failures = []
    for line in log.splitlines():
        match = LOG_LINE_RE.match(line)
        if match:
            failures.append(
                (match.group("test"), (match.group("message") or "").strip())
            )
    return failures


def main():
    issues = get_recent_test_failure_issues()
    if not issues:
        print(f"No 'Tests failed' issues found in the past {LOOKBACK_DAYS} days.")
        return

    print(f"Found {len(issues)} 'Tests failed' issue(s) in the past {LOOKBACK_DAYS} days.\n")

    for issue in sorted(issues, key=lambda i: i["createdAt"]):
        print(f"## #{issue['number']} - {issue['title']} ({issue['url']})")

        run_id = get_run_id(issue["body"])
        if not run_id:
            print("  (no linked run found in issue body)\n")
            continue

        try:
            failed_jobs = get_failed_jobs(run_id)
        except subprocess.CalledProcessError as e:
            print(f"  (failed to fetch jobs for run {run_id}: {e})\n")
            continue

        if not failed_jobs:
            print("  (no failed jobs found for this run)\n")
            continue

        for job in failed_jobs:
            failures = get_test_failures(job["id"])
            if not failures:
                print(f"  - {job['name']}: failed, but no pytest failures found "
                      f"(likely an infrastructure/setup failure)")
                continue

            print(f"  - {job['name']}:")
            for test_name, message in failures:
                print(f"      {test_name}")
                print(f"          {message}")
        print()


if __name__ == "__main__":
    sys.exit(main())

