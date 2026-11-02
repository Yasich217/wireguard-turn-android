#!/usr/bin/env python3
"""Remove orphaned Android releases replaced by an amended release commit."""

import argparse
import json
import os
import re
import subprocess
import urllib.error
import urllib.request


def superseded_releases(releases, head, current_tag, repo="."):
    def git(*args):
        return subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
        )

    parents = git("show", "-s", "--format=%P", head)
    if parents.returncode or len(parents.stdout.split()) != 1:
        return []
    result = []
    for release in releases:
        tag = release["tag_name"]
        if release.get("draft") or release.get("prerelease") or tag == current_tag:
            continue
        if not re.fullmatch(r"v\d+\.\d+\.\d+-\d+-[0-9a-f]{8}", tag):
            continue
        commit = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
        if commit.returncode:
            continue
        sha = commit.stdout.strip()
        ancestor = git("merge-base", "--is-ancestor", sha, head)
        if ancestor.returncode != 1:
            continue
        old_parents = git("show", "-s", "--format=%P", sha)
        if old_parents.returncode == 0 and old_parents.stdout == parents.stdout:
            result.append(release)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Delete selected releases and tags")
    args = parser.parse_args()
    repository = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]

    def api(path, method="GET"):
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/{path}",
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None

    releases = api("releases?per_page=100")
    candidates = superseded_releases(
        releases, os.environ["GITHUB_SHA"], os.environ["CURRENT_RELEASE_TAG"]
    )
    for release in candidates:
        tag = release["tag_name"]
        if not args.apply:
            print(f"Superseded release: {tag}")
            continue
        api(f"releases/{release['id']}", "DELETE")
        try:
            api(f"git/refs/tags/{tag}", "DELETE")
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        print(f"Removed superseded release and tag: {tag}")


if __name__ == "__main__":
    main()
