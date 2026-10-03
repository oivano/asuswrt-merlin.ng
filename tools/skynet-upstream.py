#!/usr/bin/env python3
"""Report upstream changes for review; never translate or apply patches."""

import argparse
import bisect
import json
from pathlib import Path
import re
import subprocess


def git(checkout, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(checkout), *arguments], text=True
    )


def function_index(source):
    names = ["<global>"]
    starts = [1]
    for number, line in enumerate(source.splitlines(), 1):
        match = re.match(r"^([A-Za-z_][A-Za-z_0-9]*)\(\)\s*\{", line)
        if match:
            starts.append(number)
            names.append(match.group(1))
    return starts, names


def touched_functions(patch, old_source, new_source):
    old_starts, old_names = function_index(old_source)
    new_starts, new_names = function_index(new_source)
    touched = set()
    for line in patch.splitlines():
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
        if not match:
            continue
        for start, count, starts, names in (
            (int(match[1]), int(match[2] or 1), old_starts, old_names),
            (int(match[3]), int(match[4] or 1), new_starts, new_names),
        ):
            if not count:
                continue
            position = max(0, bisect.bisect_right(starts, start) - 1)
            while position < len(starts) and starts[position] <= start + count - 1:
                touched.add(names[position])
                position += 1
    return touched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path, help="separate upstream git checkout")
    parser.add_argument("--candidate", default="HEAD", help="candidate upstream commit or tag")
    arguments = parser.parse_args()
    if arguments.candidate.startswith("-"):
        parser.error("candidate must be a commit or tag, not a git option")
    package = Path(__file__).resolve().parents[1] / "release/src/router/skynet"
    manifest = json.loads((package / "UPSTREAM.json").read_text())
    try:
        baseline = git(arguments.checkout, "rev-parse", "--verify", manifest["commit"] + "^{commit}").strip()
        candidate = git(arguments.checkout, "rev-parse", "--verify", arguments.candidate + "^{commit}").strip()
        changed = git(arguments.checkout, "diff", "--name-only", baseline, candidate, "--").splitlines()
        patch = git(arguments.checkout, "diff", "--unified=0", baseline, candidate, "--", "firewall.sh")
        touched = touched_functions(
            patch,
            git(arguments.checkout, "show", baseline + ":firewall.sh"),
            git(arguments.checkout, "show", candidate + ":firewall.sh"),
        )
    except subprocess.CalledProcessError:
        parser.error("checkout must contain both the pinned and candidate commits; fetch them in that checkout first")
    review = []
    mapped = set()
    for feature in manifest["features"]:
        functions = touched.intersection(feature["upstream_functions"])
        mapped.update(feature["upstream_functions"])
        for filename in feature["native_files"]:
            if not (package / filename).is_file():
                parser.error("missing native owner: " + filename)
        if functions:
            review.append({
                "feature": feature["name"], "state": feature["state"],
                "upstream_functions": sorted(functions), "native_files": feature["native_files"],
                "contracts": feature.get("contracts", []),
            })
    print(json.dumps({
        "baseline": baseline, "candidate": candidate, "changed_files": changed,
        "review": review, "unmapped_functions": sorted(touched - mapped),
        "requires_manual_review": bool(changed), "pin_changed": False,
    }, indent=2))


if __name__ == "__main__":
    main()