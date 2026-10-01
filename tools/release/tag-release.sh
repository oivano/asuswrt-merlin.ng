#!/usr/bin/env bash
# Releases the pending Changelog-386.txt section from DEV-nextrelease:
# dates its header, syncs version.conf SERIALNO/EXTENDNO to it, commits,
# mirrors the commit to DEV, tags <version> and pushes (CircleCI builds the tag).
#
# Usage: tools/release/tag-release.sh [--dry-run] [--no-push] [--yes]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ── Config ────────────────────────────────────────────────────────────────────
SOURCE_BRANCH="DEV"
TARGET_BRANCH="DEV-nextrelease"
REMOTE="origin"
CHANGELOG="Changelog-386.txt"
VERSION_CONF="release/src-rt/version.conf"
RELEASE_HEADER_RE='^[0-9][^ ]*-ion'

# ── CLI ───────────────────────────────────────────────────────────────────────
DRY_RUN=false
PUSH=true
ASSUME_YES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --no-push) PUSH=false ;;
        --yes)     ASSUME_YES=true ;;
        *) echo "ERROR: Unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

die() { echo "ERROR: $*" >&2; exit 1; }

git show-ref --verify --quiet "refs/heads/$SOURCE_BRANCH" || die "Branch '$SOURCE_BRANCH' does not exist."
git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH" || die "Branch '$TARGET_BRANCH' does not exist."
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || \
    die "Tracked working tree files must be clean before releasing."

# ── Resolve version from the newest changelog section on TARGET ──────────────
NOTES=$(git show "$TARGET_BRANCH:$CHANGELOG" | awk -v re="$RELEASE_HEADER_RE" \
    '$0 ~ re { if (n++) exit } n')
VERSION=$(grep -m1 -oE "$RELEASE_HEADER_RE" <<< "$NOTES") || \
    die "No release header found in $TARGET_BRANCH:$CHANGELOG."

git rev-parse -q --verify "refs/tags/$VERSION" > /dev/null && \
    die "$VERSION is already tagged; promote new changes first (tools/release/promote-validated.sh)."
if git ls-remote --exit-code --tags "$REMOTE" "refs/tags/$VERSION" > /dev/null 2>&1; then
    die "$VERSION already exists on $REMOTE."
fi

base=${VERSION%-ion}
SERIALNO=${base%%_*}
EXTENDNO=0
[[ $base == *_* ]] && EXTENDNO=${base#*_}
[[ $SERIALNO =~ ^[0-9]+(\.[0-9]+)*$ && $EXTENDNO =~ ^[0-9]+$ ]] || \
    die "Cannot parse version '$VERSION' from $CHANGELOG header."
RELEASE_DATE=$(LC_ALL=C date '+%d-%b-%Y')

echo "=== tag-release.sh ==="
echo ""
echo "Release:  $VERSION ($RELEASE_DATE)   SERIALNO=$SERIALNO EXTENDNO=$EXTENDNO"
echo "Branch:   $TARGET_BRANCH @ $(git rev-parse --short=10 "$TARGET_BRANCH")"
echo ""
echo "$NOTES" | sed '1d' | tr -d '\r' | cat -s
echo ""

$DRY_RUN && echo "(dry-run — no changes made)" && exit 0

# ── Release commit on TARGET ──────────────────────────────────────────────────
ORIG_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse HEAD)
trap 'git checkout -q "$ORIG_BRANCH" 2>/dev/null || true' EXIT
git checkout -q "$TARGET_BRANCH"

# Only the "(...)" part is replaced so the changelog's CRLF endings survive
sed -i -E "0,/${RELEASE_HEADER_RE}/{/${RELEASE_HEADER_RE}/s/\([^)]*\)/(${RELEASE_DATE})/}" "$CHANGELOG"
sed -i -E -e "s/^SERIALNO=[0-9.]*/SERIALNO=${SERIALNO}/" -e "s/^EXTENDNO=[0-9]*/EXTENDNO=${EXTENDNO}/" "$VERSION_CONF"
git add -- "$CHANGELOG" "$VERSION_CONF"

if git diff --cached --quiet; then
    echo "Changelog date and version.conf already up to date."
else
    git commit -q -m "Bumped revision to $VERSION"
    rel_sha=$(git rev-parse HEAD)
    echo "Committed ${rel_sha:0:10}  Bumped revision to $VERSION"

    # Mirror to SOURCE so later promotions don't conflict on these files
    git checkout -q "$SOURCE_BRANCH"
    if git cherry-pick "$rel_sha" > /dev/null 2>&1; then
        echo "  Mirrored to $SOURCE_BRANCH as $(git rev-parse --short=10 HEAD)"
    else
        git cherry-pick --abort 2>/dev/null || true
        echo "WARNING: could not mirror release commit to $SOURCE_BRANCH; cherry-pick ${rel_sha:0:10} manually." >&2
    fi
fi

git tag "$VERSION" "$TARGET_BRANCH"
echo "Tagged   $VERSION -> $(git rev-parse --short=10 "$TARGET_BRANCH")"

# ── Push ──────────────────────────────────────────────────────────────────────
PUSH_HINT="git push --atomic $REMOTE $TARGET_BRANCH $SOURCE_BRANCH && git push $REMOTE refs/tags/$VERSION"
if ! $PUSH; then
    echo ""
    echo "Not pushed. To publish: $PUSH_HINT"
    exit 0
fi

if ! $ASSUME_YES; then
    answer=""
    read -r -p "Push $TARGET_BRANCH, $SOURCE_BRANCH and tag $VERSION to $REMOTE? [y/N] " answer || true
    if [[ $answer != [yY]* ]]; then
        echo "Not pushed. To publish: $PUSH_HINT"
        exit 0
    fi
fi

git push --atomic "$REMOTE" "$TARGET_BRANCH" "$SOURCE_BRANCH"
git push "$REMOTE" "refs/tags/$VERSION"
echo ""
echo "Pushed. CircleCI will build $VERSION."
