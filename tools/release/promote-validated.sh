#!/usr/bin/env bash
# Promotes validated DEV commits to DEV-nextrelease by cherry-pick.
# Classifies each gap commit as [validated] (in validated-commits.txt) or [local].
# Both classes are promoted; --exclude skips specific SHAs.
# On success, user-facing promoted commits are recorded in Changelog-386.txt
# (pending section) on both branches. Tagging/pushing: tools/release/tag-release.sh.
#
# Usage: tools/release/promote-validated.sh [--dry-run] [--exclude <sha>] ...

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ── Config ────────────────────────────────────────────────────────────────────
SOURCE_BRANCH="DEV"
TARGET_BRANCH="DEV-nextrelease"
OUTDIR="$SCRIPT_DIR"
VALIDATED_FILE="$OUTDIR/validated-commits.txt"
LOG_FILE="$OUTDIR/promotion-log.txt"
CHANGELOG="Changelog-386.txt"
RELEASE_HEADER_RE='^[0-9][^ ]*-ion'
SKIP_SUBJECT_RE='^(fixup!|squash!|Merge |Revert |docs:|ci:|tools:|build:|changelog:|Updated documentation)'
NON_USER_PATH_RE='^(tools/|\.circleci/|\.github/|[^/]*\.md$|Changelog-386\.txt$|\.gitignore$)'

# ── CLI ───────────────────────────────────────────────────────────────────────
DRY_RUN=false
EXCLUDE_SHAS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --exclude)
            [[ -z "${2:-}" ]] && { echo "ERROR: --exclude requires a SHA" >&2; exit 1; }
            EXCLUDE_SHAS+=("$2"); shift
            ;;
        *) echo "ERROR: Unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

# ── Helpers ───────────────────────────────────────────────────────────────────
die() { echo "ERROR: $*" >&2; exit 1; }

changelog_top_version() {
    grep -m1 -oE "$RELEASE_HEADER_RE" "$CHANGELOG"
}

# 386.15_4-ion -> 386.15_5-ion ; 386.15-ion -> 386.15_1-ion
next_version() {
    local base=${1%-ion} n=0
    [[ $base == *_* ]] && n=${base#*_}
    echo "${base%%_*}_$((n + 1))-ion"
}

# Prints a formatted changelog entry for a commit, or nothing if not user-facing.
changelog_entry() {
    local sha=$1 subject lc type
    subject=$(git log -1 --format=%s "$sha")
    [[ $subject =~ $SKIP_SUBJECT_RE ]] && return 0
    git diff-tree --no-commit-id --name-only -r "$sha" | grep -qvE "$NON_USER_PATH_RE" || return 0

    lc=${subject,,}
    if   [[ $lc =~ (fix|cve|prevent|leak|crash) ]]; then type=FIXED
    elif [[ $lc =~ (updat|upgrad|bump) ]];           then type=UPDATED
    elif [[ $lc =~ (^|[^a-z])(add|added|new|support)([^a-z]|$) ]]; then type=ADDED
    else type=CHANGED
    fi

    printf '%s\n' "${subject%.}." | fold -s -w 59 | sed -e 's/ *$//' \
        -e "1s/^/  - $(printf '%-9s' "$type:")/" -e '2,$s/^/             /'
}

# Writes entries for TO_PROMOTE (not already in the changelog) to $1.
build_changelog_entries() {
    local out=$1 sha entry
    : > "$out"
    for sha in "${TO_PROMOTE[@]}"; do
        entry=$(changelog_entry "$sha")
        [[ -z $entry ]] && continue
        grep -qF -- "${entry%%$'\n'*}" "$CHANGELOG" && continue
        printf '%s\n' "$entry" >> "$out"
    done
}

# Appends to the pending (untagged) section, or opens a new one if the top one is tagged.
update_changelog() {
    local entries=$1 top_ver top_line last
    top_ver=$(changelog_top_version) || die "No release header found in $CHANGELOG."
    top_line=$(grep -nE -m1 "$RELEASE_HEADER_RE" "$CHANGELOG" | cut -d: -f1)
    # Changelog-386.txt is CRLF; keep inserted lines consistent
    if sed -n "${top_line}p" "$CHANGELOG" | grep -q $'\r$'; then
        sed -i 's/$/\r/' "$entries"
    fi

    if git rev-parse -q --verify "refs/tags/$top_ver" > /dev/null; then
        { printf '%s (unreleased)\r\n' "$(next_version "$top_ver")"; cat "$entries"; printf '\r\n\r\n'; } > "$entries.new"
        grep -q $'\r$' "$entries" || sed -i 's/\r$//' "$entries.new"
        sed -i "$((top_line - 1))r $entries.new" "$CHANGELOG"
        rm -f "$entries.new"
    else
        last=$(awk -v t="$top_line" -v re="$RELEASE_HEADER_RE" \
            '{ sub(/\r$/, "") } NR > t && $0 ~ re { exit } NR >= t && NF { l = NR } END { print l }' "$CHANGELOG")
        sed -i "${last}r $entries" "$CHANGELOG"
    fi
}

pending_section_label() {
    local top_ver
    top_ver=$(changelog_top_version) || die "No release header found in $CHANGELOG."
    if git rev-parse -q --verify "refs/tags/$top_ver" > /dev/null; then
        echo "new section $(next_version "$top_ver")"
    else
        echo "pending section $top_ver"
    fi
}

git show-ref --verify --quiet "refs/heads/$SOURCE_BRANCH" || \
    die "Source branch '$SOURCE_BRANCH' does not exist."
git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH" || \
    die "Target branch '$TARGET_BRANCH' does not exist."

# ── Gate: must be on SOURCE_BRANCH ───────────────────────────────────────────
current=$(git symbolic-ref --short HEAD 2>/dev/null || echo "(detached)")
[[ "$current" == "$SOURCE_BRANCH" ]] || \
    die "Must be on $SOURCE_BRANCH (currently on $current). Run: git checkout $SOURCE_BRANCH"

if ! $DRY_RUN && [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    die "Tracked working tree files must be clean before promotion."
fi

# ── Load validated-commits.txt (local SHA → validated) ───────────────────────
declare -A VALIDATED_MAP
if [[ -f "$VALIDATED_FILE" ]]; then
    while read -r local_sha rest; do
        [[ -z "$local_sha" || "${local_sha:0:1}" == "#" ]] && continue
        VALIDATED_MAP["$local_sha"]="1"
    done < "$VALIDATED_FILE"
fi

# ── Expand --exclude SHAs to full 40-char ────────────────────────────────────
declare -A EXCLUDE_MAP
for short in "${EXCLUDE_SHAS[@]}"; do
    full=$(git rev-parse "$short" 2>/dev/null) || \
        { echo "WARNING: cannot resolve --exclude SHA '$short'" >&2; continue; }
    EXCLUDE_MAP["$full"]="1"
done

# ── Compute patch-equivalent gap in chronological order ─────────────────────
echo "=== promote-validated.sh ==="
echo ""
$DRY_RUN && echo "(dry-run — no changes will be made)" && echo ""

if git diff --quiet "$TARGET_BRANCH" "$SOURCE_BRANCH"; then
    echo "$TARGET_BRANCH is already up to date with $SOURCE_BRANCH."
    exit 0
fi

mapfile -t GAP_SHAS < <(
    git log --format="%H" --reverse --right-only --cherry-pick --no-merges \
        "$TARGET_BRANCH...$SOURCE_BRANCH"
)
TOTAL=${#GAP_SHAS[@]}

if [[ $TOTAL -eq 0 ]]; then
    echo "$TARGET_BRANCH is already up to date with $SOURCE_BRANCH."
    exit 0
fi

echo "Gap: $SOURCE_BRANCH → $TARGET_BRANCH  ($TOTAL commit(s))"
echo ""

# ── Classify and list ─────────────────────────────────────────────────────────
declare -a TO_PROMOTE
N_EXCLUDED=0

for sha in "${GAP_SHAS[@]}"; do
    subject=$(git log -1 --format="%s" "$sha")

    if [[ -n "${EXCLUDE_MAP[$sha]:-}" ]]; then
        printf "  [excluded]     %s  %s\n" "${sha:0:10}" "$subject"
        (( N_EXCLUDED++ )) || true
        continue
    fi

    if [[ -n "${VALIDATED_MAP[$sha]:-}" ]]; then
        label="[validated]"
    else
        label="[local]"
    fi

    printf "  %-15s %s  %s\n" "$label" "${sha:0:10}" "$subject"
    TO_PROMOTE+=("$sha")
done

N_PROMOTE=${#TO_PROMOTE[@]}
echo ""
echo "  To promote: $N_PROMOTE   Excluded: $N_EXCLUDED"
echo ""

[[ $N_PROMOTE -eq 0 ]] && echo "Nothing to promote." && exit 0

if $DRY_RUN; then
    preview=$(mktemp)
    build_changelog_entries "$preview"
    echo "Changelog additions ($(pending_section_label)):"
    if [[ -s $preview ]]; then cat "$preview"; else echo "  (none)"; fi
    rm -f "$preview"
    exit 0
fi

# ── Cherry-pick onto TARGET_BRANCH ───────────────────────────────────────────
echo "Promoting $N_PROMOTE commit(s) from $SOURCE_BRANCH to $TARGET_BRANCH..."
SOURCE_START=$(git rev-parse "$SOURCE_BRANCH")
TARGET_START=$(git rev-parse "$TARGET_BRANCH")
git checkout "$TARGET_BRANCH"

PROMOTED=0
RUN_HEADER="$(date -u '+%Y-%m-%dT%H:%M:%SZ')  $SOURCE_BRANCH → $TARGET_BRANCH"
RUN_LOG=$(mktemp)
CL_ENTRIES=$(mktemp)

cleanup() {
    rm -f "$RUN_LOG" "$CL_ENTRIES"
    if [[ "$(git symbolic-ref --short HEAD 2>/dev/null || true)" != "$SOURCE_BRANCH" ]]; then
        git checkout -q "$SOURCE_BRANCH" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

for sha in "${TO_PROMOTE[@]}"; do
    subject=$(git log -1 --format="%s" "$sha")
    if git cherry-pick "$sha" > /dev/null 2>&1; then
        new_sha=$(git rev-parse HEAD)
        echo "  OK   ${new_sha:0:10}  (from ${sha:0:10})  $subject"
        printf "PROMOTED  %s  (from %s)  %s\n" "$new_sha" "$sha" "$subject" >> "$RUN_LOG"
        (( PROMOTED++ )) || true
    else
        echo "  FAIL ${sha:0:10}  $subject" >&2
        git cherry-pick --abort 2>/dev/null || true
        git reset --hard "$TARGET_START" > /dev/null
        mkdir -p "$OUTDIR"
        printf "\n## %s\nFAILED    %s  %s\n" "$RUN_HEADER" "$sha" "$subject" >> "$LOG_FILE"
        die "Promotion failed; $TARGET_BRANCH was rolled back to ${TARGET_START:0:10}."
    fi
done

[[ "$(git rev-parse "$SOURCE_BRANCH")" == "$SOURCE_START" ]] || \
    die "$SOURCE_BRANCH changed during promotion; inspect the repository before releasing."

# $OUTDIR may not exist on $TARGET_BRANCH
mkdir -p "$OUTDIR"
printf "\n## %s\n" "$RUN_HEADER" >> "$LOG_FILE"
cat "$RUN_LOG" >> "$LOG_FILE"

echo ""
echo "Promoted: $PROMOTED   Failed: 0"
echo "  Log: $LOG_FILE"

# ── Changelog: commit on TARGET, mirror to SOURCE (patch-equivalent, so never re-promoted)
build_changelog_entries "$CL_ENTRIES"
if [[ -s $CL_ENTRIES ]]; then
    label=$(pending_section_label)
    update_changelog "$CL_ENTRIES"
    git commit -q -m "changelog: record promoted changes" -- "$CHANGELOG"
    cl_sha=$(git rev-parse HEAD)
    echo ""
    echo "Changelog updated ($label) in ${cl_sha:0:10} — review before tagging:"
    cat "$CL_ENTRIES"

    git checkout -q "$SOURCE_BRANCH"
    if git cherry-pick "$cl_sha" > /dev/null 2>&1; then
        echo "  Mirrored to $SOURCE_BRANCH as $(git rev-parse --short=10 HEAD)"
    else
        git cherry-pick --abort 2>/dev/null || true
        echo "WARNING: could not mirror changelog commit to $SOURCE_BRANCH; cherry-pick ${cl_sha:0:10} manually." >&2
    fi
else
    echo "No user-facing changes to add to $CHANGELOG."
fi

# Return to source branch
git checkout -q "$SOURCE_BRANCH"

exit 0
