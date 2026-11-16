#!/usr/bin/env bash
# Promotes validated DEV commits to DEV-nextrelease by cherry-pick.
# Classifies each gap commit as [validated] (in validated-commits.txt) or [local].
# Both classes are promoted; --exclude skips specific SHAs.
# On success, a curated pending section in Changelog-386.txt is carried to the
# target and mirrored to the source. If none exists, entries are generated from
# promoted commits. Tagging/pushing: tools/release/tag-release.sh.
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
PROMOTION_SCRIPT_PATH="tools/release/promote-validated.sh"
RELEASE_HEADER_RE='^[0-9][^ ]*-ion'
SKIP_SUBJECT_RE='^(fixup!|squash!|Merge |Revert |docs:|ci:|tools:|build:|changelog:|Updated documentation)'
NON_USER_PATH_RE='^(tools/|\.circleci/|\.github/|[^/]*\.md$|Changelog-386\.txt$|\.gitignore$)'

# ── CLI ───────────────────────────────────────────────────────────────────────
DRY_RUN=false
SYNC_CHANGELOG=false
EXCLUDE_SHAS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --sync-changelog) SYNC_CHANGELOG=true ;;
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

changelog_top_header() {
    grep -m1 -E "$RELEASE_HEADER_RE" "$1" | tr -d '\r'
}

extract_top_changelog_section() {
    local input=$1 output=$2
    awk -v re="$RELEASE_HEADER_RE" '
        {
            normalized = $0
            sub(/\r$/, "", normalized)
            if (normalized ~ re) {
                if (found) exit
                found = 1
            }
            if (found) print
        }
    ' "$input" > "$output"
}

install_curated_changelog_section() {
    local section=$1 version=$2 target_version top_line next_line temp
    target_version=$(changelog_top_version) || die "No release header found in $CHANGELOG."
    top_line=$(grep -nE -m1 "$RELEASE_HEADER_RE" "$CHANGELOG" | cut -d: -f1)
    temp=$(mktemp)

    if [[ "$target_version" == "$version" ]]; then
        next_line=$(awk -v t="$top_line" -v re="$RELEASE_HEADER_RE" \
            'NR > t { line = $0; sub(/\r$/, "", line); if (line ~ re) { print NR; exit } }' "$CHANGELOG")
        if [[ -n "$next_line" ]]; then
            { cat "$section"; sed -n "${next_line},\$p" "$CHANGELOG"; } > "$temp"
        else
            cat "$section" > "$temp"
        fi
    elif git rev-parse -q --verify "refs/tags/$target_version" > /dev/null; then
        {
            sed -n "1,$((top_line - 1))p" "$CHANGELOG"
            cat "$section"
            printf '\r\n'
            sed -n "${top_line},\$p" "$CHANGELOG"
        } > "$temp"
    else
        rm -f "$temp"
        die "Target has pending section '$target_version', not curated section '$version'."
    fi

    mv "$temp" "$CHANGELOG"
}

sync_changelog_from_target() {
    local dirty_paths unexpected_paths target_file target_header
    dirty_paths=$({ git diff --name-only; git diff --cached --name-only; } | sort -u)
    unexpected_paths=$(printf '%s\n' "$dirty_paths" | \
        grep -vxF "$CHANGELOG" | grep -vxF "$PROMOTION_SCRIPT_PATH" || true)
    [[ -z "$unexpected_paths" ]] || \
        die "Tracked files other than $CHANGELOG must be clean to sync it: ${unexpected_paths//$'\n'/, }."
    git diff --cached --quiet || \
        die "Unstage changes before syncing $CHANGELOG."

    target_file=$(mktemp)
    git show "$TARGET_BRANCH:$CHANGELOG" > "$target_file" || {
        rm -f "$target_file"
        die "Unable to read $TARGET_BRANCH:$CHANGELOG."
    }
    target_header=$(changelog_top_header "$target_file") || {
        rm -f "$target_file"
        die "No release header found in $TARGET_BRANCH:$CHANGELOG."
    }
    [[ "$target_header" =~ ^[0-9][^[:space:]]*-ion\ \(unreleased\)$ ]] || {
        rm -f "$target_file"
        die "Expected a curated unreleased section on $TARGET_BRANCH, found '$target_header'."
    }

    cp "$target_file" "$CHANGELOG"
    rm -f "$target_file"
    if git diff --quiet -- "$CHANGELOG"; then
        echo "$CHANGELOG already matches $TARGET_BRANCH."
        return 0
    fi

    git add -- "$CHANGELOG"
    git commit -q -m "changelog: mirror curated release notes" -- "$CHANGELOG"
    echo "Mirrored $CHANGELOG from $TARGET_BRANCH to $SOURCE_BRANCH as $(git rev-parse --short=10 HEAD)."
}

# Maps a target checkpoint to its source-side cherry-pick by preserved author,
# author timestamp, and subject. If the commit is shared by ancestry, its SHA
# already identifies the source checkpoint.
find_source_checkpoint() {
    local target_sha=$1 source_sha target_signature source_signature subject
    if git merge-base --is-ancestor "$target_sha" "$SOURCE_BRANCH"; then
        printf '%s\n' "$target_sha"
        return 0
    fi

    target_signature=$(git show -s --format='%ae%x09%at%x09%s' "$target_sha")
    subject=$(git show -s --format=%s "$target_sha")
    while IFS= read -r source_sha; do
        source_signature=$(git show -s --format='%ae%x09%at%x09%s' "$source_sha")
        if [[ "$source_signature" == "$target_signature" ]]; then
            printf '%s\n' "$source_sha"
            return 0
        fi
    done < <(git log --format='%H' --fixed-strings --grep="$subject" "$SOURCE_BRANCH")

    return 1
}

# Prefer the latest release tag on the target and map it to its source-side
# cherry-pick. Repositories without a usable tag fall back to their last shared
# ancestor, which is an exact checkpoint on both histories.
find_promotion_anchors() {
    local target_tag target_sha source_sha common_sha
    target_tag=$(git describe --tags --abbrev=0 "$TARGET_BRANCH" 2>/dev/null || true)
    if [[ -n "$target_tag" ]]; then
        target_sha=$(git rev-parse "$target_tag^{commit}")
        if source_sha=$(find_source_checkpoint "$target_sha"); then
            printf '%s %s tag:%s\n' "$target_sha" "$source_sha" "$target_tag"
            return 0
        fi
        echo "ERROR: no matching source checkpoint for tagged release '$target_tag'." >&2
        return 1
    fi

    common_sha=$(git merge-base "$SOURCE_BRANCH" "$TARGET_BRANCH") || return 1
    printf '%s %s merge-base\n' "$common_sha" "$common_sha"
}

git show-ref --verify --quiet "refs/heads/$SOURCE_BRANCH" || \
    die "Source branch '$SOURCE_BRANCH' does not exist."
git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH" || \
    die "Target branch '$TARGET_BRANCH' does not exist."

# ── Gate: must be on SOURCE_BRANCH ───────────────────────────────────────────
current=$(git symbolic-ref --short HEAD 2>/dev/null || echo "(detached)")
[[ "$current" == "$SOURCE_BRANCH" ]] || \
    die "Must be on $SOURCE_BRANCH (currently on $current). Run: git checkout $SOURCE_BRANCH"

if $SYNC_CHANGELOG; then
    sync_changelog_from_target
    exit 0
fi

CURATED_CHANGELOG=false
CURATED_VERSION=""
CURATED_SOURCE_FILE=""
CURATED_SECTION_FILE=""
RESTORE_DRAFT_ON_EXIT=false
DRAFT_MIRRORED=false
RUN_LOG=""
CL_ENTRIES=""

source_header=$(changelog_top_header "$CHANGELOG" || true)
if [[ "$source_header" =~ ^([0-9][^[:space:]]*-ion)\ \(unreleased\)$ ]]; then
    CURATED_CHANGELOG=true
    CURATED_VERSION=${BASH_REMATCH[1]}
fi

if ! $DRY_RUN; then
    dirty_paths=$({ git diff --name-only; git diff --cached --name-only; } | sort -u)
    unexpected_paths=$(printf '%s\n' "$dirty_paths" | grep -vxF "$CHANGELOG" || true)
    [[ -z "$unexpected_paths" ]] || \
        die "Tracked files other than $CHANGELOG must be clean before promotion: ${unexpected_paths//$'\n'/, }."
    git diff --cached --quiet -- "$CHANGELOG" || \
        die "Unstage changes to $CHANGELOG before promotion."

    if ! git diff --quiet -- "$CHANGELOG"; then
        $CURATED_CHANGELOG || \
            die "$CHANGELOG has local edits but no top '(unreleased)' section to promote."
        CURATED_SOURCE_FILE=$(mktemp)
        cp "$CHANGELOG" "$CURATED_SOURCE_FILE"
        RESTORE_DRAFT_ON_EXIT=true
    fi
fi

if $CURATED_CHANGELOG; then
    [[ -n "$CURATED_SOURCE_FILE" ]] || {
        CURATED_SOURCE_FILE=$(mktemp)
        cp "$CHANGELOG" "$CURATED_SOURCE_FILE"
    }
    CURATED_SECTION_FILE=$(mktemp)
    extract_top_changelog_section "$CURATED_SOURCE_FILE" "$CURATED_SECTION_FILE"
fi

RUN_LOG=$(mktemp)
CL_ENTRIES=$(mktemp)

cleanup() {
    if [[ "$(git symbolic-ref --short HEAD 2>/dev/null || true)" != "$SOURCE_BRANCH" ]]; then
        git checkout -q "$SOURCE_BRANCH" 2>/dev/null || true
    fi
    if $RESTORE_DRAFT_ON_EXIT && ! $DRAFT_MIRRORED; then
        cp "$CURATED_SOURCE_FILE" "$CHANGELOG"
    fi
    rm -f "$RUN_LOG" "$CL_ENTRIES" "$CURATED_SECTION_FILE" "$CURATED_SOURCE_FILE"
}
trap cleanup EXIT INT TERM

if $RESTORE_DRAFT_ON_EXIT; then
    git restore --source="$SOURCE_BRANCH" --worktree -- "$CHANGELOG"
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

# ── Find the latest mirrored promotion marker and source-side gap ────────────
echo "=== promote-validated.sh ==="
echo ""
$DRY_RUN && echo "(dry-run — no changes will be made)" && echo ""

ANCHOR_PAIR=$(find_promotion_anchors) || \
    die "Unable to determine a shared or tagged promotion checkpoint."
read -r TARGET_ANCHOR SOURCE_ANCHOR ANCHOR_KIND <<< "$ANCHOR_PAIR"

mapfile -t RANGE_SHAS < <(
    git log --format="%H" --reverse --no-merges "$SOURCE_ANCHOR..$SOURCE_BRANCH"
)
mapfile -t PATCH_UNIQUE_SHAS < <(
    git cherry "$TARGET_BRANCH" "$SOURCE_BRANCH" "$SOURCE_ANCHOR" |
        awk '$1 == "+" { print $2 }'
)
declare -A PATCH_UNIQUE_MAP
for sha in "${PATCH_UNIQUE_SHAS[@]}"; do
    PATCH_UNIQUE_MAP["$sha"]="1"
done

declare -a GAP_SHAS
N_ALREADY_PRESENT=0
N_CHANGELOG_ONLY=0
for sha in "${RANGE_SHAS[@]}"; do
    if [[ -z "${PATCH_UNIQUE_MAP[$sha]:-}" ]]; then
        (( N_ALREADY_PRESENT++ )) || true
        continue
    fi

    files=$(git diff-tree --no-commit-id --name-only -r "$sha")
    if [[ "$files" == "$CHANGELOG" ]]; then
        (( N_CHANGELOG_ONLY++ )) || true
        continue
    fi
    GAP_SHAS+=("$sha")
done
TOTAL=${#GAP_SHAS[@]}

if [[ $TOTAL -eq 0 ]]; then
    echo "$TARGET_BRANCH is up to date with $SOURCE_BRANCH after checkpoint ${TARGET_ANCHOR:0:10}."
    exit 0
fi

echo "Checkpoint ($ANCHOR_KIND): $TARGET_BRANCH ${TARGET_ANCHOR:0:10} ↔ $SOURCE_BRANCH ${SOURCE_ANCHOR:0:10}"
echo "Gap: commits after ${SOURCE_ANCHOR:0:10} on $SOURCE_BRANCH → $TARGET_BRANCH  ($TOTAL commit(s))"
echo "  Already patch-equivalent: $N_ALREADY_PRESENT   Changelog-only: $N_CHANGELOG_ONLY"
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
    if $CURATED_CHANGELOG; then
        echo "Changelog additions (curated section $CURATED_VERSION):"
        cat "$CURATED_SECTION_FILE"
    else
        preview=$(mktemp)
        build_changelog_entries "$preview"
        echo "Changelog additions ($(pending_section_label)):"
        if [[ -s $preview ]]; then cat "$preview"; else echo "  (none)"; fi
        rm -f "$preview"
    fi
    exit 0
fi

# ── Cherry-pick onto TARGET_BRANCH ───────────────────────────────────────────
echo "Promoting $N_PROMOTE commit(s) from $SOURCE_BRANCH to $TARGET_BRANCH..."
SOURCE_START=$(git rev-parse "$SOURCE_BRANCH")
TARGET_START=$(git rev-parse "$TARGET_BRANCH")
git checkout "$TARGET_BRANCH"

PROMOTED=0
RUN_HEADER="$(date -u '+%Y-%m-%dT%H:%M:%SZ')  $SOURCE_BRANCH → $TARGET_BRANCH"

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

# ── Changelog: prefer curated source section; otherwise generate promoted entries
if $CURATED_CHANGELOG; then
    install_curated_changelog_section "$CURATED_SECTION_FILE" "$CURATED_VERSION"
    if ! git diff --quiet -- "$CHANGELOG"; then
        git add -- "$CHANGELOG"
        git commit -q -m "changelog: record curated release notes"
        cl_sha=$(git rev-parse HEAD)
        echo ""
        echo "Curated changelog section $CURATED_VERSION committed as ${cl_sha:0:10}."

        git checkout -q "$SOURCE_BRANCH"
        if git cherry-pick "$cl_sha" > /dev/null 2>&1; then
            DRAFT_MIRRORED=true
            echo "  Mirrored to $SOURCE_BRANCH as $(git rev-parse --short=10 HEAD)"
        else
            git cherry-pick --abort 2>/dev/null || true
            sync_changelog_from_target
            DRAFT_MIRRORED=true
        fi
    else
        echo "Curated changelog section $CURATED_VERSION is already present on $TARGET_BRANCH."
    fi
else
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
            sync_changelog_from_target
        fi
    else
        echo "No user-facing changes to add to $CHANGELOG."
    fi
fi

# Return to source branch
git checkout -q "$SOURCE_BRANCH"

exit 0
