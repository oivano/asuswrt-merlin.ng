#!/usr/bin/env bash
# Evaluates upstream commits for integration onto DEV.
# Report mode (default): writes eligibility, triage, and apply-feasibility reports.
# Apply mode (--apply):   cherry-picks ACCEPT+CLEAN candidates and prompts for
#                         each REVIEW+CLEAN candidate before including it.
#
# Usage: tools/release/intake-filter.sh [--apply]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ── Remotes ───────────────────────────────────────────────────────────────────
MERLIN_REMOTE="merlin"
MERLIN_REF="merlin/main"
UPSTREAM_REMOTE="upstream"
UPSTREAM_REF="upstream/master"
TARGET_BRANCH="DEV"

MERLIN_REMOTE_URL="https://github.com/RMerl/asuswrt-merlin.ng"
UPSTREAM_REMOTE_URL="git@github.com:gnuton/asuswrt-merlin.ng.git"

# ── Output files (all in tools/release/) ─────────────────────────────────────
OUTDIR="$SCRIPT_DIR"
CANDIDATES_FILE="$OUTDIR/intake-candidates.txt"
TRIAGE_FILE="$OUTDIR/intake-triage.txt"
APPLY_CHECK_FILE="$OUTDIR/intake-apply-check.txt"
PROMOTE_READY_FILE="$OUTDIR/intake-promote-ready.txt"
REJECTED_PREBUILT_FILE="$OUTDIR/intake-rejected-prebuilt.txt"
VALIDATED_FILE="$OUTDIR/validated-commits.txt"

# ── CLI ───────────────────────────────────────────────────────────────────────
APPLY_MODE=false
for arg in "$@"; do
    case "$arg" in
        --apply) APPLY_MODE=true ;;
        *) echo "ERROR: Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "  $*"; }

# Subjects that are too generic to use for dedup matching, or irrelevant to our fork
GENERIC_SUBJECT_RE='^(Merge |merge |Revert |revert |fixup! |squash! |WIP:|wip:|Bump |Bumped |bump version|Update submodule|Auto-generated|Initial commit|docs:|ci:|chore:|Updating Notes|Updating.*manifest|Updated changelog|\[SKIP_CI\]|\[skip ci\])'

is_generic_subject() { echo "$1" | grep -qE "$GENERIC_SUBJECT_RE"; }

# Patterns used by classify_commit (defined outside the function to avoid recompilation)
# Docs/CI paths that are upstream-repo-specific and irrelevant to our fork
_RE_DOCONLY='^\.github/|^\.gitignore$|^_config\.yml$|^AGENTS\.md$|^README|^Changelog|^CHANGELOG'
_RE_REJECT='release/src-rt-[45789]|/prebuilt/|\.ko$|\.a$|\.so\b|\.so\.|wl/src/|tools/toolchains/|/build-all|CLM[_.]|/dhd/|/wl\.mk|/wlc_|\.github/|/(test|tests)/requirements[^/]*$'
_RE_REVIEW='router/Makefile|/target\.mak|/dsl\.mak|/platform\.mak|/profile\.mak|/nvram[^/]*[./]|/shared/defaults\.c$|/rc/|/firewall|/iptables|/others/amtm$|version\.conf|config_base|\.mak$|/Makefile\.fw|/Makefile\.plugfest'

# Classify a commit by the paths it touches → ACCEPT / REVIEW / REJECT
classify_commit() {
    local sha="$1"
    local files
    local file_count
    files=$(git diff-tree --no-commit-id -r --name-only "$sha" 2>/dev/null || true)
    [[ -z "$files" ]] && echo "REVIEW" && return
    file_count=$(printf "%s\n" "$files" | wc -l)

    # Reject: docs/CI-only commits (every file matches the doc-only pattern)
    if ! echo "$files" | grep -qvE "$_RE_DOCONLY"; then
        echo "REJECT"; return
    fi

    # Reject: other kernel branches, binary blobs, wireless driver stack, toolchain
    if echo "$files" | grep -qE "$_RE_REJECT"; then
        echo "REJECT"; return
    fi

    # Review: build system, init paths, nvram, firewall, network stack, packaging
    if echo "$files" | grep -qE "$_RE_REVIEW"; then
        echo "REVIEW"; return
    fi

    # Broad package/data refreshes need manual target review even when they apply cleanly.
    if (( file_count > 20 )); then
        echo "REVIEW"; return
    fi

    echo "ACCEPT"
}

# True if commit touches only prebuilt/binary paths
_RE_PREBUILT='/prebuilt/|\.ko$|\.a$|\.so\b|\.so\.'
is_prebuilt_only() {
    local sha="$1"
    local files
    files=$(git diff-tree --no-commit-id -r --name-only "$sha" 2>/dev/null || true)
    [[ -z "$files" ]] && return 1
    ! echo "$files" | grep -qvE "$_RE_PREBUILT"
}

# ── Verify remotes ────────────────────────────────────────────────────────────
echo "=== intake-filter.sh ==="
echo ""

git remote get-url "$MERLIN_REMOTE" > /dev/null 2>&1 || \
    die "Remote '$MERLIN_REMOTE' missing. Run: git remote add $MERLIN_REMOTE $MERLIN_REMOTE_URL"
git remote get-url "$UPSTREAM_REMOTE" > /dev/null 2>&1 || \
    die "Remote '$UPSTREAM_REMOTE' missing. Run: git remote add $UPSTREAM_REMOTE $UPSTREAM_REMOTE_URL"

# ── Fetch (hard-fail if refs can't be refreshed) ──────────────────────────────
echo "Fetching remotes..."
git fetch "$MERLIN_REMOTE" main  2>&1 | sed 's/^/  [merlin]   /' || \
    die "Failed to fetch $MERLIN_REF — check network/remote URL."
git fetch "$UPSTREAM_REMOTE" master 2>&1 | sed 's/^/  [upstream] /' || \
    die "Failed to fetch $UPSTREAM_REF — check network/remote URL."
echo ""

# ── Build author+subject dedup set from DEV ───────────────────────────────────
echo "Building signature set from $TARGET_BRANCH..."
declare -A DEV_SIGS
while IFS=$'\t' read -r author subject; do
    is_generic_subject "$subject" && continue
    DEV_SIGS["${author}|${subject}"]="1"
done < <(git log --format="%ae%x09%s" "$TARGET_BRANCH" 2>/dev/null)
info "${#DEV_SIGS[@]} meaningful signatures on $TARGET_BRANCH."
echo ""

# ── Collect candidates from both upstream refs ────────────────────────────────
echo "Collecting candidates not present on $TARGET_BRANCH..."
declare -a CANDIDATE_SHAS  # ordered list (merlin first, then upstream, deduped)
declare -A SHA_SOURCE       # sha → source name
declare -A SHA_DATE         # sha → author date
declare -A CANDIDATE_SIGS   # author+subject → first candidate SHA

for ref in "$MERLIN_REF" "$UPSTREAM_REF"; do
    src="${ref%%/*}"
    # Walk ref newest→oldest; first author+subject hit on DEV is our sync cutoff
    cutoff=""
    while IFS=$'\t' read -r sha author subject; do
        is_generic_subject "$subject" && continue
        if [[ -n "${DEV_SIGS["${author}|${subject}"]:-}" ]]; then
            cutoff="$sha"
            break
        fi
    done < <(git log --format="%H%x09%ae%x09%s" "$ref" 2>/dev/null)

    if [[ -z "$cutoff" ]]; then
        info "WARNING: no matching commit found on $ref — cannot determine cutoff, skipping"
        continue
    fi
    info "Cutoff for $src: $(git log -1 --format='%ai  %s' "$cutoff")"

    while IFS=$'\t' read -r sha author subject date; do
        is_generic_subject "$subject" && continue
        [[ -n "${DEV_SIGS["${author}|${subject}"]:-}" ]] && continue  # already on DEV
        [[ -n "${SHA_SOURCE[$sha]:-}" ]] && continue                    # dedup across refs
        [[ -n "${CANDIDATE_SIGS["${author}|${subject}"]:-}" ]] && continue
        CANDIDATE_SHAS+=("$sha")
        SHA_SOURCE["$sha"]="$src"
        SHA_DATE["$sha"]="$date"
        CANDIDATE_SIGS["${author}|${subject}"]="$sha"
    done < <(git log --format="%H%x09%ae%x09%s%x09%ai" "$cutoff..$ref" 2>/dev/null)
done

# Cherry-picks must run oldest-first across both remotes.
mapfile -t CANDIDATE_SHAS < <(
    for sha in "${CANDIDATE_SHAS[@]}"; do
        printf "%s\t%s\n" "$(git show -s --format='%at' "$sha")" "$sha"
    done | sort -n -k1,1 | cut -f2
)

TOTAL=${#CANDIDATE_SHAS[@]}
info "Found $TOTAL candidate(s)."
echo ""

# ── Triage ────────────────────────────────────────────────────────────────────
echo "Triaging..."
declare -A SHA_VERDICT   # sha → ACCEPT / REVIEW / REJECT

> "$CANDIDATES_FILE"
> "$TRIAGE_FILE"
> "$REJECTED_PREBUILT_FILE"

for sha in "${CANDIDATE_SHAS[@]}"; do
    src="${SHA_SOURCE[$sha]}"
    subject=$(git log -1 --format="%s" "$sha")
    date="${SHA_DATE[$sha]}"
    verdict=$(classify_commit "$sha")
    SHA_VERDICT["$sha"]="$verdict"

    is_prebuilt_only "$sha" && echo "$sha  [$src]  $subject" >> "$REJECTED_PREBUILT_FILE"

    printf "%s\t%s\t%s\t%s\n" "$sha" "$src" "$date" "$subject" >> "$CANDIDATES_FILE"
    printf "%-8s  %s  [%s]  %s\n" "$verdict" "$sha" "$src" "$subject" >> "$TRIAGE_FILE"
done

info "Written: $CANDIDATES_FILE"
info "Written: $TRIAGE_FILE"
echo ""

# ── Apply-feasibility check ───────────────────────────────────────────────────
echo "Checking apply feasibility (cherry-pick dry-run on temp branch)..."
declare -A SHA_APPLY   # sha → CLEAN / APPROVED / SKIPPED / CONFLICT / N/A

> "$APPLY_CHECK_FILE"
> "$PROMOTE_READY_FILE"

# Stash any dirty working tree
STASH_REF=""
if ! git diff --quiet HEAD 2>/dev/null; then
    STASH_REF=$(git stash create "intake-filter apply-check" 2>/dev/null || true)
    [[ -n "$STASH_REF" ]] && git stash store -m "intake-filter apply-check" "$STASH_REF"
fi

TEMP_BRANCH="intake-filter-tmp-$$"
git checkout -q -b "$TEMP_BRANCH" "$TARGET_BRANCH"
CLEANUP_DONE=false

cleanup() {
    $CLEANUP_DONE && return
    git cherry-pick --abort 2>/dev/null || true
    git reset --hard HEAD 2>/dev/null || true
    git checkout -q "$TARGET_BRANCH" 2>/dev/null || true
    git branch -D "$TEMP_BRANCH" 2>/dev/null || true
    [[ -n "$STASH_REF" ]] && git stash pop 2>/dev/null || true
    CLEANUP_DONE=true
}
trap cleanup EXIT INT TERM

for sha in "${CANDIDATE_SHAS[@]}"; do
    verdict="${SHA_VERDICT[$sha]}"
    subject=$(git log -1 --format="%s" "$sha")

    if [[ "$verdict" == "REJECT" ]]; then
        SHA_APPLY["$sha"]="N/A"
        printf "%-8s  %s  %s\n" "N/A" "$sha" "$subject" >> "$APPLY_CHECK_FILE"
        continue
    fi

    if git cherry-pick --no-commit "$sha" > /dev/null 2>&1; then
        selected=false
        apply_status="CLEAN"

        if [[ "$verdict" == "ACCEPT" ]]; then
            selected=true
        elif $APPLY_MODE && [[ -t 0 ]]; then
            echo ""
            echo "Review candidate: $sha"
            echo "  $subject"
            git diff --cached --stat | sed 's/^/  /'
            if read -r -p "Apply this reviewed commit? [y/N] " answer && \
                [[ "$answer" =~ ^([yY]|[yY][eE][sS])$ ]]; then
                selected=true
                apply_status="APPROVED"
            else
                apply_status="SKIPPED"
            fi
        elif $APPLY_MODE; then
            apply_status="SKIPPED"
            info "Skipping REVIEW commit ${sha:0:10}: --apply is not attached to a terminal."
        fi

        SHA_APPLY["$sha"]="$apply_status"
        printf "%-8s  %s  %s\n" "$apply_status" "$sha" "$subject" >> "$APPLY_CHECK_FILE"

        if $selected; then
            git commit -q --no-gpg-sign -m "intake feasibility: $sha"
            echo "$sha" >> "$PROMOTE_READY_FILE"
        else
            git reset --hard HEAD > /dev/null 2>&1 || true
        fi
    else
        SHA_APPLY["$sha"]="CONFLICT"
        git cherry-pick --abort > /dev/null 2>&1 || git reset --hard HEAD > /dev/null 2>&1 || true
        printf "%-8s  %s  %s\n" "CONFLICT" "$sha" "$subject" >> "$APPLY_CHECK_FILE"
    fi
done

cleanup

info "Written: $APPLY_CHECK_FILE"
info "Written: $PROMOTE_READY_FILE"
[[ -s "$REJECTED_PREBUILT_FILE" ]] && info "Written: $REJECTED_PREBUILT_FILE"
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
n_accept=$(grep -c '^ACCEPT' "$TRIAGE_FILE" 2>/dev/null || echo 0)
n_review=$(grep -c '^REVIEW' "$TRIAGE_FILE" 2>/dev/null || echo 0)
n_reject=$(grep -c '^REJECT' "$TRIAGE_FILE" 2>/dev/null || echo 0)
n_ready=$(wc -l < "$PROMOTE_READY_FILE" | tr -d ' ')

echo "Summary:"
info "ACCEPT: $n_accept   REVIEW: $n_review   REJECT: $n_reject"
info "Selected clean commits (ready to apply): $n_ready"
echo ""
if ! $APPLY_MODE; then
    echo "Review $TRIAGE_FILE and $APPLY_CHECK_FILE, then rerun with --apply."
    exit 0
fi

# ── Apply mode ────────────────────────────────────────────────────────────────
[[ "$n_ready" -eq 0 ]] && echo "Nothing to apply." && exit 0

current=$(git symbolic-ref --short HEAD 2>/dev/null || echo "(detached)")
[[ "$current" == "$TARGET_BRANCH" ]] || \
    die "Must be on $TARGET_BRANCH to apply (currently on $current). Run: git checkout $TARGET_BRANCH"
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || \
    die "Tracked working tree files must be clean before apply."

echo "Applying $n_ready selected clean commit(s) onto $TARGET_BRANCH..."
APPLIED=0
TARGET_START=$(git rev-parse "$TARGET_BRANCH")
RUN_LOG=$(mktemp)

cleanup_apply_log() { rm -f "$RUN_LOG"; }
trap cleanup_apply_log EXIT INT TERM

while read -r sha; do
    [[ -z "$sha" ]] && continue
    subject=$(git log -1 --format="%s" "$sha")
    if git cherry-pick -x "$sha"; then
        local_sha=$(git rev-parse HEAD)
        printf "%s\t(from %s)\t%s\n" "$local_sha" "$sha" "$subject" >> "$RUN_LOG"
        echo "  OK    $sha  $subject"
        (( APPLIED++ )) || true
    else
        echo "  FAIL  $sha  $subject" >&2
        git cherry-pick --abort 2>/dev/null || true
        git reset --hard "$TARGET_START" > /dev/null
        die "Apply failed; $TARGET_BRANCH was rolled back to ${TARGET_START:0:10}."
    fi
done < "$PROMOTE_READY_FILE"

cat "$RUN_LOG" >> "$VALIDATED_FILE"
echo ""
echo "Applied: $APPLIED   Failed: 0"
[[ $APPLIED -gt 0 ]] && info "Appended $APPLIED entries to $VALIDATED_FILE"
exit 0
