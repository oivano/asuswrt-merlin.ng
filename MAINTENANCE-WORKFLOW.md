# Maintenance Workflow

This document defines the maintenance flow for this repository's target-specific legacy firmware work.

## Scope

This workflow is for maintaining the target firmware that remains on the legacy kernel and current hardware support model.

The goal is to:

- keep upstream integration separate from release promotion;
- preserve a stable release branch for target hardware;
- intake only changes that make sense for the legacy platform;
- keep traceability from upstream source commit to released firmware.

## Remotes

- merlin: https://github.com/RMerl/asuswrt-merlin.ng
- upstream: git@github.com:gnuton/asuswrt-merlin.ng.git
- origin: git@github.com:oivano/asuswrt-merlin.ng.git

## Branch Roles

- DEV: upstream-sync and integration branch.
- DEV-nextrelease: target-main and release-candidate branch.
- feature/*: short-lived development branches.
- hotfix/*: short-lived release repair branches.

## Structural Model

DEV is allowed to absorb upstream churn, conflict resolution, and partial integration work.

DEV-nextrelease must stay close to releasable at all times. Changes enter DEV-nextrelease only by explicit cherry-pick after validation.

This separation is intentional:

- upstream branches increasingly target newer-kernel assumptions;
- this target stays on the legacy platform;
- whole-branch merges into the release lane create avoidable regression risk.

## Release Flow

### 1. Intake

Fetch and inspect both upstream sources.

    git checkout DEV
    git fetch merlin
    git fetch upstream

Run the intake helper in report-only mode to review candidates before touching any branch.

    tools/release/intake-filter.sh

The helper produces:

- an eligibility report (`intake-candidates.txt`);
- a triage report with ACCEPT / REVIEW / REJECT classification (`intake-triage.txt`);
- an apply-feasibility report showing CLEAN / CONFLICT status (`intake-apply-check.txt`);
- a promotion-ready list of ACCEPT+CLEAN candidates (`intake-promote-ready.txt`);
- an auto-rejected prebuilt list (`intake-rejected-prebuilt.txt`).

When the report looks acceptable, rerun with `--apply` to automatically cherry-pick
ACCEPT+CLEAN candidates onto DEV in chronological order.

    tools/release/intake-filter.sh --apply

Successfully applied local SHAs are appended to `tools/release/validated-commits.txt`
for use as an audit trail during promotion.

### 2. Integrate On DEV

`--apply` mode handles ACCEPT+CLEAN candidates automatically.  For REVIEW candidates
or commits that conflicted during the apply check, cherry-pick manually.

    git cherry-pick -x <sha>

Rules:

- prefer cherry-picking over broad merges when the change is narrow;
- keep conflict resolution local and documented;
- avoid importing newer-kernel assumptions into the legacy target branch;
- reject driver, kernel, and build-system churn unless there is a target-specific reason;
- local commits authored directly on DEV (not sourced from upstream) are also
  eligible for promotion and will be classified as `[local]` by the promotion helper.

### 3. Validate On Hardware

Minimum validation gate on the actual target device:

- successful build;
- clean flash or upgrade path;
- boot and reboot stability;
- WAN and LAN basic connectivity;
- wireless association and basic stability;
- settings persistence;
- target-specific core features.

DEV may contain work in progress, but any commit promoted beyond this point must pass the target gate.

### 4. Promote To DEV-nextrelease

First do a dry run to review exactly what will be promoted.

    tools/release/promote-validated.sh --dry-run

The helper computes the full gap between DEV and DEV-nextrelease and
classifies every commit:

- `[validated]` — present in `tools/release/validated-commits.txt` (applied via `--apply`);
- `[local]` — authored directly on DEV, not sourced from upstream intake.

Both classes are promoted.  `validated-commits.txt` serves as an audit cross-reference,
not as a gate.

To skip specific commits (for example a local experiment not ready for release):

    tools/release/promote-validated.sh --dry-run --exclude <sha> [--exclude <sha> ...]

Short SHAs are accepted.  Excluded commits appear as `[excluded]` in the listing and
are logged as skipped.

When the dry run output is satisfactory, run without `--dry-run`.

    tools/release/promote-validated.sh [--exclude <sha> ...]

The helper:

- enforces that source is DEV (two-stage gate — commits must land and be
  validated on DEV before DEV-nextrelease accepts them);
- checks out DEV-nextrelease;
- cherry-picks all commits from the gap in chronological order;
- writes a promotion log to `tools/release/promotion-log.txt`.

Rules:

- no wholesale merge from DEV to DEV-nextrelease;
- no unrelated refactors during release stabilization;
- if a change is risky but necessary, isolate it with `--exclude` and promote it
  in a separate batch after additional validation.

### 5. Stabilize And Release

After promotion:

- rebuild from DEV-nextrelease;
- rerun a shorter regression pass;
- tag the release;
- push branch and tag to origin.

Example:

    git checkout DEV-nextrelease
    git tag -a <release-tag> -m "<release-summary>"
    git push origin DEV-nextrelease --tags

## Intake Policy

### Usually Eligible

- documentation changes relevant to this tree;
- userland fixes outside kernel-coupled paths;
- tooling and helper scripts;
- low-risk service fixes that do not alter core platform assumptions.

### Manual Review Required

- build-system changes;
- config generation changes;
- packaging changes;
- nvram-related logic;
- firewall, network stack, or init-path changes.

### Usually Rejected

- newer-kernel branch changes;
- wireless driver stack changes;
- proprietary/prebuilt component changes;
- toolchain changes;
- kernel and low-level board integration changes unless strictly required for this target.

## Guardrails

- DEV should stay buildable.
- DEV-nextrelease should stay releasable.
- Prefer revert over risky fix-forward during release freeze.
- Keep a release ledger for each promoted commit.
- Do not mix feature work with intake evaluation.

## Traceability

For every promoted commit, record:

- source remote;
- original upstream SHA;
- cherry-pick SHA on DEV-nextrelease;
- validation status;
- release tag.

The promotion helper writes a log file for this purpose, but release notes should still summarize the final promoted set.

## Suggested Cadence

1. Intake window: fetch and evaluate upstream changes.
2. Integration window: land target-suitable changes in DEV.
3. Validation window: test on hardware.
4. Promotion window: cherry-pick to DEV-nextrelease.
5. Release window: tag and publish.

## Helper Scripts

- tools/release/intake-filter.sh
- tools/release/promote-validated.sh

These helpers are intentionally conservative. They are meant to reduce mistakes, not replace engineering review.
