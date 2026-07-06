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

- DEV-refactor: upstream-sync and integration branch.
- DEV-nextrelease: target-main and release-candidate branch.
- feature/*: short-lived development branches.
- hotfix/*: short-lived release repair branches.

## Structural Model

DEV-refactor is allowed to absorb upstream churn, conflict resolution, and partial integration work.

DEV-nextrelease must stay close to releasable at all times. Changes enter DEV-nextrelease only by explicit cherry-pick after validation.

This separation is intentional:

- upstream branches increasingly target newer-kernel assumptions;
- this target stays on the legacy platform;
- whole-branch merges into the release lane create avoidable regression risk.

## Release Flow

### 1. Intake

Fetch and inspect both upstream sources.

    git checkout DEV-refactor
    git fetch merlin
    git fetch upstream

Run the intake helper to generate a candidate list.

    tools/release/intake-filter.sh --no-apply

The helper produces:

- an eligibility report;
- a list of commits that are likely safe to consider for intake;
- a list of commits that require manual review;
- a list of commits that should be rejected for this target.

### 2. Integrate On DEV-refactor

For accepted candidates, cherry-pick into DEV-refactor or merge selectively if the change set is intentionally grouped.

Rules:

- prefer cherry-picking over broad merges when the change is narrow;
- keep conflict resolution local and documented;
- avoid importing newer-kernel assumptions into the legacy target branch;
- reject driver, kernel, and build-system churn unless there is a target-specific reason.

### 3. Validate On Hardware

Minimum validation gate on the actual target device:

- successful build;
- clean flash or upgrade path;
- boot and reboot stability;
- WAN and LAN basic connectivity;
- wireless association and basic stability;
- settings persistence;
- target-specific core features.

DEV-refactor may contain work in progress, but any commit promoted beyond this point must pass the target gate.

### 4. Promote To DEV-nextrelease

Prepare a SHA list from the validated commits, then run the promotion helper.

    tools/release/promote-validated.sh --list tools/release/validated-commits.txt

The helper:

- checks out DEV-nextrelease;
- cherry-picks each listed commit;
- writes a promotion log;
- records the source SHA, destination branch, and result.

Rules:

- no wholesale merge from DEV-refactor to DEV-nextrelease;
- no unrelated refactors during release stabilization;
- if a change is risky but necessary, isolate it in its own promotion batch.

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

- DEV-refactor should stay buildable.
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
2. Integration window: land target-suitable changes in DEV-refactor.
3. Validation window: test on hardware.
4. Promotion window: cherry-pick to DEV-nextrelease.
5. Release window: tag and publish.

## Helper Scripts

- tools/release/intake-filter.sh
- tools/release/promote-validated.sh

These helpers are intentionally conservative. They are meant to reduce mistakes, not replace engineering review.
