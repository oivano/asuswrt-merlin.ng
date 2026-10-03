# Skynet Native (Experimental)

This is a C-native IPv4 policy core informed by IPSet_ASUS v9.0.5, not a
feature-complete replacement for the upstream addon. Its executable has no
shell or Python runtime dependency. It calls libipset, libcurl and SQLite
directly; only fixed-argument netfilter/module utilities are spawned.

## Current Scope

- Permanent IP/CIDR bans and global whitelists; private networks are excluded.
- Temporary bans (up to one week) with persisted expiry and kernel timeouts.
- Explicit HTTPS feeds containing one IPv4 address or CIDR per line, with
  optional `#` comments. HTML, IPv6, empty and malformed feeds are rejected.
- Atomic feed/database transactions and staged kernel policy publication.
- Cached startup, lightweight firewall reconciliation, native USB lifecycle,
  bounded workers, native settings and a compact WebUI.
- Disabled by default; executable changes arrive through firmware updates.
- Opt-in native feed scheduling with a 15-minute retry floor; no shell cron jobs.

Domain/DNS rules, countries/ASNs, IoT controls, VPN-server
interfaces, packet history, backups and addon-data
migration are **not ported**. Unsupported CLI operations fail rather than
executing an upstream script. The full behavior map is in [UPSTREAM.json](UPSTREAM.json).

## Router Setup

Use an explicitly configured writable ext2/3/4 USB mount. Native data lives in
`<mount>/skynet-native/policy.db`, separate from an existing addon installation.
Disable old Skynet hooks before enabling the native package; it detects common
active addon hooks and refuses to run alongside them. Existing addon data is
never sourced or automatically migrated.

Enable the router firewall and **explicitly disable CTF/NAT acceleration** before
activation. This is a conservative gate until hardware enforcement is verified.
At least 1 GiB of active file swap is currently required for enabled policy
operations. Use the existing native USB-swap controls; swap cannot increase
available kernel ipset memory. The native default ceiling is 65,536 entries,
with a configurable maximum of 131,072. Start with modest lists.

The native [Firewall / Skynet page](../www/Advanced_Skynet_Content.asp) provides
Overview, Rules, Feeds and Settings views with enable, mount, traffic direction,
entry limit, ban duration and feed refresh interval controls. A refresh failure
retains the last committed policy. Stop/restart the service when changing mounts.

```text
skynet status
skynet install
skynet ban 203.0.113.5
skynet ban 203.0.113.6 3600
skynet whitelist 198.51.100.0/24
skynet unban 203.0.113.5
skynet feed add https://example.org/ipv4.txt
skynet refresh
skynet feed remove https://example.org/ipv4.txt
service restart_skynet
```

Status error codes: 1 operation failure; 2 invalid limit; 3 busy; 4 active
addon hooks; 5 mount changed without teardown; 6 storage/database unavailable;
7 swap/firewall/CTF prerequisite; 8 time not synchronized; 9 unsupported command.

## Validation

From the repository root:

```text
./tools/build.sh --make skynet-check
./tools/build.sh --make skynet
./tools/build.sh --make skynet-install
```

`skynet-check` runs C parser, policy-rendering, SQLite persistence/rollback and feed
contracts with address/undefined-behavior sanitizers inside Docker, then
ARM-compiles every production module with strict warnings and checks native
page inclusion/exclusion for `RTCONFIG_SKYNET=y/n`. It does not clean the tree,
link firmware or exercise real netfilter. `skynet` builds declared dependencies
and links the ARM package; it requires the generated DSL-AC68U platform profile,
as do its firmware dependencies. `skynet-install` stages only the executable;
the WWW package owns page installation. A normal full build
still uses `tools/build.sh`; stage new source files first because that script
cleans untracked files beneath `release/`.

Hardware validation remains mandatory: boot/cached restore without WAN/NTP,
DSL/dual-WAN interface selection, whitelist precedence, real traffic drops,
firewall reloads, failed refreshes, memory peaks, storage persistence and USB
unmount during a running update. Do not promote this experimental core before
those gates pass.

## Build Ownership

Only DSL-AC68U is supported. The router Makefile owns dependency ordering
(curl, SQLite, ipset and NVRAM) and build/check/install/clean targets. The package
Makefile tracks generated header dependencies and linked libraries. Autoconf
is unnecessary for this small, in-tree, fixed-platform package: `common.mak`
already supplies toolchain and platform configuration. Adding `configure.ac`
would duplicate those responsibilities without required portability benefits.

`tools/build.sh --make` is only a generic container/make launcher, with no
Skynet-specific compiler logic. `SKYNET=y` produces `RTCONFIG_SKYNET=y`; the
page lives in `router/www` and its installer excludes it unless both the feature
and DSL-AC68U model match.

Schema v1 migrates transactionally to v2, preserving permanent rules. Temporary
policy is deferred before NTP synchronization and restored with its remaining
lifetime afterwards. A temporary ban never shortens an existing permanent ban.
Maintenance removes expired stored rules and refreshes feeds without discarding
last-good data on download failures.

## Maintaining Upstream Parity

Upstream shell patches cannot be applied mechanically to C. Maintain the
upstream version as a **behavioral reference**, not a build-time dependency.
The pin, function-to-module mapping, differences and unported features are
recorded in [UPSTREAM.json](UPSTREAM.json).

1. Keep a separate checkout of IPSet_ASUS with the pinned and proposed commits.
2. Run `python3 tools/skynet-upstream.py <checkout> --candidate <commit-or-tag>`
   from the firmware repository. This developer-only tool reports changed
   functions, native owners, existing contracts and unmapped changes. It never
   applies patches or advances the pin.
3. Review code, documentation, WebUI and feed-template changes. Security fixes
   in unported functions may still apply to native equivalents or dependencies.
4. Add a reproducing C contract before translating a relevant fix. Implement
   it in the mapped module and rerun the scoped check and applicable hardware
   tests. Only then update the manifest pin and differences in the same change.

Keep policy decisions in `core.c`, persistence in `store.c`, HTTP ingestion in
`feeds.c`, kernel publication in `backend.c`, scheduling in `schedule.c`, and router integration in `main.c`
and `rc/skynet.c`. Do not reintroduce script fallback for missing features.

No upstream executable or UI code is distributed by this package. The upstream
repository currently declares no explicit license; clarify redistribution
terms before copying upstream code or assets into future shipped artifacts.
