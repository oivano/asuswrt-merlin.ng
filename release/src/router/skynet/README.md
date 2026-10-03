# Skynet (Experimental)

This is a C-native IPv4 policy core informed by IPSet_ASUS v9.0.5, not a
feature-complete replacement for the upstream addon. Its executable has no
shell or Python runtime dependency. It calls libipset, libcurl and SQLite
directly; only fixed-argument netfilter/module utilities are spawned.

## Current Scope

- Permanent IP/CIDR bans and global whitelists; private networks are excluded.
- Temporary bans (up to one week) with persisted expiry and kernel timeouts.
- Explicit HTTPS feeds containing one IPv4 address or CIDR per line, with
  optional `#` comments. Valid IPv6 entries are skipped in mixed-family feeds;
  HTML, malformed entries and feeds with no usable IPv4 entries are rejected.
- Eight built-in upstream feeds, persistent source selection and custom HTTPS URLs.
- Source counts, last success, excluded/current/cached/failed/pending health.
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
`<mount>/skynet/policy.db`, separate from an existing addon installation.
Disable old Skynet hooks before enabling the native package; it detects common
active addon hooks and refuses to run alongside them. Existing addon data is
never sourced or automatically migrated.

Enable the router firewall before activation. CTF/NAT acceleration may remain
enabled; enforcement with acceleration still requires hardware validation.
At least 1 GiB of active file swap is currently required for enabled policy
operations. Startup reuses sufficient active file swap; otherwise it creates
and activates a fully allocated 1 GiB `<mount>/skynet/swap` file directly in C.
Later starts validate and reactivate that file without rewriting it. Creation
requires 1 GiB plus 16 MiB free space. Existing invalid files are not overwritten;
failures leave policy activation blocked and are reported in the system log.
USB unmount deactivates the owned swap file before removing the mount; ordinary
service restarts retain active swap. The file is preserved for the next start.
Swap cannot increase available kernel ipset memory. The native default ceiling is 65,536 entries,
with a configurable maximum of 131,072. Start with modest lists.

The native [Firewall / Skynet page](../www/Advanced_Skynet_Content.asp) provides
Overview, Updates, Protection and IPv4 Rules views with enable, mount, traffic
direction, entry limit, ban duration and feed refresh interval controls.
Updates includes per-source counts/health, enable toggles, confirmed removal,
custom HTTPS source addition and default restoration. Apply Sources publishes
the complete selection atomically; normal status polling preserves unsaved
toggles. Native actions match numeric request IDs instead of assuming that
a five-second timer proves worker completion. Settings restart still uses the
firmware's ordinary apply acknowledgement, not verified worker completion.
Each enabled source is attempted even when another source fails. Failed sources
retain their cached entries; successful sources update together in one atomic
policy publication. A partial refresh reports error 1 despite publishing the
successful updates. Publication/database failures retain the last committed
policy. Stop/restart the service when changing mounts.

```text
skynet status
skynet install
skynet ban 203.0.113.5
skynet ban 203.0.113.6 3600
skynet whitelist 198.51.100.0/24
skynet unban 203.0.113.5
skynet feed add https://example.org/ipv4.txt
skynet feed add firehol_level2.netset
skynet feed select '[1,2,3]'
skynet feed defaults ''
skynet refresh
skynet feed remove https://example.org/ipv4.txt
service restart_skynet
```

Built-in sources match the pinned upstream filter list: `bds_atif.ipset`,
`cybercrime.ipset`, `et_compromised.ipset`, `firehol_level2.netset`,
`firehol_level3.netset`, `ipsum_3.ipset`, `spamhaus_drop.netset` (FireHOL), and
`IP-High-Confidence-Feed.txt` (ThreatView). These filenames identify IPv4 lists,
not domains. Add/remove accepts either the filename or its canonical HTTPS URL;
custom sources require a full HTTPS URL. Fresh policy stores contain all eight
enabled sources, initially pending download. Existing schema-v1/v2 stores migrate
to v3 without replacing their configured feeds. Restore Default Sources replaces
custom sources and re-enables the eight defaults while retaining their existing
caches. Source selection uses the stable numeric IDs in status JSON; unknown,
duplicate, non-integer and empty selections are rejected. Excluded caches remain
on storage but do not enter kernel policy or enabled entry counts. Existing
entry/download limits still apply when combining multiple lists.

Status error codes: 1 operation failure; 2 invalid limit; 3 busy; 4 active
addon hooks; 5 mount changed without teardown; 6 storage/database unavailable;
7 swap/firewall prerequisite; 8 time not synchronized; 9 unsupported command.

Error 1 is a generic operation failure, not a libcurl error code. Feed failures
log a preceding `feed <id> refresh failed` diagnostic with the parser/limit or
transfer reason, curl code, HTTP status, byte/entry counts and SQLite error.
Feed URLs and contents are not logged. Check these details before changing a
feed or raising limits. Individual download failures preserve that source's
cached entries; failure of the combined publication preserves the whole policy.

## Upstream WebUI Parity

The supplied upstream ASP is the functionality reference, not a drop-in native
frontend: its `start_Skynet*` workers and `settings.js`/`stats.js` payloads are not
implemented by this executable. Full applicable parity remains unfinished.

| Reference Area | Native Status / Remaining Work                                                                                                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Overview       | Policy/storage/time counts only; enforcement verification, block counters, charts and IP/device/port details remain.                                                                                          |
| Updates        | Built-ins, custom feeds, selection, counts/health, cache-preserving per-source refresh and default restore exist; local-hour daily/Monday schedules, template import and content change/hash tracking remain. |
| Protection     | Enable/disable, direction, limits, swap and mount exist; configurable private handling, CDN/shared/VPN whitelists, secure WAN management and verified restart remain.                                         |
| Rules          | Permanent/temporary IPv4/CIDR and whitelists exist; comments, batch actions, stable owner IDs, full pagination/search, domains/DNS caches, ASN groups and imports remain.                                     |
| IoT            | Persisted device selection, client detection, WAN isolation, protocol/port exceptions, VPN exceptions, logging and targeted connection eviction remain.                                                       |
| Countries      | Country selection, validated HTTPS sources/caches and atomic policy replacement remain.                                                                                                                       |
| Statistics     | Rate-limited native packet logging, log-source detection, budgets, retention, country lookups, associated domains and charts remain.                                                                          |
| History        | Rotation-safe incremental ingestion, bounded queries, stable pagination, CSV export, trends, selective cleanup and activity journal remain.                                                                   |
| Backup         | Dated snapshots, download, safe validated restore, rollback and three-point retention remain.                                                                                                                 |

Firmware updates intentionally replace addon executable auto-update. AiProtection
ingestion is not applicable while BWDPI is absent on DSL-AC68U; WireGuard is not
functional on this kernel. Do not add shell fallback or advertise unsupported
controls as working. Each remaining area needs native backend contracts,
authenticated httpd integration, failure/recovery tests and real hardware
validation before claiming complete parity.

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

Schema v1/v2 migrates to v3, preserving rules and configured feeds. Temporary
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
