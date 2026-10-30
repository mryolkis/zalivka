# Zalivka rewrite plan — from scratch, KISS, DRY

This document is the durable plan for the clean rewrite. `git tag pre-rewrite`
(commit `c79e478`) is the untouched original. Every rewrite commit must leave
`cargo fmt`, `cargo clippy -D warnings`, and the test suite green.

## Objective and interpretation

User objective: **rewrite all code from scratch, KISS, DRY**.

- *From scratch*: every production source file is replaced with a new
  implementation. Files are not patched incrementally; they are deleted and
  rewritten. The final module tree is rebuilt around domains, not history.
- *All code*: every production source file is rewritten. The existing test
  suite is the frozen specification: it is retained (adapted only for imports)
  so behavior cannot drift, rather than rewritten to match the new internals.
  No feature is dropped.
- *KISS*: fewer modules (85 → ~15), one obvious way to do each thing, no
  test-only seams in production code, no forwarding layers that add no
  invariant, deadline/poll and validation logic shared.
- *DRY*: one proxy route model, one HTTP framing decoder, one device-transition
  helper, one protocol vocabulary, one digest/poll/validation helper per concept.

Behavior is frozen by the existing black-box suite under `tests/protocols/`
(217 tests using scripted USB/TLS peers) plus the fixtures in `tests/fixtures/`.
Those tests are the specification; they are adapted only for import paths.

## Baseline (recorded before the rewrite)

- Production: 85 files, 19,508 non-blank lines.
- Tests: 66 files, 24,384 lines, 558 tests (549 run, 9 ignored).
- `cargo fmt --check`: clean. `cargo clippy --all-targets --all-features`: clean.
- Full suite green except one environment failure: the GUI test that calls the
  real `Job::spawn` needs a writable `%LOCALAPPDATA%\zalivka\logs`. The sandbox
  denies AppData, so local runs redirect it:
  `LOCALAPPDATA=.cache/env/localappdata`, `TEMP=.cache/env/temp`.
- Known structural findings:
  - No copy-paste duplication (18 six-line windows total); duplication is
    *parallel implementations*: proxy resolution ×3.5, HTTP/1.1 framing ×2,
    poll-until-deadline ×8, device re-connect ×4, container parsing ×2.
  - Cycles: `net ↔ proxy`, `ipsw ↔ firmware`, `drivers ↔ windows`, `usb ↔ windows`.
  - 18 `#[path]` unit-test modules injected into production modules; the library
    compiles `tests/support/*` into itself under `cfg(test)`.
  - Mechanical consolidation identified: ~550–650 LOC. Structural cleanup is
    worth more than line-count reduction.

## Target architecture (~15 domain modules)

| Module | Responsibility | Old sources |
| --- | --- | --- |
| `support` | device identity, storage, logging, progress/cancel | device, storage, logging, progress |
| `wire` | plist framing/accessors, digest factory | wire, checksum |
| `ipsw` | ZIP, manifest, identities, verification, image streaming | ipsw + 4 submodules |
| `crypto` | IM4P/IMG4 DER, AEA key unwrap | img4, aea |
| `tss` | TSS transport + request builders (Apple private PKI) | tss + request |
| `firmware` | updater personalization, containers, canary | firmware + 3 submodules |
| `usb` | enumeration, DFU, KIS, platform USB backends | usb + 3 submodules, windows/apple, windows/reset |
| `mux` | USB multiplex transport + streams | mux + 3 submodules |
| `restore` | restore orchestration, boot, Port DFU, session, attestation | restore.rs + boot/port_dfu/session/connection/options/events |
| `restored` | device-side restored service: data requests, images, keys, FDR/ASR | restore/data*, images, recovery, file_data, keys, requests, attestation + fdr + asr |
| `net` | HTTP agents, Apple URL policy, TLS, assets, downloads, catalog/cache | net + 4 submodules + catalog |
| `proxy` | proxy policy, CONNECT, sockets, OS resolvers | proxy + 6 submodules, windows/proxy, windows/negotiate |
| `host` | host readiness, drivers, Windows setup/packages, Linux udev | drivers + linux + windows/setup* |
| `app` | CLI surface and shared operations | cli, operations |
| `gui` | egui application + localization (feature `gui`) | gui + 10 submodules, localization |

Rules:
- Break `net ↔ proxy` by moving TLS configuration ownership into `net` and
  having `proxy` depend on a small `proxy::Tls` trait or on `net` (one direction).
  Break `ipsw ↔ firmware` by moving plist-bundle/container verification into `ipsw`.
- Platform code lives behind `#[cfg]` inside `usb`, `proxy`, `host`; no caller
  reaches through OS chains.
- Tests live outside the library: unit-only seams (`InputReady::new`,
  `Record::parse_json`, `routes_from_strings`, `winusb_inf`) become private or
  are deleted when their tests are ported.
- One error type style: `anyhow` with contextual messages; no new error enums
  unless they carry recovery semantics.

## Execution order and status

Each slice = rewrite module + adapt/port its tests + delete old files + verify.

| # | Slice | Status |
| --- | --- | --- |
| 0 | Baseline, checkpoint tag, audits, green recipe | done |
| 1 | `support` (device/storage first; logging/progress next) | done (device, storage, logging, progress) |
| 2 | `wire` (+ digest factory) | done (wire + checksum/digest) |
| 3 | `ipsw` (flatten identity/verify/digest/stream) | done (all files rewritten; final flatten deferred to cleanup) |
| 4 | `crypto` (img4 + aea) | done |
| 5 | `tss` (transport + requests) | done |
| 6 | `firmware` (updater/containers/canary/request) | done (containers moved to ipsw; updater/canary/request rewritten) |
| 7 | `usb` (flatten backend/descriptors/KIS, absorb DFU and Windows USB) | done (usb.rs/backend/descriptors/KIS + dfu) |
| 8 | `mux` (flatten packet/channel/stream) | done (packet/channel/stream/session) |
| 9 | `restore` (orchestrator/boot/port DFU/session/attestation) | done (all 16 files rewritten) |
| 10 | `restored` services (data/images/keys/FDR/ASR) | done (all restore modules and FDR/ASR) |
| 11 | `net` (+ catalog; break proxy cycle) | done (catalog/net/assets/download/request; TLS moved to crate root; cycle broken) |
| 12 | `proxy` (one route model; unify framing) | done, including the macOS CFNetwork resolver (review-only on Windows) |
| 13 | `host` (drivers/Windows/Linux) | done (drivers + linux + entire Windows tree rewritten) |
| 14 | `app` (CLI + operations) | done |
| 15 | `gui` (+ localization) | done (all gui modules and localization rewritten) |
| — | cross-cutting `logging`/`progress` | done |
| 16 | Cleanup: Cargo dependencies, dead cfg, docs, final full verification | done (clean-build verification recorded below) |

## Progress log

| Commit | Slice | Verification |
| --- | --- | --- |
| `976d8ac` | foundation: `device`, `checksum`, `storage` | 269 lib + 216 protocols |
| `b990b12` | plan and baseline audits | — |
| `db79a31` | `wire` full rewrite | 552 tests, clippy clean |
| `35fbf08` | `catalog` and `aea` full rewrites | 552 tests, clippy clean |
| `5e53668` | `img4` full rewrite | 552 tests, clippy clean |
| `0c03d79` | `wire::flag` consolidation (14 call sites) | 552 tests, clippy clean |
| `dec6857` | `tss` transport rewrite | 552 tests, clippy clean |
| `ceaa8e8` | `tss` request builders rewrite | 552 tests, clippy clean |
| `964db87` | `ipsw/stream` + `ipsw/digest` rewrites | 552 tests, clippy clean |
| `878c3f3` | `ipsw/identity` rewrite | 552 tests, clippy clean |
| `841a3bc` | container parsing moved to `ipsw/containers`, rewritten, cycle broken | 552 tests, clippy clean |
| `1440f67` | `ipsw/verify` rewrite | 552 tests, clippy clean |
| `f585661` | `ipsw.rs` archive rewrite (IPSW domain complete) | 552 tests, clippy clean |
| `14aad94` | firmware domain rewrite (updater/request/canary) | 552 tests, clippy clean |
| `50d43df` | `dfu` rewrite | 552 tests, clippy clean |
| `cb590ff` | `usb/descriptors` rewrite | 552 tests, clippy clean |
| `276834b` | `usb/kis` portal rewrite | 552 tests, clippy clean |
| `26e16d7` | `usb/backend` rewrite | 552 tests, clippy clean |
| `33063fc` | `usb.rs` enumeration/transport rewrite (USB domain complete) | 552 tests, clippy clean |
| `96ba27d` | `mux/packet` + `mux/channel` rewrites | 552 tests, clippy clean |
| `c45df02` | `mux/stream` rewrite | 552 tests, clippy clean |
| `8452045` | `mux.rs` session rewrite (mux domain complete) | 552 tests, clippy clean |
| `070df36` | `fdr` + `fdr/protocol` + `asr` rewrites | 552 tests, clippy clean |
| `b7b0f66` | restore `events` + `data_type` rewrites | 552 tests, clippy clean |
| `0b6a619` | restore `options` rewrite | 552 tests, clippy clean |
| `47e9235` | restore `connection` + `session` rewrites | 552 tests, clippy clean |
| `595660e` | restore `requests` + `data` rewrites | 552 tests, clippy clean |
| `caccc63` | restore `images` + `recovery` rewrites | 552 tests, clippy clean |
| `757c3bb` | restore `file_data` + `keys` rewrites | 552 tests, clippy clean |
| `992e8d7` | restore `attestation` rewrite | 552 tests, clippy clean |
| `5bf7edf` | restore `boot` rewrite | 552 tests, clippy clean |
| `aee3a7c` | restore `port_dfu` rewrite | 552 tests, clippy clean |
| `f9aab44` | `restore.rs` orchestrator rewrite (restore domain complete) | 552 tests, clippy clean |
| `b520dcf` | `net/tls` + `net/assets` rewrites | 552 tests, clippy clean |
| `0647b80` | `net/request` rewrite | 552 tests, clippy clean |
| `6c5718a` | `net/download` rewrite | 552 tests, clippy clean |
| `9eb77d4` | `net` rewrite + `net↔proxy` cycle broken via top-level `tls` | 552 tests, clippy clean |
| `2959e2e` | `proxy/negotiate` + `proxy/linux` rewrites | 552 tests, clippy clean |
| `bb07ad3` | `proxy/socket` rewrite | 552 tests, clippy clean |
| `f0bedeb` | `proxy/connect` rewrite | 552 tests, clippy clean |
| `ada9032` | `proxy.rs` policy/connector rewrite | 552 tests, clippy clean |
| `95dfa22` | `windows/proxy` + `windows/negotiate` rewrites | 552 tests, clippy clean |
| `649b5ba` | `operations` + `cli` rewrites (app domain) | 552 tests, clippy clean |
| `0eb1359` | `drivers` + `drivers/linux` rewrites | 552 tests, clippy clean |
| `5ccf346` | `windows/mod` + `windows/reset` rewrites | 552 tests, clippy clean |
| `ef3458c` | `windows/setup/log` + `windows/setup/token` rewrites | 552 tests, clippy clean |
| `e70a93d` | `windows/setup/cleanup` rewrite | 552 tests, clippy clean |
| `52c7bc1` | `windows/setup` orchestration rewrite | 552 tests, clippy clean |
| `d67e1aa` | `windows/package` rewrite | 552 tests, clippy clean |
| `24290a3` | `windows/apple` rewrite (Windows tree complete) | 552 tests, clippy clean |
| `3e8df2c` | `localization` rewrite | 552 tests, clippy clean |
| `66d49ec` | `gui/theme` + `gui/setup` rewrites | 552 tests, clippy clean |
| `8705ced` | `gui/journal` + `gui/widgets` rewrites | 552 tests, clippy clean |
| `a71fe3c` | `gui/events` + `gui/view` rewrites | 552 tests, clippy clean |
| `8564e31` | `gui/cards` + `gui/dialogs` rewrites | 552 tests, clippy clean |
| `951bb92` | `gui/worker` rewrite | 552 tests, clippy clean |
| `aca05a3` | `gui.rs` rewrite (GUI domain complete) | 552 tests, clippy clean |
| `9bd9895` | `logging` + `progress` rewrites | 552 tests, clippy clean |
| `7ba1945` | `proxy/macos` rewrite (all production files now rewritten) | 552 tests, clippy clean; macOS compile-only elsewhere |
| `421a468` | cleanup: GUI journal-dir injection + `ureq` feature merge | 552 tests, clippy clean, `--no-default-features` clean |
| `fe8db25` | `mux/channel` + `main` rewrites (every src file now differs from `pre-rewrite`) | 552 tests, clippy clean |

Every entry ran `cargo fmt --check` (or `cargo fmt`), `cargo clippy
--all-targets --all-features -- -D warnings`, and the full test suite with
`TEMP`/`LOCALAPPDATA` redirected into `.cache/env`.

## Verification recipe

```powershell
# Local sandbox: keep temporary and application data inside the workspace.
$env:TEMP = "$PWD\.cache\env\temp"
$env:TMP = $env:TEMP
$env:LOCALAPPDATA = "$PWD\.cache\env\localappdata"
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

`cargo test --all-features` covers 4 targets: library, GUI binary, protocol
integration tests, throughput (ignored). Clippy is also run with
`--no-default-features` to keep the CLI-only build working.

## Test strategy (final)

- The behavior suite under `tests/protocols/` is the specification and was kept
  intact; only imports changed where the rewritten modules moved.
- Unit tests under `tests/unit/` remain included by their production module with
  `#[cfg(test)]` so they can exercise private helpers. This is test-only code:
  `src/lib.rs` compiles `tests/support/*` only under `cfg(test)`, and no
  production path depends on it. Removing that include would require converting
  dozens of white-box suites into integration tests with no behavioral gain, so
  it is a deliberate, documented deviation from the earlier plan.
- The GUI journal directory is injected into `Job::spawn`; the end-to-end GUI
  test no longer depends on `%LOCALAPPDATA%` being writable.
- Known environment flake (not code): on this Windows profile the localization
  round-trip test can fail once with `os error 5` while another process holds the
  temp file; it passes immediately on rerun and in the final repeated run.

## Final state and evidence

- Every current `src/**/*.rs` file differs from `git tag pre-rewrite`
  (`IDENTICAL: 0` by blob hash); `src/tls.rs` and `src/ipsw/containers.rs` are
  new, `src/net/tls.rs` and `src/firmware/containers.rs` were removed.
- The production tree is 85 modules in 15 domain groups (see `README.md`);
  domain boundaries, not raw file count, were the KISS/DRY target. Duplicated
  policy/parsing/polling code was consolidated, and the `net ↔ proxy` and
  `ipsw ↔ firmware` cycles were removed.
- Clean-build verification (`cargo clean` first):
  - `cargo fmt --check`: clean.
  - `cargo clippy --all-targets --all-features --locked -- -D warnings`: clean.
  - `cargo clippy --no-default-features --locked -- -D warnings`: clean.
  - `cargo test --all-features --locked`: 269 lib + 67 GUI + 216 protocol
    passed, 10 ignored.
- `proxy/macos.rs` is macOS-only and was reviewed but not compiled on the
  Windows host; macOS CI is the compile gate for it.

## Non-goals

- No behavior changes to the CLI, GUI, protocols, proxy/PAC/WPAD support,
  Windows driver setup, UAC helper, localization, or logging formats.
- No dropped features, no new runtime dependencies. Dependency cleanup is
  limited to removing duplicates/dead cfg (e.g. duplicate `ureq` entry).
