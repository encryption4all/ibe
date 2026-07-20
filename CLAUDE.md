# CLAUDE.md

## Agent notes (migrated from the dobby memory repo)

## Overview
`encryption4all/ibe` is an identity-based encryption crate (`no_std`,
`#![forbid(unsafe_code)]`) providing PostGuard's IBE schemes. PostGuard production
uses `ibe` with only the `cgwkv` and `mkem` features enabled.

## Architecture
- CGWKV + MKEM is used for multi-recipient encryption. MKEM wraps IBKEM with
  AES-128-GCM: a random session key, encrypted per recipient.
- Identity = SHA3-512(input), 64 bytes, fed through `Scalar::from_bytes_wide` for
  CGWKV.
- SharedSecret = SHAKE256(compressed Gt element), 32 bytes.
- BLS12-381 targets roughly 127 bits of security.
- Sibling crate `ibs` has a `zeroize` feature; `ibe` does not yet (open issue #7).

## Security: already fixed on main, don't re-audit
An in-depth security audit on 2026-07-04 produced several findings across the
IBE schemes and the mkem/shared-secret paths; all of them are fixed and shipped
on main, so don't re-audit them. Per-finding detail (root cause and fix
location) lives in this repo's private security advisories while they are
embargoed. Restore the per-finding summary here once those advisories are
published.
- Zeroize: an optional `zeroize` feature exists (#14). Types are `Copy`, so it's
  `Zeroize` (not `ZeroizeOnDrop`); callers must explicitly call `.zeroize()`.
  Further hardening tracked in open issue #45.

## Code quality
`no_std`, `#![forbid(unsafe_code)]`. `.unwrap()`s are only used on constant-size
slices.

## Dependency constraint: rand/getrandom bumps are blocked
`ibe`'s `rand` (0.8 to 0.10) and wasm32 `getrandom` (0.2 to 0.4) bumps cannot land
independently. `group`, `ff`, `pairing`, and `pg-curve` all transitively pull in
`rand_core 0.6`; `ibe` calls `Group::random(&mut rng)` / `Scalar::random(...)`,
which need `&mut R: RngCore + CryptoRng` from rand_core 0.6. Bumping `ibe`'s
`rand` to 0.10 (a separate, incompatible `rand_core 0.10` type) breaks every call
site. The wasm32 `getrandom = "0.2", features = ["js"]` direct dep exists only to
enable the `js` feature on the copy pulled in transitively via `rand_core 0.6`;
switching the direct dep to 0.4 just adds an unused parallel copy. Don't attempt
either bump until the BLS curve stack (pg-curve, pairing, group, ff) publishes a
rand_core-0.10-compatible release; re-verify pg-curve's current `rand_core`
version before retrying.

As of 2026-07-16 (issue #53) the specific blocker is the `pairing` crate.
`group 0.14.0` and `ff 0.14.0` are published and stable (both on `rand_core 0.10`),
but no stable `pairing` release is compatible with them: the only 0.24 is
`pairing 0.24.0-pre.0`, a pre-release that pins `group =0.14.0-pre.0` (itself on
`rand_core 0.9`, not 0.10). `pg-curve` is a fork of `bls12_381` and must implement
the `pairing` traits; `multi_miller_loop`, `pairing`, `Gt`, and `G2Prepared` are
used throughout ibe's schemes (see `src/ibe/*` and `src/kem/*`), so pg-curve cannot
advance to `group 0.14` until a stable `pairing 0.24` (or an upstream `bls12_381`
0.9) exists. Upstream `bls12_381` is likewise still 0.8.0 on `group 0.13`.
Empirically, bumping pg-curve to `pairing = "0.24"` fails resolution, and forcing
the `-pre.0` stack only reaches `rand_core 0.9` (and pulls in duplicate `rand_core`
copies), so it does not satisfy this bump either. Re-check crates.io for a stable
`pairing 0.24` before retrying.

## Release process
Migrating from a manual `cargo publish` / `git tag` flow to release-plz automation
(PR #35, 2026-05-17). The `release-plz.toml` config has landed, but the
`.github/workflows/release-plz.yml` workflow is not yet present — the bot lacks the
`workflows` permission, so the workflow file still needs manual human application
before the automation is live. Until then the release flow is still manual.
(This supersedes older "manual release, no automation" claims about ibe that still
circulate; check for `release-plz.toml` at the repo root if this ever seems out of
date again.)
- `release-plz.toml` at repo root: single-crate config, `git_tag_name =
  "v{{ version }}"`, `[[package]] name = "ibe"`, `publish = true`.
- `.github/workflows/release-plz.yml` (still to be applied by a human): two jobs
  (`release-plz-release` and `release-plz-pr`), using `release-plz/action@v0.5`,
  `dtolnay/rust-toolchain@stable`, `actions/checkout@v6`. Mirrors postguard's
  delivery workflow minus the multi-package Docker/pg-pkg/pg-ffi/pg-core parsing.
- Bootstrapped at version 0.4.0, not 0.3.1: the `bits()` fix (PR #13) changes
  identity derivation for KV1 and Waters, a cryptographic behavior change even
  though the public Rust API is unchanged, so the pre-1.0 minor bump is the
  honest signal. `CHANGELOG.md` has a manually-written `## 0.4.0` bootstrap entry;
  release-plz only generates entries for commits after it.
- Maintainer prerequisites: repo secret `CARGO_REGISTRY_TOKEN` (same value used
  for postguard/cryptify); Settings > Actions > General > Workflow permissions >
  "Allow GitHub Actions to create and approve pull requests".
- The automating bot lacks the `workflows` permission, so workflow file changes
  here have to be delivered as a patch in a comment for a human to apply.
