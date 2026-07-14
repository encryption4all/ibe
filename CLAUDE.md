
---

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
From the 2026-07-04 in-depth security audit, all findings below are fixed and
shipped on main:
- `bits()` identity collapse (ibe#12/#13): fixed via `flat_map` instead of `zip`
  in `src/util.rs:43-49`; a test asserts `64*8` bits. Had collapsed the identity
  space of the KV1 and Waters schemes to 2^8 = 256. CGWKV, CGWFO, CGW, and
  Boyen-Waters were never affected, and PostGuard production uses CGWKV so was
  never affected either.
- mkem raw-truncation into an AES key (GHSA-236p-m8qr-cmjg): fixed via
  HKDF-SHA256 with domain-separation label `ibe-mkem-aes128gcm` in
  `derive_aead_key`, `src/kem/mkem.rs:68`.
- Non-constant-time secret equality (GHSA-whr9-835c-9m5j): fixed; `SharedSecret`
  now implements `ConstantTimeEq` and `PartialEq` via `ct_eq`.
- KV1 fixed identity point for `hzero` (GHSA-wvwc-w2wm-hx95): fixed via a random
  G1 point.
- Public-key deserialization skipped the subgroup check (GHSA-25fp-2fjj-g84w,
  issue #50, PR #51): `from_bytes` in `cgw.rs`, `cgw_kv.rs`,
  `kiltz_vahlis_one.rs` (`PublicKey` and `HashParameters`), and
  `boyen_waters.rs` used `from_compressed_unchecked`; switched to the checked
  `from_compressed`. USK/CT `from_bytes` already used the checked variant. When
  auditing curve-point deserialization in this crate, grep for
  `from_compressed_unchecked` per-file; don't trust a prior "reviewed, clean"
  note, since this exact bug hid in that gap.
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

## Release process
Release-plz automation, migrated from a manual `cargo publish` / `git tag` flow on
PR #35 (2026-05-17). (This supersedes older "manual release, no automation"
claims about ibe that still circulate; check for `release-plz.toml` at the repo
root if this ever seems out of date again.)
- `release-plz.toml` at repo root: single-crate config, `git_tag_name =
  "v{{ version }}"`, `[[package]] name = "ibe"`, `publish = true`.
- `.github/workflows/release-plz.yml`: two jobs (`release-plz-release` and
  `release-plz-pr`), using `release-plz/action@v0.5`, `dtolnay/rust-toolchain@stable`,
  `actions/checkout@v6`. Mirrors postguard's delivery workflow minus the
  multi-package Docker/pg-pkg/pg-ffi/pg-core parsing.
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
