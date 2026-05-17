# CHANGELOG.md

## 0.4.0

### Security

- `bits()` in `src/util.rs` now produces all bits from its input slice instead of
  `min(input_len, 8)`. This restores the full identity space for the **KV1** and
  **Waters** schemes, which previously collapsed to 2^8 = 256. Fixes
  [#12](https://github.com/encryption4all/ibe/issues/12) via
  [#13](https://github.com/encryption4all/ibe/pull/13).

  **Breaking for KV1 and Waters users:** identity derivation for these two schemes
  now produces different values, so user secret keys (USKs) and ciphertexts issued
  by a 0.3.0 build are not compatible with 0.4.0. The other schemes
  (CGWKV, CGWFO, CGW, Boyen-Waters, Waters-Naccache) are unaffected.

### Added

- Realistic-identity collision tests for KV1 and Waters
  ([#13](https://github.com/encryption4all/ibe/pull/13)).
- Clippy lint job in CI ([#15](https://github.com/encryption4all/ibe/issues/15),
  [#22](https://github.com/encryption4all/ibe/pull/22)).

### Changed

- Bumped `criterion` dev-dependency to 0.8
  ([#26](https://github.com/encryption4all/ibe/pull/26)).
- Replaced the unmaintained `paste` dev-dependency with `pastey`
  ([#31](https://github.com/encryption4all/ibe/pull/31), addresses
  [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436)).
- Standardized README to the org-wide format and added the PostGuard logo
  ([#11](https://github.com/encryption4all/ibe/pull/11)).
- Cleaned up clippy warnings throughout the crate
  ([#16](https://github.com/encryption4all/ibe/issues/16),
  [#21](https://github.com/encryption4all/ibe/pull/21)).
- Dropped AI-slop phrasing from README and `mkem` doc comment
  ([#24](https://github.com/encryption4all/ibe/pull/24)).

### Fixed

- Replaced the deprecated `wasm32-wasi` target with `wasm32-wasip1` in CI.
- README reference `src/pke` → `src/ibe`
  ([#20](https://github.com/encryption4all/ibe/pull/20)).
- Silence unused-import warning in the `test_ibe` macro
  ([#34](https://github.com/encryption4all/ibe/pull/34)).

### Removed

- Commented-out `unpack_pk` benchmark
  ([#19](https://github.com/encryption4all/ibe/pull/19)).

## 0.3.0

### Changed

- Changed multi-user key encapsulation, see [this PR](https://github.com/encryption4all/ibe/pull/10).
- Changed `irmaseal-curve 0.1.4` to `pg-curve 0.2.0` (includes `bls12_381 0.8`).

## 0.2.3

### Added

- w-NAF precomputations speedups in all CGW schemes.

### Changed

- reference IACR eprint version in `CGWKV` CCA construction.

## 0.2.2

### Added

- All publicly exposed structs are `Debug` (`#[deny(missing_debug_implementations)]`).

### Changed

- renamed `mr` module to `mkem`.
- renamed `pke` module to `ibe`.
- Multirecipient encapsulation now returns an iterator.

## 0.2.1

### Removed

- Binary that prints the sizes. No longer required since constants are now listed on docs.rs.

## 0.2.0

### Added

- Seperation of KEMs and IBEs and their respective traits (`IBKEM`, `IBE`).
- New anonymous schemes (some CCA-transformed): Chen-Gay-Wee, Boyen-Waters.
- Support for multi-encapsulation (under the `mr` feature).

### Changed

- Bumped dependencies to `irmaseal_curve 0.1.4`, which forks `bls12_381 0.7.0`.
- Speedup several other KEMs using `multi_miller_loop`.
