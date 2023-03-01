# CHANGELOG.md

## Unreleased

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
