# CHANGELOG.md

## 0.2.0

### Added

- Seperation of KEMs and IBEs and their respective traits (`IBKEM`, `IBE`).
- New anonymous schemes (some CCA-transformed): Chen-Gay-Wee, Boyen-Waters.
- Support for multi-encapsulation (under the `mr` feature).

### Changed

- Bumped dependencies to `irmaseal_curve 0.1.4`, which forks `bls12_381 0.7.0`.
- Speedup several other KEMs using `multi_miller_loop`.
