# IBE
Collection of Identity Based Encryption (IBE) schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381) in Rust.
This crate contains both identity-based encryption schemes (IBEs, see `src/pke`) and identity-based key encapsulation mechanisms (IBKEMs, see `src/kem`). References to papers appear in the respective source files.

This crate contains the following schemes (in chronological order of publication):
* Waters (IND-ID-CPA IBE),
* Boyen-Waters (IND-sID-CPA IBE),
* Waters-Naccache (IND-ID-CPA IBE),
* Kiltz-Vahlis IBE1 (IND-CCA2 IBKEM),
* Chen-Gay-Wee (IND-ID-CPA IBE, IND-ID-CCA2 IBKEM).

## Technical notes
* **This implementation has not (yet) been reviewed or audited. Use at your own risk.**
* Uses [Keccak](https://crates.io/crates/tiny-keccak) for hashing to identities, hashing to secrets and as symmetric primitives for the Fujisaki-Okamoto transform.
* Compiles succesfully on Rust Stable.
* Does not use the Rust standard library (no-std).
* The structure of the byte serialisation of the various datastructures is not guaranteed to remain constant between releases of this library.
* All operations in this library are implemented to run in constant time.
* The binary sourced by the file in `src/bin/sizes.rs` produces a binary that prints various sizes of different schemes.

## TODO's
* The underlying libraries might benefit from running on Rust nightly, which prevents compiler optimizations that could jeopardize constant time operations, but enabling this will require using `subtle/nightly`.
* The performance of this library is heavily dependant on the arithmetic of the underlying curve, BLS12-381. Any new optimizations to the original library could significantly increase performance of the schemes in this crate. It should therefore be considered to merge these optimizations into this crate as well (via the `irmaseal-curve` crate).
