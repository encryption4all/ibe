# ibe

> For full documentation, visit [docs.postguard.eu](https://docs.postguard.eu/repos/ibe).

A collection of Identity-Based Encryption (IBE) schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/encryption4all/pg-curve) in Rust. This crate contains both identity-based encryption schemes (see `src/pke`) and identity-based key encapsulation mechanisms (see `src/kem`).

In the PostGuard ecosystem, this crate provides the cryptographic IBE primitives that `pg-core` builds on to encrypt and decrypt messages using identity attributes.

The following schemes are included (in chronological order of publication):

- Waters (IND-ID-CPA IBE)
- Boyen-Waters (IND-sID-CPA IBE)
- Waters-Naccache (IND-ID-CPA IBE)
- Kiltz-Vahlis IBE1 (IND-CCA2 IBKEM)
- Chen-Gay-Wee (IND-ID-CPA IBE, IND-ID-CCA2 IBKEM)

References to papers appear in the respective source files.

## Technical notes

- **This implementation has not (yet) been reviewed or audited. Use at your own risk.**
- Uses [Keccak](https://crates.io/crates/tiny-keccak) for hashing to identities, hashing to secrets and as symmetric primitives for the Fujisaki-Okamoto transform.
- Compiles successfully on Rust Stable.
- Does not use the Rust standard library (no-std).
- The structure of the byte serialisation of the various datastructures is not guaranteed to remain constant between releases of this library.
- All operations in this library are implemented to run in constant time.
- The performance of this library mostly depends on the arithmetic of the underlying curve operations, BLS12-381. Any new optimizations to the original library could significantly increase performance of the schemes in this crate. It should therefore be considered to merge these optimizations into this crate as well (via the `pg-curve` crate).

## Development

Build the crate:

```sh
cargo build --release
```

Run all tests:

```sh
cargo test --release --all-features
```

## Releasing

New versions are published manually to [crates.io](https://crates.io/crates/ibe). Bump the version in `Cargo.toml`, commit, tag, and run `cargo publish`.

## License

MIT
