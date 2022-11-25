//! Collection of Identity Based Encryption (IBE) schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381) in Rust.
//! This crate contains both identity-based encryption schemes (IBEs, see [the ibe module](`crate::ibe`)) and identity-based key encapsulation mechanisms (IBKEMs, see [the kem module](`crate::kem`)).
//! References to papers appear in the respective source files.
//!
//! This crate contains the following schemes (in chronological order of publication):
//! * [`Waters`](ibe::waters) (IND-ID-CPA IBE),
//! * [`Boyen-Waters`](ibe::boyen_waters) (IND-sID-CPA IBE),
//! * [`Waters-Naccache`](ibe::waters_naccache) (IND-ID-CPA IBE),
//! * [`Kiltz-Vahlis IBE1`](kem::kiltz_vahlis_one) (IND-CCA2 IBKEM),
//! * [`Chen-Gay-Wee Fujisaki-Okamoto`](kem::cgw_fo) (IND-ID-CPA IBE, IND-ID-CCA2 IBKEM).
//! * [`Chen-Gay-Wee Kiltz-Vahlis`](kem::cgw_kv) (IND-ID-CPA IBE, IND-ID-CCA2 IBKEM).
//!
//! # Examples
//!
//! The following example is similar for all the KEM schemes. Check the corresponding tests for
//! concrete examples per scheme. To actually run this example, do not forget to enable the `kv1`
//! feature.
//!
//! ```
//! use ibe::kem::IBKEM;
//! use ibe::kem::kiltz_vahlis_one::*;
//!
//! let mut rng = rand::thread_rng();
//!
//! // Derive an identity (specific to this scheme).
//! let id = <KV1 as IBKEM>::Id::from("Johnny");
//!
//! // Generate a public-private-keypair for a trusted third party.
//! let (pk, sk) = KV1::setup(&mut rng);
//!
//! // Extract a private key for an identity / user.
//! let usk = KV1::extract_usk((&pk, &sk), &id, &mut rng);
//!
//! // Generate a random message and encrypt it with the public key and an identity.
//! let (c, k) = KV1::encaps(&pk, &id, &mut rng);
//!
//! // Decrypt the ciphertext of that message with the private key of the user.
//! let k2 = KV1::decaps(&usk, &c).unwrap();
//!
//! assert_eq!(k, k2);
//! ```

#![no_std]
#![deny(missing_debug_implementations, rust_2018_idioms, missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use core::fmt::Debug;

#[cfg(test)]
extern crate std;

#[macro_use]
#[cfg(test)]
mod macros;

#[allow(unused)]
mod util;

pub mod ibe;
pub mod kem;

/// Artifacts of the system that can be compressed should implement this trait.
///
/// Secret artifacts such as the master secret key, user secret key should implement this in
/// constant-time.
pub trait Compress: Debug + Sized + Clone {
    /// The size of the compressed output.
    const OUTPUT_SIZE: usize;

    /// The type of the output.
    type Output: Sized + AsRef<[u8]>;

    /// Compresses this artifact to a short serialized byte representation.
    fn to_bytes(&self) -> Self::Output;

    /// Decompresses a serialized artifact.
    fn from_bytes(output: &Self::Output) -> subtle::CtOption<Self>;
}
