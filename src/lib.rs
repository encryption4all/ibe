//! Identity Based Encryption schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381).
//!
//! Implements the following schemes:
//! * Waters
//! * Waters-Naccache
//! * Kiltz-Vahlis IBE1
//! * Chen-Gay-Wee
//!
//! ## How to use
//! The following example is similar for all the schemes.
//! Check the corresponding tests for concrete examples per scheme.
//!
//! ```
//! use ibe::kem::IBKEM;
//! use ibe::kem::kiltz_vahlis_one::*;
//!
//! const ID: &'static str = "email:w.geraedts@sarif.nl";
//! let mut rng = rand::thread_rng();
//!
//! // Hash the identity to a set of scalars.
//! let kid = Identity::derive(ID.as_bytes());
//!
//! // Generate a public-private-keypair for a trusted third party.
//! let (pk, sk) = KV1::setup(&mut rng);
//!
//! // Extract a private key for an identity / user.
//! let usk = KV1::extract_usk(Some(&pk), &sk, &kid, &mut rng);
//!
//! // Generate a random message and encrypt it with the public key and an identity.
//! let (c, k) = KV1::encaps(&pk, &kid, &mut rng);
//!
//! // Decrypt the ciphertext of that message with the private key of the user.
//! let k2 = KV1::decaps(None, &usk, &c);
//!
//! assert_eq!(k, k2);
//! ```

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

#[macro_use]
mod util;

pub mod kem;

#[doc(hidden)]
pub mod pke;

use subtle::CtOption;

/// Artifact that can be compressed/decrompressed.
pub trait Compressable: Sized {
    const OUTPUT_SIZE: usize;
    type Output: Sized;
    fn to_bytes(self: &Self) -> Self::Output;
    fn from_bytes(output: &Self::Output) -> CtOption<Self>;
}
