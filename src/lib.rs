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
//! let kid = <KV1 as IBKEM>::Id::derive(ID.as_bytes());
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
//! let k2 = KV1::decaps(None, &usk, &c).unwrap();
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

use crate::util::sha3_512;
use irmaseal_curve::Scalar;
use subtle::CtOption;

/// Artifacts of the system that can be compressed/decrompressed/copied.
pub trait Compressable: Copy {
    const OUTPUT_SIZE: usize;
    type Output: Sized;
    fn to_bytes(self: &Self) -> Self::Output;
    fn from_bytes(output: &Self::Output) -> CtOption<Self>;
}

/// Size of the identity buffer.
pub const ID_BYTES: usize = 64;

/// Byte representation of an identity.
/// Most schemes use the same representation.
///
/// This identity is obtained by hashing using sha3_512.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Identity([u8; ID_BYTES]);

impl Identity {
    /// Hash a byte slice to a set of Identity parameters, which acts as a user public key.
    /// Uses sha3-512 internally.
    pub fn derive(b: &[u8]) -> Identity {
        Identity(sha3_512(b))
    }

    /// Hash a string slice to a set of Identity parameters.
    /// Directly converts characters to UTF-8 byte representation.
    pub fn derive_str(s: &str) -> Identity {
        Self::derive(s.as_bytes())
    }

    /// Create a scalar from an identity.
    fn to_scalar(&self) -> Scalar {
        Scalar::from_bytes_wide(&self.0)
    }
}
