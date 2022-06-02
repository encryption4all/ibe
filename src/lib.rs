//! Collection of Identity Based Encryption (IBE) schemes on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381) in Rust.
//! This crate contains both identity-based encryption schemes (IBEs, see [the pke module](`crate::pke`)) and identity-based key encapsulation mechanisms (IBKEMs, see [the kem module](`crate::kem`)).
//! References to papers appear in the respective source files.
//!
//! This crate contains the following schemes (in chronological order of publication):
//! * Waters (IND-ID-CPA IBE),
//! * Boyen-Waters (IND-sID-CPA IBE),
//! * Waters-Naccache (IND-ID-CPA IBE),
//! * Kiltz-Vahlis IBE1 (IND-CCA2 IBKEM),
//! * Chen-Gay-Wee (IND-ID-CPA IBE, IND-ID-CCA2 IBKEM).
//!
//! # Examples
//!
//! The following example is similar for all the KEM schemes. Check the corresponding tests for
//! concrete examples per scheme. To actually run this example, do not forget to enable the `kv1`
//! feature.
//!
//! ```
//! use ibe::Derive;
//! use ibe::kem::IBKEM;
//! use ibe::kem::kiltz_vahlis_one::*;
//!
//! const ID: &'static str = "email:w.geraedts@sarif.nl";
//! let mut rng = rand::thread_rng();
//!
//! // Derive an identity (specific to this scheme).
//! let kid = <KV1 as IBKEM>::Id::derive_str(ID);
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
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(test)]
extern crate std;

#[cfg(feature = "mr")]
extern crate alloc;

#[cfg(test)]
#[macro_use]
#[allow(unused)]
mod test_macros;

#[allow(unused)]
mod util;

pub mod kem;
pub mod pke;

/// Artifacts of the system that can be compressed should implement this trait.
///
/// Secret artifacts such as the master secret key, user secret key should implement this in
/// constant-time.
pub trait Compress: Copy {
    const OUTPUT_SIZE: usize;
    type Output: Sized + Copy + Clone + AsRef<[u8]>;

    /// Compresses this artifact to a short serialized byte representation.
    fn to_bytes(&self) -> Self::Output;

    /// Decompresses a serialized artifact.
    fn from_bytes(output: &Self::Output) -> subtle::CtOption<Self>;
}

/// Trait that is used to derive identities for schemes.
pub trait Derive: Sized {
    /// Derive an identity for a scheme from a byte slice.
    fn derive(b: &[u8]) -> Self;

    /// Derive an identity for a schem from a string.
    /// Internally uses UTF-8 encoding `as_bytes()`.
    fn derive_str(s: &str) -> Self {
        Self::derive(s.as_bytes())
    }
}
