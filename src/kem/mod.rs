//! This module contains CCA2 secure key encapsulation mechnisms based on IBE schemes.
//!
//! Among the schemes are:
//!
//! - Kiltz-Vahlis IBE1,
//! - CGWFO (CCA security through FO-transform),
//! - CGWKV1-3 (CCA security due to technique by Kiltz-Vahlis applied to CGW).

#[cfg(any(feature = "cgwfo", doc))]
#[doc(cfg(feature = "cgwfo"))]
pub mod cgw_fo;

#[cfg(any(feature = "cgwkv1", doc))]
#[doc(cfg(feature = "cgwkv1"))]
pub mod cgw_kv1;

#[cfg(any(feature = "cgwkv2", doc))]
#[doc(cfg(feature = "cgwkv2"))]
pub mod cgw_kv2;

#[cfg(any(feature = "cgwkv3", doc))]
#[doc(cfg(feature = "cgwkv3"))]
pub mod cgw_kv3;

#[cfg(any(feature = "kv1", doc))]
#[doc(cfg(feature = "kv1"))]
pub mod kiltz_vahlis_one;

use crate::util::*;
use crate::Compressable;
use irmaseal_curve::Gt;
use rand::{CryptoRng, Rng};

/// Size of the shared secret in bytes.
pub const SS_BYTES: usize = 64;

/// All KEMs in this library produce a 64-byte shared secret.
///
/// This shared secret has roughly a 127 bits of security.
/// This is due to the fact that BLS12-381 targets this security level (optimistically).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedSecret(pub [u8; SS_BYTES]);

/// Uses SHAKE256 to derive a 64-byte shared secret from a target group element.
///
/// Internally compresses the target group element to byte representation.
impl From<&Gt> for SharedSecret {
    fn from(el: &Gt) -> Self {
        SharedSecret(shake256::<SS_BYTES>(&el.to_compressed()))
    }
}

/// Error indicating that the decapsulation was not successful.
#[derive(Debug)]
pub struct DecapsulationError;

/// Identity-based public key encapsulation mechanism (IBKEM).
pub trait IBKEM {
    /// Master public key (MPK).
    type Pk: Compressable;

    /// Master secret key (MSK).
    type Sk: Compressable;

    /// User secret key (USK).
    type Usk: Compressable;

    /// Ciphertext (CT).
    type Ct: Compressable;

    /// Identity.
    type Id: Copy;

    /// Shared secret.
    type Ss: Copy;

    /// Sizes of this system's artifacts.
    const PK_BYTES: usize;
    const SK_BYTES: usize;
    const USK_BYTES: usize;
    const CT_BYTES: usize;

    /// Creates a MSK, MPK pair.
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> (Self::Pk, Self::Sk);

    /// Extract a user secret key for an identity using the MSK.
    ///
    /// Optionally requires the system's public key.
    fn extract_usk<R: Rng + CryptoRng>(
        pk: Option<&Self::Pk>,
        sk: &Self::Sk,
        id: &Self::Id,
        rng: &mut R,
    ) -> Self::Usk;

    /// Encapsulate a shared secret using the master public key and an identity.
    fn encaps<R: Rng + CryptoRng>(
        pk: &Self::Pk,
        id: &Self::Id,
        rng: &mut R,
    ) -> (Self::Ct, Self::Ss);

    /// Decrypt a ciphertext using a user secret key to retrieve the shared secret.
    ///
    /// Optionally requires a public key to perform this operation.
    ///
    /// For some schemes this operation can fail explicitly, e.g., when
    /// a bogus ciphertext is used as input.
    fn decaps(
        mpk: Option<&Self::Pk>,
        usk: &Self::Usk,
        ct: &Self::Ct,
    ) -> Result<Self::Ss, crate::kem::DecapsulationError>;
}
