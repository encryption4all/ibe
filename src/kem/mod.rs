//! This module contains CCA2 secure key encapsulation mechnisms based on IBE schemes.
//!
//! Among the schemes are:
//!
//! - Kiltz-Vahlis IBE1,
//! - CGWFO (CCA security through FO-transform),
//! - CGWKV1-3 (CCA security due to technique by Kiltz-Vahlis applied to CGW).

pub mod cgw_fo;
pub mod cgw_kv1;
pub mod cgw_kv2;
pub mod cgw_kv3;
pub mod kiltz_vahlis_one;

use crate::util::*;
use crate::Compressable;
use irmaseal_curve::Gt;
use rand::{CryptoRng, Rng};

/// All KEMs in this library produce a 64-byte shared secret.
///
/// This shared secret has roughly a 127 bits of security.
/// This is due to the fact that BLS12-381 targets this security level (optimistically).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedSecret(pub [u8; 64]);

/// Uses SHAKE256 to derive a 64-byte shared secret from a target group element.
///
/// Internally compresses the target group element to byte representation.
impl From<&Gt> for SharedSecret {
    fn from(el: &Gt) -> Self {
        SharedSecret(shake256::<64>(&el.to_compressed()))
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

    /// User secret key (USK)
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
    ) -> (Self::Ct, Self::Ss) {
        let (cts, k) = Self::multi_encaps::<R, 1>(pk, &[id], rng);
        (cts[0], k)
    }

    /// Encapsulate the same shared secret in multiple ciphertexts.
    ///
    /// This allows to sent an encrypted broadcast message to N receivers.
    ///
    /// # Warning
    ///
    /// Not all schemes hide the identity associated with each ciphertext.
    fn multi_encaps<R: Rng + CryptoRng, const N: usize>(
        pk: &Self::Pk,
        ids: &[&Self::Id; N],
        rng: &mut R,
    ) -> ([Self::Ct; N], Self::Ss);

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
