//! This module contains IND-CCA2 secure identity-based key encapsulation mechanisms (IBKEMs).
//!
//! Among the schemes are:
//! - Kiltz-Vahlis IBE1,
//! - CGWFO (CCA security through FO-transform),
//! - CGWKV (CCA security due to technique by Kiltz-Vahlis applied to CGW).

#[cfg(feature = "kv1")]
#[cfg_attr(docsrs, doc(cfg(feature = "kv1")))]
pub mod kiltz_vahlis_one;

#[cfg(feature = "cgwfo")]
#[cfg_attr(docsrs, doc(cfg(feature = "cgwfo")))]
pub mod cgw_fo;

#[cfg(feature = "cgwkv")]
#[cfg_attr(docsrs, doc(cfg(feature = "cgwkv")))]
pub mod cgw_kv;

#[cfg(feature = "mkem")]
#[cfg_attr(docsrs, doc(cfg(feature = "mkem")))]
pub mod mkem;

use crate::util::*;
use crate::Compress;
use core::ops::BitXorAssign;
use irmaseal_curve::Gt;
use rand_core::{CryptoRng, RngCore};

/// Size of the shared secret in bytes.
pub const SS_BYTES: usize = 32;

/// All KEMs in this library produce a 32-byte shared secret.
///
/// This shared secret has roughly a 127 bits of security.
/// This is due to the fact that BLS12-381 targets this security level (optimistically).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedSecret(pub [u8; SS_BYTES]);

/// Uses SHAKE256 to derive a 32-byte shared secret from a target group element.
///
/// Internally compresses the target group element to byte representation.
impl From<&Gt> for SharedSecret {
    fn from(el: &Gt) -> Self {
        SharedSecret(shake256::<SS_BYTES>(&el.to_compressed()))
    }
}

impl BitXorAssign for SharedSecret {
    fn bitxor_assign(&mut self, rhs: Self) {
        for i in 0..SS_BYTES {
            self.0[i] ^= rhs.0[i];
        }
    }
}

/// Opaque error in case a KEM protocol fails.
#[derive(Debug)]
pub struct Error;

/// Identity-based key encapsulation mechanism (IBKEM).
pub trait IBKEM: Clone {
    /// Scheme identifier.
    const IDENTIFIER: &'static str;

    /// Master public key (Mpk).
    type Pk: Compress;

    /// Master secret key (Msk).
    type Sk: Compress;

    /// User secret key (Usk).
    type Usk: Compress;

    /// Ciphertext (Ct).
    type Ct: Compress + Default;

    /// Identity.
    type Id: Copy + Default;

    /// Scheme-specific inputs to the extraction (other than the identity).
    type ExtractParams<'pk, 'sk>;

    /// Scheme-specific inputs to the decapsulation (other than the ciphertext).
    type DecapsParams<'pk, 'usk>;

    /// Size of the master public key in bytes.
    const PK_BYTES: usize;

    /// Size of the master secret key in bytes.
    const SK_BYTES: usize;

    /// Size of the user secret key in bytes.
    const USK_BYTES: usize;

    /// Size of the ciphertext in bytes.
    const CT_BYTES: usize;

    /// Creates a MSK, MPK pair.
    fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::Pk, Self::Sk);

    /// Extract a user secret key for an identity using the MSK.
    ///
    /// Optionally requires the system's public key, see [`Self::ExtractParams`].
    fn extract_usk<R: RngCore + CryptoRng>(
        ep: Self::ExtractParams<'_, '_>,
        id: &Self::Id,
        rng: &mut R,
    ) -> Self::Usk;

    /// Encapsulate a shared secret using the master public key and an identity.
    fn encaps<R: RngCore + CryptoRng>(
        pk: &Self::Pk,
        id: &Self::Id,
        rng: &mut R,
    ) -> (Self::Ct, SharedSecret);

    /// Decrypt a ciphertext using a user secret key to retrieve the shared secret.
    ///
    /// Optionally requires a public key to perform this operation.
    ///
    /// For some schemes this operation can fail explicitly, e.g., when
    /// an illegitimate ciphertext is used as input.
    fn decaps(dp: Self::DecapsParams<'_, '_>, ct: &Self::Ct) -> Result<SharedSecret, Error>;
}
