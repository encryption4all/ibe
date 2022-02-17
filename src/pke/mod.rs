//! This module contains IND-CPA secure identity-based encryption schemes (IBEs).
//!
//! # Notes
//!
//! These schemes **should** be used in CCA transformations.
//!
//! Some scheme's API slightly differ; some require the system's public key for extraction.  These
//! parameters are made optional.
//!
//! Among the schemes are:
//!
//! - Waters,
//! - Waters-Naccache,
//! - Boyen-Waters,
//! - Chen-Gay-Wee (or short, CGW).

#[cfg(feature = "boyen_waters")]
#[cfg_attr(docsrs, doc(cfg(feature = "boyen_waters")))]
pub mod boyen_waters;

#[cfg(feature = "cgw")]
#[cfg_attr(docsrs, doc(cfg(feature = "cgw")))]
pub mod cgw;

#[cfg(feature = "waters")]
#[cfg_attr(docsrs, doc(cfg(feature = "waters")))]
pub mod waters;

#[cfg(feature = "waters_naccache")]
#[cfg_attr(docsrs, doc(cfg(feature = "waters_naccache")))]
pub mod waters_naccache;

use crate::{Compress, Derive};
use group::Group;
use rand::{CryptoRng, Rng};

/// Identity-based public key encryption scheme (IBPKE).
pub trait IBE {
    /// Master public key (Mpk).
    type Pk: Compress;

    /// Master secret key (Msk).
    type Sk: Compress;

    /// User secret key (Usk).
    type Usk: Compress;

    /// Ciphertext (Ct).
    type Ct: Compress;

    /// Message type (Msg), we require group so that we can draw random messages.
    type Msg: Compress + Group;

    /// Internal identity type (Id).
    type Id: Copy + Derive;

    /// Randomness required to encrypt a message.
    type RngBytes: Sized;

    /// Size of the master public key in bytes.
    const PK_BYTES: usize;

    /// Size of the master secret key in bytes.
    const SK_BYTES: usize;

    /// Size of the user secret key in bytes.
    const USK_BYTES: usize;

    /// Size of the ciphertext in bytes.
    const CT_BYTES: usize;

    /// Size of the message in bytes.
    const MSG_BYTES: usize;

    /// Creates an MSK, MPK pair.
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> (Self::Pk, Self::Sk);

    /// Extract a user secret key for an identity using the MSK.
    ///
    /// Optionally requires the system's public key.
    fn extract_usk<R: Rng + CryptoRng>(
        pk: Option<&Self::Pk>,
        s: &Self::Sk,
        id: &Self::Id,
        rng: &mut R,
    ) -> Self::Usk;

    /// Encrypt a message using the MPK and an identity.
    fn encrypt(pk: &Self::Pk, id: &Self::Id, message: &Self::Msg, rng: &Self::RngBytes)
        -> Self::Ct;

    /// Decrypt a ciphertext using a user secret key to retrieve a message.
    fn decrypt(usk: &Self::Usk, ct: &Self::Ct) -> Self::Msg;
}
