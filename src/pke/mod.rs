//! This module contains traits and implementations for some IBE schemes.
//! All schemes are IND-CPA secure. References to the original appearance in the literature
//! are listed in the top of each source file.
//!
//! # Note
//! Some scheme's API slightly differ; some require the system's public key for extraction.
//! These parameters are made optional.
//!
//! Among the schemes are:
//!
//! - Waters
//! - Waters-Naccache
//! - Chen-Gay-Wee (or short, CGW)

pub mod boyen_waters;
pub mod cgw;
pub mod waters;
pub mod waters_naccache;

use crate::Compressable;
use group::Group;
use rand::Rng;

/// Identity-based public key encryption scheme (IBPKE)
pub trait IBE {
    /// Master public key (MPK)
    type Pk: Compressable;

    /// Master secret key (MSK)
    type Sk: Compressable;

    /// User secret key (USK)
    type Usk: Compressable;

    /// Ciphertext (CT)
    type Ct: Compressable;

    /// Message type (m), we require group so that we can draw random messages
    type Message: Compressable + Group;

    /// Internal identity type (id)
    type Id: Copy + Clone;

    /// Randomness required to encrypt a message
    type RngBytes: Sized;

    /// Sizes
    const PK_BYTES: usize;
    const SK_BYTES: usize;
    const USK_BYTES: usize;
    const CT_BYTES: usize;
    const MSG_BYTES: usize;

    /// Creates a MSK, MPK pair
    fn setup<R: Rng>(rng: &mut R) -> (Self::Pk, Self::Sk);

    /// Extract a user secret key for an identity using the MSK
    ///
    /// Optionally requires the system's public key
    fn extract_usk<R: Rng>(
        pk: Option<&Self::Pk>,
        s: &Self::Sk,
        id: &Self::Id,
        rng: &mut R,
    ) -> Self::Usk;

    /// Encrypt a message using a MPK and an identity
    fn encrypt(
        pk: &Self::Pk,
        id: &Self::Id,
        message: &Self::Message,
        rng: &Self::RngBytes,
    ) -> Self::Ct;

    /// Decrypt a ciphertext using a user secret key to retrieve a message
    fn decrypt(usk: &Self::Usk, ct: &Self::Ct) -> Self::Message;
}
