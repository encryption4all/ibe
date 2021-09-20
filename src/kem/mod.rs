//! This module contains CCA2 secure key encapsulation mechnisms based on IBE schemes.
//!
//! Among the schemes are:
//!
//! - Kiltz-Vahlis IBE1
//! - CGWFO (CCA security through FO-transform)
//! - CGWKV1-3 (CCA security due to technique by Kiltz-Vahlis applied to CGW)

pub mod cgw_fo;
pub mod cgw_kv1;
pub mod cgw_kv2;
pub mod cgw_kv3;
pub mod kiltz_vahlis_one;

use crate::Compressable;
use rand::Rng;

/// Identity-based public key encapsulation mechanism (IBKEM)
pub trait IBKEM {
    /// Master public key (MPK)
    type Pk: Compressable;

    /// Master secret key (MSK)
    type Sk: Compressable;

    /// User secret key (USK)
    type Usk: Compressable;

    /// Ciphertext (CT)
    type Ct: Compressable + Copy;

    /// Identity
    type Id: Copy + Clone + Sized;

    /// Shared secret
    type Ss: Sized;

    /// Sizes of this system's artifacts
    const PK_BYTES: usize;
    const SK_BYTES: usize;
    const USK_BYTES: usize;
    const CT_BYTES: usize;

    /// Creates a MSK, MPK pair
    fn setup<R: Rng>(rng: &mut R) -> (Self::Pk, Self::Sk);

    /// Extract a user secret key for an identity using the MSK
    ///
    /// Optionally requires the system's public key
    fn extract_usk<R: Rng>(
        pk: Option<&Self::Pk>,
        sk: &Self::Sk,
        id: &Self::Id,
        rng: &mut R,
    ) -> Self::Usk;

    /// Encapsulate a shared secret using MPK and an identity
    fn encaps<R: Rng>(pk: &Self::Pk, id: &Self::Id, rng: &mut R) -> (Self::Ct, Self::Ss) {
        let (cts, k) = Self::multi_encaps::<R, 1>(pk, &[id], rng);
        (cts[0], k)
    }

    /// Encapsulate the same shared secret in multiple ciphertexts
    ///
    /// This allows to sent an encrypted broadcast message to N participants
    ///
    /// # Warning
    /// Not all schemes hide the identity associated with each ciphertext.
    fn multi_encaps<R: Rng, const N: usize>(
        pk: &Self::Pk,
        ids: &[&Self::Id; N],
        rng: &mut R,
    ) -> ([Self::Ct; N], Self::Ss);

    /// Decrypt a ciphertext using a user secret key to retrieve the shared secret
    ///
    /// Optionally requires a public key to perform this operation
    fn decaps(mpk: Option<&Self::Pk>, usk: &Self::Usk, ct: &Self::Ct) -> Self::Ss;
}
