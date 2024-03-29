//! IND-ID-CCA2 secure IBKEM by a scheme by Chen, Gay and Wee.
//! * From: "[Improved Dual System ABE in Prime-Order Groups via Predicate Encodings](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!
//! CCA security due to a general approach by Fujisaki and Okamoto.
//! * From: "[A Modular Analysis of the Fujisaki-Okamoto Transformation](https://eprint.iacr.org/2017/604.pdf)"
//!
//! Symmetric primitives G and H instantiated using sha3_512 and sha3_256, respectively.
//! To output a bigger secret SHAKE256 can be used with a bigger output buffer.
//!
//! A drawback of a Fujisaki-Okamoto transform is that we now need the public key to decapsulate.

use crate::ibe::cgw::{CipherText, Msg, CGW, USK_BYTES as CPA_USK_BYTES};
use crate::ibe::IBE;
use crate::kem::{Error, SharedSecret, IBKEM};
use crate::util::*;
use crate::Compress;
use arrayref::{array_refs, mut_array_refs};
use group::Group;
use rand::{CryptoRng, Rng};
use subtle::{ConstantTimeEq, CtOption};

/// These struct are identical for the CCA KEM.
pub use crate::ibe::cgw::{PublicKey, SecretKey, CT_BYTES, MSG_BYTES, PK_BYTES, SK_BYTES};

/// Size of the compressed user secret key in bytes.
///
/// The USK includes a random message and the identity (needed for re-encryption).
pub const USK_BYTES: usize = CPA_USK_BYTES + ID_BYTES;

/// User secret key. Can be used to decaps the corresponding ciphertext.
/// Also known as USK_{id}.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UserSecretKey {
    usk: crate::ibe::cgw::UserSecretKey,
    id: Identity,
}

impl Compress for UserSecretKey {
    const OUTPUT_SIZE: usize = USK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut buf = [0u8; USK_BYTES];
        let (usk, id) = mut_array_refs![&mut buf, CPA_USK_BYTES, ID_BYTES];

        *usk = self.usk.to_bytes();
        id.copy_from_slice(&self.id.0);

        buf
    }

    fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let (usk, rid) = array_refs![&bytes, CPA_USK_BYTES, ID_BYTES];

        let usk = crate::ibe::cgw::UserSecretKey::from_bytes(usk);
        let id = Identity(*rid);

        usk.map(|usk| UserSecretKey { usk, id })
    }
}

/// The CCA2 secure KEM that results by applying the implicit rejection
/// variant of the Fujisaki-Okamoto transform to the Chen-Gay-Wee IBE scheme.
#[derive(Debug, Clone, Copy)]
pub struct CGWFO;

impl IBKEM for CGWFO {
    const IDENTIFIER: &'static str = "cgwfo";

    type Pk = PublicKey;
    type Sk = SecretKey;
    type Usk = UserSecretKey;
    type Ct = CipherText;
    type Id = Identity;

    const PK_BYTES: usize = PK_BYTES;
    const USK_BYTES: usize = USK_BYTES;
    const SK_BYTES: usize = SK_BYTES;
    const CT_BYTES: usize = CT_BYTES;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> (PublicKey, SecretKey) {
        CGW::setup(rng)
    }

    fn extract_usk<R: Rng + CryptoRng>(
        _pk: Option<&PublicKey>,
        sk: &SecretKey,
        id: &Identity,
        rng: &mut R,
    ) -> UserSecretKey {
        let usk = CGW::extract_usk(None, sk, id, rng);

        UserSecretKey { usk, id: *id }
    }

    fn encaps<R: Rng + CryptoRng>(
        pk: &PublicKey,
        id: &Identity,
        rng: &mut R,
    ) -> (CipherText, SharedSecret) {
        let m = Msg::random(rng);

        let mut pre_coins = [0u8; MSG_BYTES + ID_BYTES];
        pre_coins[..MSG_BYTES].copy_from_slice(&m.to_bytes());

        pre_coins[MSG_BYTES..].copy_from_slice(&id.0);
        let coins = sha3_512(&pre_coins);

        let ct = CGW::encrypt(pk, id, &m, &coins);

        (ct, SharedSecret::from(&m))
    }

    /// Decapsulate a shared secret from the ciphertext.
    ///
    /// # Panics
    ///
    /// This scheme **does** requires the master public key due to usage the Fujisaki-Okamoto transform.
    /// This function panics if no master public key is provided.
    ///
    /// # Errors
    ///
    /// This function returns an [`Error`] when an illegitimate ciphertext is encountered (explicit rejection).
    fn decaps(
        opk: Option<&PublicKey>,
        usk: &UserSecretKey,
        c: &CipherText,
    ) -> Result<SharedSecret, Error> {
        let pk = opk.unwrap();

        let m = CGW::decrypt(&usk.usk, c);

        let mut pre_coins = [0u8; MSG_BYTES + ID_BYTES];
        pre_coins[..MSG_BYTES].copy_from_slice(&m.to_bytes());
        pre_coins[MSG_BYTES..].copy_from_slice(&usk.id.0);

        let coins = sha3_512(&pre_coins);

        let c2 = CGW::encrypt(pk, &usk.id, &m, &coins);

        // Can save some time by not doing a constant-time comparison
        // since we can leak whether the decapsulation succeeds/fails.
        if c.ct_eq(&c2).into() {
            Ok(SharedSecret::from(&m))
        } else {
            Err(Error)
        }
    }
}

#[cfg(feature = "mkem")]
impl crate::kem::mkem::MultiRecipient for CGWFO {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Derive;

    test_kem!(CGWFO);

    #[cfg(feature = "mkem")]
    test_multi_kem!(CGWFO);
}
