//! IND-ID-CCA2 secure IBKEM by a scheme by Chen, Gay and Wee.
//! * From: "[Improved Dual System ABE in Prime-Order Groups via Predicate Encodings](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!
//! CCA security due to a general approach by Fujisaki and Okamoto.
//! * From: "[A Modular Analysis of the Fujisaki-Okamoto Transformation](https://eprint.iacr.org/2017/604.pdf)"
//!
//! Symmetric primitives G and H instantiated using sha3_512 and sha3_256, respectively.
//! To output a bigger secret SHAKE256 can be used with a bigger output buffer.
//!
//! A drawback of a Fujisaki-Okamoto transform is that we now need the public key to decapsulate :(

use crate::kem::{DecapsulationError, SharedSecret, IBKEM};
use crate::pke::cgw::{CipherText, Message, CGW, N_BYTE_LEN, USK_BYTES as CPA_USK_BYTES};
use crate::pke::IBE;
use crate::util::sha3_512;
use crate::Compressable;
use arrayref::{array_refs, mut_array_refs};
use group::Group;
use rand::{CryptoRng, Rng};
use subtle::{ConstantTimeEq, CtOption};

/// These struct are identical for the CCA KEM
pub use crate::pke::cgw::{Identity, PublicKey, SecretKey, CT_BYTES, PK_BYTES, SK_BYTES};

/// The USK includes a random message and the identity (needed for re-encryption)
pub const USK_BYTES: usize = CPA_USK_BYTES + N_BYTE_LEN;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UserSecretKey {
    usk: crate::pke::cgw::UserSecretKey,
    id: Identity,
}

impl Compressable for UserSecretKey {
    const OUTPUT_SIZE: usize = USK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut buf = [0u8; USK_BYTES];
        let (usk, id) = mut_array_refs![&mut buf, CPA_USK_BYTES, N_BYTE_LEN];

        *usk = self.usk.to_bytes();
        id.copy_from_slice(&self.id.0);

        buf
    }

    fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let (usk, rid) = array_refs![&bytes, CPA_USK_BYTES, N_BYTE_LEN];

        let usk = crate::pke::cgw::UserSecretKey::from_bytes(usk);
        let id = Identity(*rid);

        usk.map(|usk| UserSecretKey { usk, id: id })
    }
}

pub struct CGWFO;

impl IBKEM for CGWFO {
    type Pk = PublicKey;
    type Sk = SecretKey;
    type Usk = UserSecretKey;
    type Ct = CipherText;
    type Ss = SharedSecret;
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

        UserSecretKey {
            usk,
            id: id.clone(),
        }
    }

    fn multi_encaps<R: Rng + CryptoRng, const N: usize>(
        pk: &Self::Pk,
        ids: &[&Self::Id; N],
        rng: &mut R,
    ) -> ([Self::Ct; N], Self::Ss) {
        let mut cts = [CipherText::default(); N];
        let m = Message::random(rng);

        let coins = sha3_512(&m.to_bytes());

        for (i, id) in ids.iter().enumerate() {
            let c = CGW::encrypt(pk, id, &m, &coins);
            cts[i] = c;
        }

        (cts, SharedSecret::from(&m))
    }

    /// Decapsulate a shared secret from the ciphertext.
    ///
    /// This scheme **does** requires the master public key due to usage the Fujisaki-Okamoto transform.
    /// This function panics if no master public key is provided.
    ///
    /// This function returns a [`DecapsulationError`] when an
    /// illegitimate ciphertext is encountered (explicit rejection).
    fn decaps(
        opk: Option<&PublicKey>,
        usk: &UserSecretKey,
        c: &CipherText,
    ) -> Result<SharedSecret, DecapsulationError> {
        let pk = opk.unwrap();

        let m = CGW::decrypt(&usk.usk, c);
        let coins = sha3_512(&m.to_bytes());

        let c2 = CGW::encrypt(pk, &usk.id, &m, &coins);

        if c.ct_eq(&c2).into() {
            Ok(SharedSecret::from(&m))
        } else {
            Err(DecapsulationError)
        }
    }
}

#[cfg(test)]
mod tests {
    test_kem!(CGWFO);
}
