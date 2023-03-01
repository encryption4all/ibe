//! This module contains a generic API around three KEMs to use in a multi-user setting.
//! It leverages the underlying IBKEM and a DEM to construct a hybrid encryption scheme, which
//! is used to encrypt a randomly drawn [`SharedSecret`].
//!
//! # Example usage:
//!
//! In this example we encapsulate a session key for two users.
//!
//! ```
//! use ibe::kem::IBKEM;
//! use ibe::kem::mkem::{MultiRecipient, Ciphertext};
//! use ibe::kem::cgw_kv::CGWKV;
//! use ibe::Derive;
//!
//! let mut rng = rand::thread_rng();
//!
//! let ids = ["email:w.geraedts@sarif.nl", "email:l.botros@cs.ru.nl"];
//! let derived: Vec<<CGWKV as IBKEM>::Id> = ids.iter().map(|id| <CGWKV as IBKEM>::Id::derive_str(id)).collect();
//!
//! // Create a master key pair.
//! let (pk, sk) = CGWKV::setup(&mut rng);
//!
//! // Generate USKs for both identities.
//! let usk1 = CGWKV::extract_usk(None, &sk, &derived[0], &mut rng);
//! let usk2 = CGWKV::extract_usk(None, &sk, &derived[1], &mut rng);
//!
//! // Encapsulate a single session key for two users.
//! let (cts_iter, k) = CGWKV::multi_encaps(&pk, &derived, &mut rng);
//! let cts: Vec<Ciphertext<CGWKV>> = cts_iter.collect();
//!
//! let k1 = CGWKV::multi_decaps(Some(&pk), &usk1, &cts[0]).unwrap();
//! let k2 = CGWKV::multi_decaps(Some(&pk), &usk2, &cts[1]).unwrap();
//!
//! assert_eq!(k, k1);
//! assert_eq!(k, k2);
//! ```

use crate::kem::{Compress, Error, SharedSecret, IBKEM, SS_BYTES};
use core::slice::Iter;
use rand::{CryptoRng, Rng};
use subtle::CtOption;

use aes_gcm::aead::{Nonce, Tag};
use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};

#[cfg(feature = "cgwfo")]
use crate::kem::cgw_fo::CGWFO;

#[cfg(feature = "cgwkv")]
use crate::kem::cgw_kv::CGWKV;

#[cfg(feature = "kv1")]
use crate::kem::kiltz_vahlis_one::KV1;

const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 16;

impl SharedSecret {
    /// Sample random shared secret.
    fn random<R: Rng + CryptoRng>(r: &mut R) -> Self {
        let mut ss_bytes = [0u8; SS_BYTES];
        r.fill_bytes(&mut ss_bytes);

        SharedSecret(ss_bytes)
    }
}

/// A multi-recipient ciphertext.
#[derive(Debug, Clone)]
pub struct Ciphertext<K: IBKEM> {
    ct_asymm: K::Ct,
    ct_symm: [u8; SS_BYTES],
    tag: Tag<Aes128Gcm>,
    nonce: Nonce<Aes128Gcm>,
}

/// Iterator that produces multi-recipient ciphertexts.
#[derive(Debug)]
pub struct Ciphertexts<'a, K: IBKEM, R> {
    ss: SharedSecret,
    pk: &'a K::Pk,
    ids: Iter<'a, K::Id>,
    rng: &'a mut R,
}

impl<'a, K, R> Iterator for Ciphertexts<'a, K, R>
where
    K: IBKEM,
    R: Rng + CryptoRng,
{
    type Item = Ciphertext<K>;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;

        let (ct_asymm, kek) = <K as IBKEM>::encaps(self.pk, id, self.rng);

        let aead = Aes128Gcm::new_from_slice(&kek.0[..KEY_SIZE]).unwrap();
        let nonce_bytes = self.rng.gen::<[u8; NONCE_SIZE]>();
        let nonce = Nonce::<Aes128Gcm>::from_slice(&nonce_bytes);

        let mut shared_key = self.ss.0;

        let tag = aead
            .encrypt_in_place_detached(nonce, b"", &mut shared_key)
            .unwrap();

        Some(Ciphertext::<K> {
            ct_asymm,
            ct_symm: shared_key,
            nonce: *nonce,
            tag,
        })
    }
}

/// Trait that captures multi-recipient encapsulation/decapsulation.
pub trait MultiRecipient: IBKEM {
    /// Encapsulates a single shared secret under multiple identities.
    fn multi_encaps<'a, R: Rng + CryptoRng>(
        pk: &'a <Self as IBKEM>::Pk,
        ids: impl IntoIterator<IntoIter = Iter<'a, Self::Id>>,
        rng: &'a mut R,
    ) -> (Ciphertexts<'a, Self, R>, SharedSecret) {
        let ss = SharedSecret::random(rng);

        let cts = Ciphertexts {
            ss,
            pk,
            rng,
            ids: ids.into_iter(),
        };

        (cts, ss)
    }

    /// Decapsulates the single shared secret from a [`Ciphertext`].
    ///
    /// # Notes
    ///
    /// In some cases this function requires the master public key, depending on the underlying
    /// IBKEM scheme used (e.g., CGWFO).
    fn multi_decaps(
        mpk: Option<&Self::Pk>,
        usk: &Self::Usk,
        ct: &Ciphertext<Self>,
    ) -> Result<SharedSecret, Error> {
        let kek = <Self as IBKEM>::decaps(mpk, usk, &ct.ct_asymm)?;
        let aead = Aes128Gcm::new_from_slice(&kek.0[..KEY_SIZE]).unwrap();
        let mut shared_key = ct.ct_symm;
        aead.decrypt_in_place_detached(&ct.nonce, b"", &mut shared_key, &ct.tag)
            .map_err(|_e| Error)?;

        Ok(SharedSecret(shared_key))
    }
}

macro_rules! impl_mkemct_compress {
    ($scheme: ident) => {
        impl Compress for Ciphertext<$scheme> {
            const OUTPUT_SIZE: usize = $scheme::CT_BYTES + SS_BYTES + TAG_SIZE + NONCE_SIZE;
            type Output = [u8; Self::OUTPUT_SIZE];

            fn to_bytes(&self) -> Self::Output {
                use arrayref::mut_array_refs;

                let mut res = [0u8; Self::OUTPUT_SIZE];
                let (ct_asymm, ct_symm, tag, nonce) =
                    mut_array_refs![&mut res, $scheme::CT_BYTES, SS_BYTES, TAG_SIZE, NONCE_SIZE];

                *ct_asymm = self.ct_asymm.to_bytes();
                *ct_symm = self.ct_symm;
                *tag = self.tag.into();
                *nonce = self.nonce.into();

                res
            }

            fn from_bytes(output: &Self::Output) -> CtOption<Self> {
                use arrayref::array_refs;

                let (ct_asymm, ct_symm, tag, nonce) =
                    array_refs![&output, $scheme::CT_BYTES, SS_BYTES, TAG_SIZE, NONCE_SIZE];

                let ct_asymm = <$scheme as IBKEM>::Ct::from_bytes(ct_asymm);
                let tag = Tag::<Aes128Gcm>::from_slice(tag);
                let nonce = Nonce::<Aes128Gcm>::from_slice(nonce);

                ct_asymm.map(|ct_asymm| Ciphertext {
                    ct_asymm,
                    ct_symm: *ct_symm,
                    tag: *tag,
                    nonce: *nonce,
                })
            }
        }
    };
}

#[cfg(feature = "cgwkv")]
impl_mkemct_compress!(CGWKV);

#[cfg(feature = "cgwfo")]
impl_mkemct_compress!(CGWFO);

#[cfg(feature = "kv1")]
impl_mkemct_compress!(KV1);
