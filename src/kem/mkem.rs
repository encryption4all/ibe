//! This module contains a generic implementation shell around all three KEMs to use in a multi-recipient setting.
//! It leverages an IBKEM + DEM to construct a KEM to hybrid an identical, randomly drawn key under
//! different identities.
//!
//! # Example usage:
//!
//! In this example we encapsulate a session key for two recipients.
//!
//! ```
//! use ibe::kem::IBKEM;
//! use ibe::kem::mkem::{MultiRecipient, MultiRecipientCiphertext};
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
//! // Encapsulate a single session key for two recipients.
//! let (cts_iter, k) = CGWKV::multi_encaps(&pk, &derived, &mut rng);
//! let cts: Vec<MultiRecipientCiphertext<CGWKV>> = cts_iter.collect();
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

impl SharedSecret {
    /// Sample random shared secret.
    fn random<R: Rng + CryptoRng>(r: &mut R) -> Self {
        let mut ss_bytes = [0u8; SS_BYTES];
        r.fill_bytes(&mut ss_bytes);

        SharedSecret(ss_bytes)
    }
}

/// A multi-recipient ciphertext.
///
/// This is an extension of a scheme's ciphertext.
#[derive(Debug, Clone)]
pub struct MultiRecipientCiphertext<K: IBKEM> {
    ct_asymm: K::Ct,
    ct_symm: [u8; SS_BYTES],
    tag: Tag<Aes128Gcm>,
    nonce: Nonce<Aes128Gcm>,
}

/// Iterator for multi-recipient ciphertexts.
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
    type Item = MultiRecipientCiphertext<K>;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.ids.next()?;

        let (ct_asymm, kek) = <K as IBKEM>::encaps(self.pk, id, self.rng);

        let aead = Aes128Gcm::new_from_slice(&kek.0[..16]).unwrap();
        let nonce_bytes = self.rng.gen::<[u8; 12]>();
        let nonce = Nonce::<Aes128Gcm>::from_slice(&nonce_bytes);

        let mut shared_key = self.ss.0;
        let tag = aead
            .encrypt_in_place_detached(nonce, b"", &mut shared_key)
            .unwrap();

        Some(MultiRecipientCiphertext::<K> {
            ct_asymm,
            ct_symm: shared_key,
            nonce: *nonce,
            tag,
        })
    }
}

/// Trait that captures multi-recipient encapsulation/decapsulation.
pub trait MultiRecipient: IBKEM {
    /// Encapsulates a single shared secret for a multiple of counterparties.
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

    /// Decapsulates the single shared secret from a [`MultiRecipientCiphertext`].
    ///
    /// # Notes
    ///
    /// In some cases this function requires the master public key, depending on
    /// the underlying IBKEM scheme used (e.g., CGWFO).
    fn multi_decaps(
        mpk: Option<&Self::Pk>,
        usk: &Self::Usk,
        ct: &MultiRecipientCiphertext<Self>,
    ) -> Result<SharedSecret, Error> {
        let kek = <Self as IBKEM>::decaps(mpk, usk, &ct.ct_asymm)?;

        let aead = Aes128Gcm::new_from_slice(&kek.0[..16]).unwrap();

        let mut shared_key_encrypted = ct.ct_symm;
        aead.decrypt_in_place_detached(&ct.nonce, b"", &mut shared_key_encrypted, &ct.tag)
            .unwrap();

        Ok(SharedSecret(shared_key_encrypted))
    }
}

//macro_rules! impl_mkemct_compress {
//    ($scheme: ident) => {
//        impl Compress for MultiRecipientCiphertext<$scheme> {
//            const OUTPUT_SIZE: usize = $scheme::CT_BYTES + SS_BYTES;
//            type Output = [u8; $scheme::CT_BYTES + SS_BYTES];
//
//            fn to_bytes(&self) -> Self::Output {
//                let mut res = [0u8; Self::OUTPUT_SIZE];
//                res[..$scheme::CT_BYTES].copy_from_slice(&self.ct_i.to_bytes());
//                res[$scheme::CT_BYTES..].copy_from_slice(&self.ss_i.0);
//
//                res
//            }
//
//            fn from_bytes(output: &Self::Output) -> CtOption<Self> {
//                let ct_i = <$scheme as IBKEM>::Ct::from_bytes(
//                    &output[..$scheme::CT_BYTES].try_into().unwrap(),
//                );
//                let mut ss_bytes = [0u8; SS_BYTES];
//                ss_bytes[..].copy_from_slice(&output[$scheme::CT_BYTES..]);
//                let ss_i = SharedSecret(ss_bytes);
//
//                ct_i.map(|ct_i| MultiRecipientCiphertext { ct_i, ss_i })
//            }
//        }
//    };
//}
//
//#[cfg(feature = "cgwkv")]
//impl_mkemct_compress!(CGWKV);
//
//#[cfg(feature = "cgwfo")]
//impl_mkemct_compress!(CGWFO);
//
//#[cfg(feature = "kv1")]
//impl_mkemct_compress!(KV1);
