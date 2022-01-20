//! This module contains a generic implementation shell around all three KEMs to use in a multi-recipient setting.

use crate::kem::{Compress, Error, SharedSecret, IBKEM, SS_BYTES};
use alloc::vec::Vec;
use core::convert::TryInto;
use rand::{CryptoRng, Rng};
use subtle::CtOption;

#[cfg(feature = "cgwfo")]
use crate::kem::cgw_fo::CGWFO;

#[cfg(feature = "cgwkv")]
use crate::kem::cgw_kv::CGWKV;

#[cfg(feature = "kv1")]
use crate::kem::kiltz_vahlis_one::KV1;

#[derive(Clone, Copy)]
pub struct MultiRecipientCiphertext<K: IBKEM> {
    ct_i: K::Ct,
    ss_i: SharedSecret,
}

pub trait MultiRecipient<K: IBKEM> {
    fn multi_encaps<R: Rng + CryptoRng>(
        pk: &<K as IBKEM>::Pk,
        ids: &[&<K as IBKEM>::Id],
        rng: &mut R,
    ) -> (Vec<MultiRecipientCiphertext<K>>, SharedSecret) {
        let mut ss_bytes = [0u8; SS_BYTES];
        rng.fill_bytes(&mut ss_bytes);
        let ss = SharedSecret(ss_bytes);

        let cts = ids
            .iter()
            .map(|id| {
                let (ct_i, mut ss_i) = <K as IBKEM>::encaps(pk, id, rng);
                ss_i ^= ss;

                MultiRecipientCiphertext::<K> { ct_i, ss_i }
            })
            .collect();

        (cts, ss)
    }

    fn multi_decaps(
        mpk: Option<&K::Pk>,
        usk: &K::Usk,
        ct: &MultiRecipientCiphertext<K>,
    ) -> Result<SharedSecret, Error> {
        let mut ss = <K as IBKEM>::decaps(mpk, usk, &ct.ct_i)?;
        ss ^= ct.ss_i;

        Ok(ss)
    }
}

macro_rules! impl_mrct_compress {
    ($scheme: ident) => {
        impl Compress for MultiRecipientCiphertext<$scheme> {
            const OUTPUT_SIZE: usize = $scheme::CT_BYTES + SS_BYTES;
            type Output = [u8; $scheme::CT_BYTES + SS_BYTES];

            fn to_bytes(&self) -> Self::Output {
                let mut res = [0u8; Self::OUTPUT_SIZE];
                res[..$scheme::CT_BYTES].copy_from_slice(&self.ct_i.to_bytes());
                res[$scheme::CT_BYTES..].copy_from_slice(&self.ss_i.0);

                res
            }

            fn from_bytes(output: &Self::Output) -> CtOption<Self> {
                let ct_i = <$scheme as IBKEM>::Ct::from_bytes(
                    &output[..$scheme::CT_BYTES].try_into().unwrap(),
                );
                let mut ss_bytes = [0u8; SS_BYTES];
                ss_bytes[..].copy_from_slice(&output[$scheme::CT_BYTES..]);
                let ss_i = SharedSecret(ss_bytes);

                ct_i.map(|ct_i| MultiRecipientCiphertext { ct_i, ss_i })
            }
        }
    };
}

#[cfg(feature = "cgwkv")]
impl_mrct_compress!(CGWKV);

#[cfg(feature = "cgwfo")]
impl_mrct_compress!(CGWFO);

#[cfg(feature = "kv1")]
impl_mrct_compress!(KV1);
