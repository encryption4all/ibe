//! IND-ID-CCA2 secure IBKEM Chen, Gay and Wee.
//!  * From: "[Improved Dual System ABE in Prime-Order Groups via Predicate Encodings](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!
//! CCA security due to a generalized approach from Kiltz & Vahlis.
//!  * From: "[CCA2 Secure IBE: Standard Model Efficiency through Authenticated Symmetric Encryption](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!  * Published in: CT-RSA, 2008

extern crate alloc;
use alloc::vec::Vec;

use crate::kem::{Error, SharedSecret, IBKEM};
use crate::util::*;
use crate::Compress;
use core::convert::TryInto;
use group::{WnafBase, WnafScalar};
use irmaseal_curve::{
    multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
    Scalar,
};
use rand::{CryptoRng, Rng};
use subtle::{Choice, ConditionallySelectable, CtOption};

/// Size of the compressed master public key in bytes.
pub const PK_BYTES: usize = 8 * G1_BYTES + GT_BYTES;

/// Size of the compressed master secret key in bytes.
pub const SK_BYTES: usize = 16 * SCALAR_BYTES;

/// Size of the compressed user secret key in bytes.
pub const USK_BYTES: usize = 6 * G2_BYTES;

/// Size of the compressed ciphertext key in bytes.
pub const CT_BYTES: usize = 4 * G1_BYTES + 32;

const WINDOW_SIZE: usize = 4;

/// Public key parameters generated by the PKG used to encaps messages.
/// Also known as MPK.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PublicKey {
    a_1: [G1Affine; 2],
    w0ta_1: [G1Affine; 2],
    w1ta_1: [G1Affine; 2],
    wprime_1: [G1Affine; 2],
    kta_t: Gt,
}

/// Secret key parameter generated by the PKG used to extract user secret keys.
/// Also known as MSK.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SecretKey {
    b: [Scalar; 2],
    k: [Scalar; 2],
    w0: [[Scalar; 2]; 2],
    w1: [[Scalar; 2]; 2],
    wprime: [[Scalar; 2]; 2],
}

/// User secret key. Can be used to decaps the corresponding ciphertext.
/// Also known as USK_{id}.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UserSecretKey {
    d0: [G2Affine; 2],
    d1: [G2Affine; 2],
    d2: [G2Affine; 2],
}

/// Encrypted message. Can only be decapsed with a corresponding user secret key.
/// Also known as CT_{id}
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct CipherText {
    c0: [G1Affine; 2],
    c1: [G1Affine; 2],
    k: [u8; 32],
}

/// The CGW-KV1 identity-based key encapsulation scheme.
#[derive(Debug, Clone, Copy)]
pub struct CGWKV;

impl IBKEM for CGWKV {
    const IDENTIFIER: &'static str = "cgwkv";

    type Pk = PublicKey;
    type Sk = SecretKey;
    type Usk = UserSecretKey;
    type Ct = CipherText;
    type Id = Identity;

    const PK_BYTES: usize = PK_BYTES;
    const SK_BYTES: usize = SK_BYTES;
    const USK_BYTES: usize = USK_BYTES;
    const CT_BYTES: usize = CT_BYTES;

    /// Generate a keypair used by the Private Key Generator (PKG).
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> (PublicKey, SecretKey) {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        let a = [rand_scalar(rng), rand_scalar(rng)];
        let b = [rand_scalar(rng), rand_scalar(rng)];

        let w0 = [
            [rand_scalar(rng), rand_scalar(rng)],
            [rand_scalar(rng), rand_scalar(rng)],
        ];

        let w1 = [
            [rand_scalar(rng), rand_scalar(rng)],
            [rand_scalar(rng), rand_scalar(rng)],
        ];

        let wprime = [
            [rand_scalar(rng), rand_scalar(rng)],
            [rand_scalar(rng), rand_scalar(rng)],
        ];

        let k = [rand_scalar(rng), rand_scalar(rng)];

        let w0a = [
            w0[0][0] * a[0] + w0[1][0] * a[1],
            w0[0][1] * a[0] + w0[1][1] * a[1],
        ];
        let w1a = [
            w1[0][0] * a[0] + w1[1][0] * a[1],
            w1[0][1] * a[0] + w1[1][1] * a[1],
        ];
        let wprimea = [
            wprime[0][0] * a[0] + wprime[1][0] * a[1],
            wprime[0][1] * a[0] + wprime[1][1] * a[1],
        ];

        let scalars = [
            a[0], a[1], w0a[0], w0a[1], w1a[0], w1a[1], wprimea[0], wprimea[1],
        ];

        let base = WnafBase::<_, WINDOW_SIZE>::new(G1Projective::generator());
        let batch: Vec<G1Projective> = scalars
            .iter()
            .map(|scalar| &base * &WnafScalar::<_, WINDOW_SIZE>::new(scalar))
            .collect();

        let mut out = [G1Affine::default(); 8];
        G1Projective::batch_normalize(&batch, &mut out);

        let kta_t = pairing(&g1, &g2) * (k[0] * a[0] + k[1] * a[1]);

        (
            PublicKey {
                a_1: [out[0], out[1]],
                w0ta_1: [out[2], out[3]],
                w1ta_1: [out[4], out[5]],
                wprime_1: [out[6], out[7]],
                kta_t,
            },
            SecretKey {
                b,
                k,
                w0,
                w1,
                wprime,
            },
        )
    }

    /// Extract a user secret key for a given identity.
    fn extract_usk<R: Rng + CryptoRng>(
        _pk: Option<&PublicKey>,
        sk: &SecretKey,
        v: &Identity,
        rng: &mut R,
    ) -> UserSecretKey {
        let r = rand_scalar(rng);
        let id = v.to_scalar();

        let br = [sk.b[0] * r, sk.b[1] * r];

        let scalars = [
            br[0],
            br[1],
            (sk.k[0]
                - (br[0] * sk.w0[0][0]
                    + br[1] * sk.w0[0][1]
                    + id * (br[0] * sk.w1[0][0] + br[1] * sk.w1[0][1]))),
            (sk.k[1]
                - (br[0] * sk.w0[1][0]
                    + br[1] * sk.w0[1][1]
                    + id * (br[0] * sk.w1[1][0] + br[1] * sk.w1[1][1]))),
            -(br[0] * sk.wprime[0][0] + br[1] * sk.wprime[0][1]),
            -(br[0] * sk.wprime[1][0] + br[1] * sk.wprime[1][1]),
        ];

        let base = WnafBase::<_, WINDOW_SIZE>::new(G2Projective::generator());
        let batch: Vec<G2Projective> = scalars
            .iter()
            .map(|scalar| &base * &WnafScalar::<_, WINDOW_SIZE>::new(scalar))
            .collect();

        let mut out = [G2Affine::default(); 6];
        G2Projective::batch_normalize(&batch, &mut out);

        UserSecretKey {
            d0: [out[0], out[1]], // K_i
            d1: [out[2], out[3]], // K'_i,0
            d2: [out[4], out[5]], // K'_i,1
        }
    }

    fn encaps<R: Rng + CryptoRng>(
        pk: &PublicKey,
        id: &Identity,
        rng: &mut R,
    ) -> (CipherText, SharedSecret) {
        let s = rand_scalar(rng);
        let k = pk.kta_t * s;

        let x = id.to_scalar();
        let c0 = [(pk.a_1[0] * s).into(), (pk.a_1[1] * s).into()];

        let mut smallk = [0u8; 32];
        rng.fill_bytes(&mut smallk);

        let xprime = rpc(&smallk, &[c0[0], c0[1]]);

        // TODO: this leaves room for optimizations.
        let c1: [G1Affine; 2] = [
            ((pk.w0ta_1[0] * s) + (pk.w1ta_1[0] * (s * x)) + (pk.wprime_1[0] * (s * xprime)))
                .into(),
            ((pk.w0ta_1[1] * s) + (pk.w1ta_1[1] * (s * x)) + (pk.wprime_1[1] * (s * xprime)))
                .into(),
        ];

        (CipherText { c0, c1, k: smallk }, SharedSecret::from(&k))
    }

    /// Derive the same SharedSecret from the CipherText using a UserSecretKey.
    ///
    /// # Errors
    ///
    /// This operation always implicitly rejects ciphertexts and therefore never errors.
    fn decaps(
        _pk: Option<&PublicKey>,
        usk: &UserSecretKey,
        ct: &CipherText,
    ) -> Result<SharedSecret, Error> {
        let yprime = rpc(&ct.k, &[ct.c0[0], ct.c0[1]]);
        let tmp1: G2Affine = (usk.d1[0] + (usk.d2[0] * yprime)).into();
        let tmp2: G2Affine = (usk.d1[1] + (usk.d2[1] * yprime)).into();

        let m = multi_miller_loop(&[
            (&ct.c0[0], &G2Prepared::from(tmp1)),
            (&ct.c0[1], &G2Prepared::from(tmp2)),
            (&ct.c1[0], &G2Prepared::from(usk.d0[0])),
            (&ct.c1[1], &G2Prepared::from(usk.d0[1])),
        ])
        .final_exponentiation();

        Ok(SharedSecret::from(&m))
    }
}

impl Compress for PublicKey {
    const OUTPUT_SIZE: usize = PK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; PK_BYTES] {
        let mut res = [0u8; PK_BYTES];

        for i in 0..2 {
            let x = i * G1_BYTES;
            let y = x + G1_BYTES;
            res[x..y].copy_from_slice(&self.a_1[i].to_compressed());
            res[96 + x..96 + y].copy_from_slice(&self.w0ta_1[i].to_compressed());
            res[192 + x..192 + y].copy_from_slice(&self.w1ta_1[i].to_compressed());
            res[288 + x..288 + y].copy_from_slice(&self.wprime_1[i].to_compressed());
        }
        res[384..].copy_from_slice(&self.kta_t.to_compressed());

        res
    }

    fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        // from_compressed_unchecked doesn't check whether the element has
        // a cofactor. To mount an attack using a cofactor an attacker
        // must be able to manipulate the public parameters. But then the
        // attacker can simply use parameters they generated themselves.
        // Thus checking for a cofactor is superfluous.
        let mut a_1 = [G1Affine::default(); 2];
        let mut w0ta_1 = [G1Affine::default(); 2];
        let mut w1ta_1 = [G1Affine::default(); 2];
        let mut wprime_1 = [G1Affine::default(); 2];
        let mut kta_t = Gt::default();

        let mut is_some = Choice::from(1u8);
        for i in 0..2 {
            let x = i * G1_BYTES;
            let y = x + G1_BYTES;
            is_some &= G1Affine::from_compressed_unchecked(bytes[x..y].try_into().unwrap())
                .map(|el| a_1[i] = el)
                .is_some();
            is_some &=
                G1Affine::from_compressed_unchecked(bytes[96 + x..96 + y].try_into().unwrap())
                    .map(|el| w0ta_1[i] = el)
                    .is_some();
            is_some &=
                G1Affine::from_compressed_unchecked(bytes[192 + x..192 + y].try_into().unwrap())
                    .map(|el| w1ta_1[i] = el)
                    .is_some();
            is_some &=
                G1Affine::from_compressed_unchecked(bytes[288 + x..288 + y].try_into().unwrap())
                    .map(|el| wprime_1[i] = el)
                    .is_some();
        }
        is_some &= Gt::from_compressed_unchecked(bytes[384..672].try_into().unwrap())
            .map(|el| kta_t = el)
            .is_some();

        CtOption::new(
            PublicKey {
                a_1,
                w0ta_1,
                w1ta_1,
                wprime_1,
                kta_t,
            },
            is_some,
        )
    }
}

impl Compress for SecretKey {
    const OUTPUT_SIZE: usize = SK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; SK_BYTES] {
        let mut res = [0u8; SK_BYTES];
        let (mut x, mut y);

        for i in 0..2 {
            x = i * SCALAR_BYTES;
            y = x + SCALAR_BYTES;
            res[x..y].copy_from_slice(&self.b[i].to_bytes());
            res[64 + x..64 + y].copy_from_slice(&self.k[i].to_bytes());

            for j in 0..2 {
                x = (i * 2 + j) * SCALAR_BYTES;
                y = x + SCALAR_BYTES;
                res[128 + x..128 + y].copy_from_slice(&self.w0[i][j].to_bytes());
                res[256 + x..256 + y].copy_from_slice(&self.w1[i][j].to_bytes());
                res[384 + x..384 + y].copy_from_slice(&self.wprime[i][j].to_bytes());
            }
        }

        res
    }

    fn from_bytes(bytes: &[u8; SK_BYTES]) -> CtOption<Self> {
        let mut b = [Scalar::default(); 2];
        let mut k = [Scalar::default(); 2];
        let mut w0 = [[Scalar::default(); 2]; 2];
        let mut w1 = [[Scalar::default(); 2]; 2];
        let mut wprime = [[Scalar::default(); 2]; 2];

        let mut is_some = Choice::from(1u8);
        for i in 0..2 {
            let x = i * SCALAR_BYTES;
            let y = x + SCALAR_BYTES;
            is_some &= Scalar::from_bytes(&bytes[x..y].try_into().unwrap())
                .map(|s| b[i] = s)
                .is_some();
            is_some &= Scalar::from_bytes(&bytes[64 + x..64 + y].try_into().unwrap())
                .map(|s| k[i] = s)
                .is_some();
            for j in 0..2 {
                let x = (i * 2 + j) * SCALAR_BYTES;
                let y = x + SCALAR_BYTES;
                is_some &= Scalar::from_bytes(&bytes[128 + x..128 + y].try_into().unwrap())
                    .map(|s| w0[i][j] = s)
                    .is_some();
                is_some &= Scalar::from_bytes(&bytes[256 + x..256 + y].try_into().unwrap())
                    .map(|s| w1[i][j] = s)
                    .is_some();
                is_some &= Scalar::from_bytes(&bytes[384 + x..384 + y].try_into().unwrap())
                    .map(|s| wprime[i][j] = s)
                    .is_some();
            }
        }

        CtOption::new(
            SecretKey {
                b,
                k,
                w0,
                w1,
                wprime,
            },
            is_some,
        )
    }
}

impl Compress for UserSecretKey {
    const OUTPUT_SIZE: usize = USK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut res = [0u8; USK_BYTES];

        for i in 0..2 {
            let x = i * G2_BYTES;
            let y = x + G2_BYTES;
            res[x..y].copy_from_slice(&self.d0[i].to_compressed());
            res[192 + x..192 + y].copy_from_slice(&self.d1[i].to_compressed());
            res[384 + x..384 + y].copy_from_slice(&self.d2[i].to_compressed());
        }

        res
    }

    fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let mut d0 = [G2Affine::default(); 2];
        let mut d1 = [G2Affine::default(); 2];
        let mut d2 = [G2Affine::default(); 2];

        let mut is_some = Choice::from(1u8);
        for i in 0..2 {
            let x = i * G2_BYTES;
            let y = x + G2_BYTES;
            is_some &= G2Affine::from_compressed(&bytes[x..y].try_into().unwrap())
                .map(|el| d0[i] = el)
                .is_some();
            is_some &= G2Affine::from_compressed(&bytes[192 + x..192 + y].try_into().unwrap())
                .map(|el| d1[i] = el)
                .is_some();
            is_some &= G2Affine::from_compressed(&bytes[384 + x..384 + y].try_into().unwrap())
                .map(|el| d2[i] = el)
                .is_some();
        }

        CtOption::new(UserSecretKey { d0, d1, d2 }, is_some)
    }
}

impl Compress for CipherText {
    const OUTPUT_SIZE: usize = CT_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; CT_BYTES] {
        let mut res = [0u8; CT_BYTES];

        for i in 0..2 {
            let x = i * G1_BYTES;
            let y = x + G1_BYTES;
            res[x..y].copy_from_slice(&self.c0[i].to_compressed());
            res[96 + x..96 + y].copy_from_slice(&self.c1[i].to_compressed());
        }

        res[192..].copy_from_slice(&self.k);

        res
    }

    fn from_bytes(bytes: &[u8; CT_BYTES]) -> CtOption<Self> {
        let mut c0 = [G1Affine::default(); 2];
        let mut c1 = [G1Affine::default(); 2];
        let mut k = [0u8; 32];

        let mut is_some = Choice::from(1u8);
        for i in 0..2 {
            let x = i * G1_BYTES;
            let y = x + G1_BYTES;
            is_some &= G1Affine::from_compressed(&bytes[x..y].try_into().unwrap())
                .map(|el| c0[i] = el)
                .is_some();
            is_some &= G1Affine::from_compressed(&bytes[96 + x..96 + y].try_into().unwrap())
                .map(|el| c1[i] = el)
                .is_some();
        }

        k.copy_from_slice(&bytes[192..]);

        CtOption::new(CipherText { c0, c1, k }, is_some)
    }
}

impl ConditionallySelectable for CipherText {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut k = [0u8; 32];
        for (i, k) in k.iter_mut().enumerate() {
            *k = u8::conditional_select(&a.k[i], &b.k[i], choice);
        }

        CipherText {
            c0: [
                G1Affine::conditional_select(&a.c0[0], &b.c0[0], choice),
                G1Affine::conditional_select(&a.c0[1], &b.c0[1], choice),
            ],
            c1: [
                G1Affine::conditional_select(&a.c1[0], &b.c1[0], choice),
                G1Affine::conditional_select(&a.c1[1], &b.c1[1], choice),
            ],
            k,
        }
    }
}

#[cfg(feature = "mkem")]
impl crate::kem::mkem::MultiRecipient for CGWKV {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Derive;

    test_kem!(CGWKV);

    #[cfg(feature = "mkem")]
    test_multi_kem!(CGWKV);
}
