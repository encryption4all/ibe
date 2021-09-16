//! IND-ID-CPA secure IBE by Chen, Gay and Wee.
//!
//! This file contains the passively secure public-key encryption algorithm (PKE).
//! All structs' byte serialization use compression.

use crate::util::*;
use arrayref::{array_refs, mut_array_refs};
use core::convert::TryInto;
use irmaseal_curve::{
    multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
    Scalar,
};
use rand::Rng;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

// Max identity buf size
const K: usize = 256;
const N: usize = 2 * K;
pub(crate) const N_BYTE_LEN: usize = N / 8;

// Sizes of elements in particular groups (compressed)
const GT_BYTES: usize = 288;
const G1_BYTES: usize = 48;
const G2_BYTES: usize = 96;
const SCALAR_BYTES: usize = 32;

// Derived sizes of compressed
pub(crate) const MSG_BYTES: usize = GT_BYTES;
pub(crate) const CT_BYTES: usize = 4 * G1_BYTES + GT_BYTES;
pub(crate) const PK_BYTES: usize = 6 * G1_BYTES + GT_BYTES;
pub(crate) const SK_BYTES: usize = 12 * SCALAR_BYTES;
pub(crate) const USK_BYTES: usize = 4 * G2_BYTES;

/// Public key parameters generated by the PKG used to encrypt messages.
/// Also known as MPK.
#[derive(Clone, Copy, PartialEq)]
pub struct PublicKey {
    a_1: [G1Affine; 2],
    w0ta_1: [G1Affine; 2],
    w1ta_1: [G1Affine; 2],
    kta_t: Gt,
}

/// Secret key parameter generated by the PKG used to extract user secret keys.
/// Also known as MSK.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SecretKey {
    b: [Scalar; 2],
    k: [Scalar; 2],
    w0: [[Scalar; 2]; 2],
    w1: [[Scalar; 2]; 2],
}

/// User secret key. Can be used to decrypt the corresponding ciphertext.
/// Also known as USK_{id}.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct UserSecretKey {
    d0: [G2Affine; 2],
    d1: [G2Affine; 2],
}

/// Encrypted message. Can only be decrypted with a corresponding user secret key.
/// Also known as CT_{id}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CipherText {
    c0: [G1Affine; 2],
    c1: [G1Affine; 2],
    cprime: Gt,
}

/// Hashed byte representation of an identity.
#[derive(Debug, PartialEq)]
pub struct Identity(pub [u8; N_BYTE_LEN]);

/// A message that can be encrypted using the PKE.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Message(Gt);

/// Generate a keypair used by the Private Key Generator (PKG).
pub fn setup<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
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

    let k = [rand_scalar(rng), rand_scalar(rng)];

    let w0ta = [
        w0[0][0] * a[0] + w0[1][0] * a[1],
        w0[0][1] * a[0] + w0[1][1] * a[1],
    ];
    let w1ta = [
        w1[0][0] * a[0] + w1[1][0] * a[1],
        w1[0][1] * a[0] + w1[1][1] * a[1],
    ];

    let batch = [
        g1 * a[0],
        g1 * a[1],
        g1 * w0ta[0],
        g1 * w0ta[1],
        g1 * w1ta[0],
        g1 * w1ta[1],
    ];

    let mut out = [G1Affine::default(); 6];
    G1Projective::batch_normalize(&batch, &mut out);
    let kta_t = pairing(&g1, &g2) * (k[0] * a[0] + k[1] * a[1]);

    (
        PublicKey {
            a_1: [out[0], out[1]],
            w0ta_1: [out[2], out[3]],
            w1ta_1: [out[4], out[5]],
            kta_t,
        },
        SecretKey { b, k, w0, w1 },
    )
}

/// Extract a user secret key for a given identity.
pub fn extract_usk<R: Rng>(sk: &SecretKey, v: &Identity, rng: &mut R) -> UserSecretKey {
    let g2 = G2Affine::generator();
    let r = rand_scalar(rng);
    let id = v.to_scalar();

    let br = [sk.b[0] * r, sk.b[1] * r];

    let batch = [
        g2 * br[0],
        g2 * br[1],
        g2 * -(sk.k[0]
            + (br[0] * sk.w0[0][0]
                + br[1] * sk.w0[0][1]
                + id * (br[0] * sk.w1[0][0] + br[1] * sk.w1[0][1]))),
        g2 * -(sk.k[1]
            + (br[0] * sk.w0[1][0]
                + br[1] * sk.w0[1][1]
                + id * (br[0] * sk.w1[1][0] + br[1] * sk.w1[1][1]))),
    ];
    let mut out = [G2Affine::default(); 4];
    G2Projective::batch_normalize(&batch, &mut out);

    UserSecretKey {
        d0: [out[0], out[1]],
        d1: [out[2], out[3]],
    }
}

/// Encrypt a message using the PKG public key and an identity.
pub fn encrypt(pk: &PublicKey, v: &Identity, message: &Message, rng: &[u8; 64]) -> CipherText {
    let s = Scalar::from_bytes_wide(rng);
    let id = v.to_scalar();

    let batch = [
        pk.a_1[0] * s,
        pk.a_1[1] * s,
        (pk.w0ta_1[0] * s) + (pk.w1ta_1[0] * (s * id)),
        (pk.w0ta_1[1] * s) + (pk.w1ta_1[1] * (s * id)),
    ];

    let mut out = [G1Affine::default(); 4];
    G1Projective::batch_normalize(&batch, &mut out);

    let cprime = pk.kta_t * s + message.0;

    CipherText {
        c0: [out[0], out[1]],
        c1: [out[2], out[3]],
        cprime,
    }
}

/// Derive the same message from the CipherText using a UserSecretKey.
pub fn decrypt(usk: &UserSecretKey, ct: &CipherText) -> Message {
    let m = ct.cprime
        + multi_miller_loop(&[
            (&ct.c0[0], &G2Prepared::from(usk.d1[0])),
            (&ct.c0[1], &G2Prepared::from(usk.d1[1])),
            (&ct.c1[0], &G2Prepared::from(usk.d0[0])),
            (&ct.c1[1], &G2Prepared::from(usk.d0[1])),
        ])
        .final_exponentiation();

    Message(m)
}

impl Identity {
    /// Hash a byte slice to a set of Identity parameters, which acts as a user public key.
    /// Uses sha3-512 internally.
    pub fn derive(b: &[u8]) -> Identity {
        Identity(sha3_512(b))
    }

    /// Hash a string slice to a set of Identity parameters.
    /// Directly converts characters to UTF-8 byte representation.
    pub fn derive_str(s: &str) -> Identity {
        Self::derive(s.as_bytes())
    }

    fn to_scalar(&self) -> Scalar {
        Scalar::from_bytes_wide(&self.0)
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        let mut res = [u8::default(); N_BYTE_LEN];
        for (src, dst) in self.0.iter().zip(res.as_mut().iter_mut()) {
            *dst = *src;
        }
        Identity(res)
    }
}

impl Copy for Identity {}

impl Message {
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        Self(rand_gt(rng))
    }

    pub fn to_bytes(&self) -> [u8; GT_BYTES] {
        self.0.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; GT_BYTES]) -> CtOption<Self> {
        Gt::from_compressed(bytes).map(Self)
    }
}

impl Default for Message {
    fn default() -> Self {
        Message(Gt::default())
    }
}

impl ConstantTimeEq for Message {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Message {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Message(Gt::conditional_select(&a.0, &b.0, choice))
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; PK_BYTES] {
        let mut res = [0u8; PK_BYTES];

        for i in 0..2 {
            let x = i * G1_BYTES;
            let y = x + G1_BYTES;
            res[x..y].copy_from_slice(&self.a_1[i].to_compressed());
            res[96 + x..96 + y].copy_from_slice(&self.w0ta_1[i].to_compressed());
            res[192 + x..192 + y].copy_from_slice(&self.w1ta_1[i].to_compressed());
        }
        res[288..].copy_from_slice(&self.kta_t.to_compressed());

        res
    }

    pub fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        // from_compressed_unchecked doesn't check whether the element has
        // a cofactor. To mount an attack using a cofactor an attacker
        // must be able to manipulate the public parameters. But then the
        // attacker can simply use parameters they generated themselves.
        // Thus checking for a cofactor is superfluous.
        let mut a_1 = [G1Affine::default(); 2];
        let mut w0ta_1 = [G1Affine::default(); 2];
        let mut w1ta_1 = [G1Affine::default(); 2];
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
        }
        is_some &= Gt::from_compressed_unchecked(bytes[288..].try_into().unwrap())
            .map(|el| kta_t = el)
            .is_some();

        CtOption::new(
            PublicKey {
                a_1,
                w0ta_1,
                w1ta_1,
                kta_t,
            },
            is_some,
        )
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; SK_BYTES] {
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
            }
        }

        res
    }

    pub fn from_bytes(bytes: &[u8; SK_BYTES]) -> CtOption<Self> {
        let mut b = [Scalar::default(); 2];
        let mut k = [Scalar::default(); 2];
        let mut w0 = [[Scalar::default(); 2]; 2];
        let mut w1 = [[Scalar::default(); 2]; 2];

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
            }
        }

        CtOption::new(SecretKey { b, k, w0, w1 }, is_some)
    }
}

impl UserSecretKey {
    pub fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut res = [0u8; USK_BYTES];
        let (d00, d01, d10, d11) =
            mut_array_refs![&mut res, G2_BYTES, G2_BYTES, G2_BYTES, G2_BYTES];

        *d00 = self.d0[0].to_compressed();
        *d01 = self.d0[1].to_compressed();
        *d10 = self.d1[0].to_compressed();
        *d11 = self.d1[1].to_compressed();

        res
    }

    pub fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let (d00, d01, d10, d11) = array_refs![bytes, G2_BYTES, G2_BYTES, G2_BYTES, G2_BYTES];

        let d00 = G2Affine::from_compressed(d00);
        let d01 = G2Affine::from_compressed(d01);
        let d10 = G2Affine::from_compressed(d10);
        let d11 = G2Affine::from_compressed(d11);

        d00.and_then(|d00| {
            d01.and_then(|d01| {
                d10.and_then(|d10| {
                    d11.map(|d11| UserSecretKey {
                        d0: [d00, d01],
                        d1: [d10, d11],
                    })
                })
            })
        })
    }
}

impl CipherText {
    pub fn to_bytes(&self) -> [u8; CT_BYTES] {
        let mut res = [0u8; CT_BYTES];
        let (c00, c01, c10, c11, cprime) =
            mut_array_refs![&mut res, G1_BYTES, G1_BYTES, G1_BYTES, G1_BYTES, GT_BYTES];

        *c00 = self.c0[0].to_compressed();
        *c01 = self.c0[1].to_compressed();
        *c10 = self.c1[0].to_compressed();
        *c11 = self.c1[1].to_compressed();
        *cprime = self.cprime.to_compressed();

        res
    }

    pub fn from_bytes(bytes: &[u8; CT_BYTES]) -> CtOption<Self> {
        let (c00, c01, c10, c11, cprime) =
            array_refs![bytes, G1_BYTES, G1_BYTES, G1_BYTES, G1_BYTES, GT_BYTES];

        let c00 = G1Affine::from_compressed(c00);
        let c01 = G1Affine::from_compressed(c01);
        let c10 = G1Affine::from_compressed(c10);
        let c11 = G1Affine::from_compressed(c11);
        let cprime = Gt::from_compressed(cprime);

        c00.and_then(|c00| {
            c01.and_then(|c01| {
                c10.and_then(|c10| {
                    c11.and_then(|c11| {
                        cprime.map(|cprime| CipherText {
                            c0: [c00, c01],
                            c1: [c10, c11],
                            cprime,
                        })
                    })
                })
            })
        })
    }
}

impl ConstantTimeEq for CipherText {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0[0].ct_eq(&other.c0[0])
            & self.c0[1].ct_eq(&other.c0[1])
            & self.c1[0].ct_eq(&other.c1[0])
            & self.c1[1].ct_eq(&other.c1[1])
            & self.cprime.ct_eq(&other.cprime)
    }
}

impl ConditionallySelectable for CipherText {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        CipherText {
            c0: [
                G1Affine::conditional_select(&a.c0[0], &b.c0[0], choice),
                G1Affine::conditional_select(&a.c0[1], &b.c0[1], choice),
            ],
            c1: [
                G1Affine::conditional_select(&a.c1[0], &b.c1[0], choice),
                G1Affine::conditional_select(&a.c1[1], &b.c1[1], choice),
            ],
            cprime: Gt::conditional_select(&a.cprime, &b.cprime, choice),
        }
    }
}

impl Default for UserSecretKey {
    fn default() -> Self {
        UserSecretKey {
            d0: [G2Affine::default(); 2],
            d1: [G2Affine::default(); 2],
        }
    }
}

impl ConditionallySelectable for UserSecretKey {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        UserSecretKey {
            d0: [
                G2Affine::conditional_select(&a.d0[0], &b.d0[0], choice),
                G2Affine::conditional_select(&a.d0[1], &b.d0[1], choice),
            ],
            d1: [
                G2Affine::conditional_select(&a.d1[0], &b.d1[0], choice),
                G2Affine::conditional_select(&a.d1[1], &b.d1[1], choice),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &'static [u8] = b"email:w.geraedts@sarif.nl";

    #[allow(dead_code)]
    struct DefaultSubResults {
        pk: PublicKey,
        sk: SecretKey,
        usk: UserSecretKey,
        c: CipherText,
        m: Message,
    }

    fn perform_default() -> DefaultSubResults {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let kid = Identity::derive(ID);

        let (pk, sk) = setup(&mut rng);
        let usk = extract_usk(&sk, &kid, &mut rng);

        let m = Message::random(&mut rng);

        let mut rand_bytes = [0u8; 64];
        rng.fill_bytes(&mut rand_bytes);

        let c = encrypt(&pk, &kid, &m, &rand_bytes);

        DefaultSubResults { pk, sk, usk, c, m }
    }

    #[test]
    fn eq_encrypt_decrypt() {
        let results = perform_default();
        let m2 = decrypt(&results.usk, &results.c);

        assert_eq!(results.m, m2);
    }
    #[test]
    fn eq_serialize_deserialize() {
        let result = perform_default();

        assert!(result.pk == PublicKey::from_bytes(&result.pk.to_bytes()).unwrap());
        assert_eq!(
            result.sk,
            SecretKey::from_bytes(&result.sk.to_bytes()).unwrap()
        );
        assert_eq!(
            result.usk,
            UserSecretKey::from_bytes(&result.usk.to_bytes()).unwrap()
        );
        assert_eq!(
            result.c,
            CipherText::from_bytes(&result.c.to_bytes()).unwrap()
        );
    }
}
