//! IND-ID-CCA2 secure IBKEM Chen, Gay and Wee.
//!  * From: "[Improved Dual System ABE in Prime-Order Groups via Predicate Encodings](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!
//! CCA security due to a generalized approach from Kiltz & Vahlis.
//!  * From: "[CCA2 Secure IBE: Standard Model Efficiency through Authenticated Symmetric Encryption](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!  * Published in: CT-RSA, 2008
//!
//! Important notice: Keep in mind that the security of this scheme has not formally been proven.

use crate::util::*;
use core::convert::TryInto;
use irmaseal_curve::{
    multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
    Scalar,
};
use rand::Rng;
use subtle::{Choice, CtOption};

// Max identity buf size
const K: usize = 256;
const N: usize = 2 * K;
const N_BYTE_LEN: usize = N / 8;

// Sizes of elements in particular groups (compressed)
const GT_BYTES: usize = 288;
const G1_BYTES: usize = 48;
const G2_BYTES: usize = 96;
const SCALAR_BYTES: usize = 32;

// Derived sizes
pub const PK_BYTES: usize = 8 * G1_BYTES + 2 * GT_BYTES;
pub const SK_BYTES: usize = 15 * SCALAR_BYTES;
pub const USK_BYTES: usize = 6 * G2_BYTES;
pub const CT_BYTES: usize = 5 * G1_BYTES + 1 * GT_BYTES;

/// Public key parameters generated by the PKG used to encaps messages.
/// Also known as MPK.
#[derive(Clone, Copy, PartialEq)]
pub struct PublicKey {
    a_1: [G1Affine; 2],
    w0ta_1: [G1Affine; 2],
    w1ta_1: [G1Affine; 2],
    wprime_1: [G1Affine; 2],
    kta_t: Gt,
    aprime_t: Gt,
}

/// Secret key parameter generated by the PKG used to extract user secret keys.
/// Also known as MSK.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SecretKey {
    alpha: Scalar,
    b: [Scalar; 2],
    k: [Scalar; 2],
    w0: [[Scalar; 2]; 2],
    w1: [[Scalar; 2]; 2],
    wprime: [Scalar; 2],
}

/// User secret key. Can be used to decaps the corresponding ciphertext.
/// Also known as USK_{id}.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct UserSecretKey {
    d0: [G2Affine; 2],
    d1: [G2Affine; 2],
    d2: [G2Affine; 2],
}

/// Encrypted message. Can only be decapsed with a corresponding user secret key.
/// Also known as CT_{id}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CipherText {
    c0: [G1Affine; 2],
    c1: [G1Affine; 2],
    c2: G1Affine,
    c3: Gt,
}

/// Hashed byte representation of an identity.
pub struct Identity([u8; N_BYTE_LEN]);

/// A shared secret in the target group.
///
/// You can use the byte representation to derive, for example, an AES key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedSecret(Gt);

/// Generate a keypair used by the Private Key Generator (PKG).
pub fn setup<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let alpha = rand_scalar(rng);
    let k = [rand_scalar(rng), rand_scalar(rng)];
    let a = [Scalar::one(), rand_scalar(rng)];
    let b = [rand_scalar(rng), rand_scalar(rng)];

    let w0 = [
        [rand_scalar(rng), rand_scalar(rng)],
        [rand_scalar(rng), rand_scalar(rng)],
    ];

    let w1 = [
        [rand_scalar(rng), rand_scalar(rng)],
        [rand_scalar(rng), rand_scalar(rng)],
    ];

    let wprime = [rand_scalar(rng), rand_scalar(rng)];

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
        g1 * (a[0] * wprime[0]),
        g1 * (a[0] * wprime[1]),
    ];

    let mut out = [G1Affine::default(); 8];
    G1Projective::batch_normalize(&batch, &mut out);

    let pair = pairing(&g1, &g2);
    let kta_t = pair * (k[0] * a[0] + k[1] * a[1]);
    let aprime_t = pair * alpha;

    (
        PublicKey {
            a_1: [out[0], out[1]],
            w0ta_1: [out[2], out[3]],
            w1ta_1: [out[4], out[5]],
            wprime_1: [out[6], out[7]],
            kta_t,
            aprime_t,
        },
        SecretKey {
            alpha,
            b,
            k,
            w0,
            w1,
            wprime,
        },
    )
}

fn hash_g1_to_scalar(g1: G1Affine) -> Scalar {
    let buf = sha3_512(&g1.to_uncompressed());
    Scalar::from_bytes_wide(&buf)
}

/// Extract a user secret key for a given identity.
pub fn extract_usk<R: Rng>(sk: &SecretKey, v: &Identity, rng: &mut R) -> UserSecretKey {
    let g2 = G2Affine::generator();
    let r = rand_scalar(rng);
    let alpha2 = rand_scalar(rng);
    let alpha1 = sk.alpha - alpha2;
    let id = v.to_scalar();

    let br = [sk.b[0] * r, sk.b[1] * r];

    let batch = [
        g2 * br[0],
        g2 * br[1],
        g2 * (alpha2
            - sk.k[0]
            - (br[0] * sk.w0[0][0]
                + br[1] * sk.w0[0][1]
                + id * (br[0] * sk.w1[0][0] + br[1] * sk.w1[0][1]))),
        g2 * (-sk.k[1]
            - (br[0] * sk.w0[1][0]
                + br[1] * sk.w0[1][1]
                + id * (br[0] * sk.w1[1][0] + br[1] * sk.w1[1][1]))),
        g2 * (alpha1 - (br[0] * sk.wprime[0])),
        g2 * -(br[0] * sk.wprime[1]),
    ];

    let mut out = [G2Affine::default(); 6];
    G2Projective::batch_normalize(&batch, &mut out);

    UserSecretKey {
        d0: [out[0], out[1]], // K
        d1: [out[2], out[3]], // K'
        d2: [out[4], out[5]], // K' bar
    }
}

/// Generate a SharedSecret and corresponding Ciphertext for that key.
pub fn encaps<R: Rng>(pk: &PublicKey, id: &Identity, rng: &mut R) -> (CipherText, SharedSecret) {
    let s = rand_scalar(rng);
    let x = id.to_scalar();

    let c0 = [(pk.a_1[0] * s).into(), (pk.a_1[1] * s).into()];

    let c1: [G1Affine; 2] = [
        ((pk.w0ta_1[0] * s) + (pk.w1ta_1[0] * (s * x))).into(),
        ((pk.w0ta_1[1] * s) + (pk.w1ta_1[1] * (s * x))).into(),
    ];

    let y = hash_g1_to_scalar(c0[0]);
    let c2: G1Affine = ((pk.wprime_1[0] * s) + (pk.wprime_1[1]) * (s * y)).into();
    let c3 = pk.kta_t * s;
    let k = pk.aprime_t * s;

    (
        CipherText {
            c0, // C_i
            c1, // C'_i
            c2, // C''
            c3, // C' (\in Gt)
        },
        SharedSecret(k),
    )
}

/// Derive the same SharedSecret from the CipherText using a UserSecretKey.
pub fn decaps(usk: &UserSecretKey, ct: &CipherText) -> SharedSecret {
    let y = hash_g1_to_scalar(ct.c0[0]);
    let z: G2Affine = (usk.d2[0] + (usk.d2[1] * y)).into();

    let k = ct.c3
        + multi_miller_loop(&[
            (
                &ct.c0[0],
                &G2Prepared::from(G2Affine::from(usk.d1[0] + G2Projective::from(z))),
            ),
            (&ct.c0[1], &G2Prepared::from(usk.d1[1])),
            (
                &G1Affine::from(ct.c1[0] + G1Projective::from(ct.c2)),
                &G2Prepared::from(usk.d0[0]),
            ),
            (&ct.c1[1], &G2Prepared::from(usk.d0[1])),
        ])
        .final_exponentiation();

    SharedSecret(k)
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

impl SharedSecret {
    pub fn to_bytes(&self) -> [u8; GT_BYTES] {
        self.0.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; GT_BYTES]) -> CtOption<Self> {
        Gt::from_compressed(bytes).map(Self)
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
            res[288 + x..288 + y].copy_from_slice(&self.wprime_1[i].to_compressed());
        }
        res[384..672].copy_from_slice(&self.kta_t.to_compressed());
        res[672..].copy_from_slice(&self.aprime_t.to_compressed());

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
        let mut wprime_1 = [G1Affine::default(); 2];
        let mut kta_t = Gt::default();
        let mut aprime_t = Gt::default();

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
        is_some &= Gt::from_compressed_unchecked(bytes[672..].try_into().unwrap())
            .map(|el| aprime_t = el)
            .is_some();

        CtOption::new(
            PublicKey {
                a_1,
                w0ta_1,
                w1ta_1,
                wprime_1,
                kta_t,
                aprime_t,
            },
            is_some,
        )
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; SK_BYTES] {
        let mut res = [0u8; SK_BYTES];
        let (mut x, mut y);

        res[0..32].copy_from_slice(&self.alpha.to_bytes());
        for i in 0..2 {
            x = i * SCALAR_BYTES;
            y = x + SCALAR_BYTES;
            res[32 + x..32 + y].copy_from_slice(&self.b[i].to_bytes());
            res[96 + x..96 + y].copy_from_slice(&self.k[i].to_bytes());
            res[416 + x..416 + y].copy_from_slice(&self.wprime[i].to_bytes());

            for j in 0..2 {
                x = (i * 2 + j) * SCALAR_BYTES;
                y = x + SCALAR_BYTES;
                res[160 + x..160 + y].copy_from_slice(&self.w0[i][j].to_bytes());
                res[288 + x..288 + y].copy_from_slice(&self.w1[i][j].to_bytes());
            }
        }

        res
    }

    pub fn from_bytes(bytes: &[u8; SK_BYTES]) -> CtOption<Self> {
        let mut alpha = Scalar::default();
        let mut b = [Scalar::default(); 2];
        let mut k = [Scalar::default(); 2];
        let mut w0 = [[Scalar::default(); 2]; 2];
        let mut w1 = [[Scalar::default(); 2]; 2];
        let mut wprime = [Scalar::default(); 2];

        let mut is_some = Choice::from(1u8);
        for i in 0..2 {
            let x = i * SCALAR_BYTES;
            let y = x + SCALAR_BYTES;
            is_some &= Scalar::from_bytes(&bytes[0..32].try_into().unwrap())
                .map(|s| alpha = s)
                .is_some();
            is_some &= Scalar::from_bytes(&bytes[32 + x..32 + y].try_into().unwrap())
                .map(|s| b[i] = s)
                .is_some();
            is_some &= Scalar::from_bytes(&bytes[96 + x..96 + y].try_into().unwrap())
                .map(|s| k[i] = s)
                .is_some();
            is_some &= Scalar::from_bytes(&bytes[416 + x..416 + y].try_into().unwrap())
                .map(|s| wprime[i] = s)
                .is_some();
            for j in 0..2 {
                let x = (i * 2 + j) * SCALAR_BYTES;
                let y = x + SCALAR_BYTES;
                is_some &= Scalar::from_bytes(&bytes[160 + x..160 + y].try_into().unwrap())
                    .map(|s| w0[i][j] = s)
                    .is_some();
                is_some &= Scalar::from_bytes(&bytes[288 + x..288 + y].try_into().unwrap())
                    .map(|s| w1[i][j] = s)
                    .is_some();
            }
        }

        CtOption::new(
            SecretKey {
                alpha,
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

impl UserSecretKey {
    pub fn to_bytes(&self) -> [u8; USK_BYTES] {
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
    pub fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
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

impl CipherText {
    pub fn to_bytes(&self) -> [u8; CT_BYTES] {
        let mut res = [0u8; CT_BYTES];

        for i in 0..2 {
            let x = i * G1_BYTES;
            let y = x + G1_BYTES;
            res[x..y].copy_from_slice(&self.c0[i].to_compressed());
            res[96 + x..96 + y].copy_from_slice(&self.c1[i].to_compressed());
        }
        res[192..240].copy_from_slice(&self.c2.to_compressed());
        res[240..].copy_from_slice(&self.c3.to_compressed());

        res
    }

    pub fn from_bytes(bytes: &[u8; CT_BYTES]) -> CtOption<Self> {
        let mut c0 = [G1Affine::default(); 2];
        let mut c1 = [G1Affine::default(); 2];
        let mut c2 = G1Affine::default();
        let mut c3 = Gt::default();

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
        is_some &= G1Affine::from_compressed(&bytes[192..240].try_into().unwrap())
            .map(|el| c2 = el)
            .is_some();
        is_some &= Gt::from_compressed(&bytes[240..].try_into().unwrap())
            .map(|el| c3 = el)
            .is_some();

        CtOption::new(CipherText { c0, c1, c2, c3 }, is_some)
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
        ss: SharedSecret,
    }

    fn perform_default() -> DefaultSubResults {
        let mut rng = rand::thread_rng();

        let kid = Identity::derive(ID);

        let (pk, sk) = setup(&mut rng);
        let usk = extract_usk(&sk, &kid, &mut rng);

        let (c, ss) = encaps(&pk, &kid, &mut rng);

        DefaultSubResults { pk, sk, usk, c, ss }
    }

    #[test]
    fn eq_encaps_decaps() {
        let results = perform_default();
        let ss2 = decaps(&results.usk, &results.c);

        assert_eq!(results.ss, ss2);
    }

    #[test]
    fn eq_serialize_deserialize() {
        let result = perform_default();

        assert_eq!(
            result.ss,
            SharedSecret::from_bytes(&result.ss.to_bytes()).unwrap()
        );
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
