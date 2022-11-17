//! IND-CCA2 secure IBE Kiltz-Vahlis IBE1 scheme.
//! * From: "[CCA2 Secure IBE: Standard Model Efficiency through Authenticated Symmetric Encryption](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//! * Published in: CT-RSA, 2008

use crate::kem::{Error, SharedSecret, IBKEM};
use crate::util::*;
use crate::Compress;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use irmaseal_curve::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar};
use rand::{CryptoRng, Rng};
use subtle::{Choice, ConditionallySelectable, CtOption};

const K: usize = 256;
const N: usize = 2 * K;
const HASH_PARAMETER_SIZE: usize = N * 48;

/// Size of the compressed master public key in bytes.
pub const PK_BYTES: usize = 96 + 48 + HASH_PARAMETER_SIZE + 48 + 288;

/// Size of the compressed master secret key in bytes.
pub const SK_BYTES: usize = G1_BYTES;

/// Size of the compressed user secret key in bytes.
pub const USK_BYTES: usize = 2 * G1_BYTES + G2_BYTES;

/// Size of the compressed ciphertext key in bytes.
pub const CT_BYTES: usize = G1_BYTES + G2_BYTES;

#[derive(Debug)]
struct HashParameters([G1Affine; N]);

/// The Kiltz-Vahlis-1 identity-based key encapsulation scheme.
#[derive(Debug, Clone, Copy)]
pub struct KV1;

/// Public key parameters generated by the PKG used to encrypt messages.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKey {
    g: G2Affine,
    hzero: G1Affine,
    h: HashParameters,
    u: G1Affine,
    z: Gt,
}

/// Secret key parameter generated by the PKG used to extract user secret keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SecretKey {
    alpha: G1Affine,
}

/// Points on the paired curves that form the user secret key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UserSecretKey {
    d1: G1Affine,
    d2: G2Affine,
    d3: G1Affine,
}

/// Encrypted message. Can only be decrypted with an user secret key.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct CipherText {
    c1: G2Affine,
    c2: G1Affine,
}

fn hash_to_curve(pk: &PublicKey, v: &Identity) -> G1Projective {
    let mut hcoll: G1Projective = pk.hzero.into();
    for (hi, vi) in pk.h.0.iter().zip(bits(&v.0)) {
        hcoll = G1Projective::conditional_select(&hcoll, &(hi + hcoll), vi);
    }
    hcoll
}

fn hash_g2_to_scalar(x: G2Affine) -> Scalar {
    let buf = sha3_512(&x.to_uncompressed());
    Scalar::from_bytes_wide(&buf)
}

impl IBKEM for KV1 {
    const IDENTIFIER: &'static str = "kv1";

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
        let g: G2Affine = rand_g2(rng).into();

        let alpha: G1Affine = rand_g1(rng).into();
        let u: G1Affine = rand_g1(rng).into();
        let z = irmaseal_curve::pairing(&alpha, &g);

        let hzero = G1Affine::default();
        let mut h = HashParameters([G1Affine::default(); N]);
        for hi in h.0.iter_mut() {
            *hi = rand_g1(rng).into();
        }

        let pk = PublicKey { g, hzero, h, u, z };
        let sk = SecretKey { alpha };

        (pk, sk)
    }

    /// Extract a user secret key for a given identity.
    ///
    /// This scheme **does** require the master public key to perform this operation.
    /// If no master public key is given, this function panics.
    fn extract_usk<R: Rng + CryptoRng>(
        opk: Option<&PublicKey>,
        sk: &SecretKey,
        v: &Identity,
        rng: &mut R,
    ) -> UserSecretKey {
        let pk = opk.unwrap();
        let s = rand_scalar(rng);

        let d1 = (sk.alpha + (hash_to_curve(pk, v) * s)).into();
        let d2 = (pk.g * (-s)).into();
        let d3 = (pk.u * s).into();

        UserSecretKey { d1, d2, d3 }
    }

    fn encaps<R: Rng + CryptoRng>(
        pk: &Self::Pk,
        id: &Self::Id,
        rng: &mut R,
    ) -> (Self::Ct, SharedSecret) {
        let r = rand_scalar(rng);

        let c1 = (pk.g * r).into();
        let t = hash_g2_to_scalar(c1);
        let c2 = ((hash_to_curve(pk, id) + (pk.u * t)) * r).into();
        let k = pk.z * r;

        (CipherText { c1, c2 }, SharedSecret::from(&k))
    }

    /// Decrypt ciphertext to a SharedSecret using a user secret key.
    ///
    /// # Panics
    ///
    /// This scheme does **not** require the systems master public key to perform this operation.
    /// Therefore, this operation never panics.
    ///
    /// # Errors
    ///
    /// This operation always implicitly rejects ciphertexts and therefore never errors.
    fn decaps(
        _opk: Option<&PublicKey>,
        usk: &UserSecretKey,
        c: &CipherText,
    ) -> Result<SharedSecret, Error> {
        let t = hash_g2_to_scalar(c.c1);
        let x: G1Affine = (usk.d1 + (usk.d3 * t)).into();

        let k = multi_miller_loop(&[
            (&x, &G2Prepared::from(c.c1)),
            (&c.c2, &G2Prepared::from(usk.d2)),
        ])
        .final_exponentiation();

        Ok(SharedSecret::from(&k))
    }
}

impl HashParameters {
    pub fn to_bytes(&self) -> [u8; HASH_PARAMETER_SIZE] {
        let mut res = [0u8; HASH_PARAMETER_SIZE];
        for i in 0..N {
            *array_mut_ref![&mut res, i * 48, 48] = self.0[i].to_compressed();
        }
        res
    }

    pub fn from_bytes(bytes: &[u8; HASH_PARAMETER_SIZE]) -> CtOption<Self> {
        let mut res = [G1Affine::default(); N];
        let mut is_some = Choice::from(1u8);
        for i in 0..N {
            // See comment in PublicKey::from_bytes on cofactor.
            is_some &= G1Affine::from_compressed_unchecked(array_ref![bytes, i * 48, 48])
                .map(|s| {
                    res[i] = s;
                })
                .is_some();
        }
        CtOption::new(HashParameters(res), is_some)
    }
}

impl ConditionallySelectable for HashParameters {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = [G1Affine::default(); N];
        for (i, (ai, bi)) in a.0.iter().zip(b.0.iter()).enumerate() {
            res[i] = G1Affine::conditional_select(&ai, &bi, choice);
        }
        HashParameters(res)
    }
}

impl PartialEq for HashParameters {
    fn eq(&self, rhs: &HashParameters) -> bool {
        self.0.iter().zip(rhs.0.iter()).all(|(x, y)| x.eq(y))
    }
}

impl Clone for HashParameters {
    fn clone(&self) -> Self {
        let mut res = [G1Affine::default(); N];
        for (src, dst) in self.0.iter().zip(res.as_mut().iter_mut()) {
            *dst = *src;
        }
        Self(res)
    }
}

impl Copy for HashParameters {}

impl Default for HashParameters {
    fn default() -> Self {
        HashParameters([G1Affine::default(); N])
    }
}

impl Compress for PublicKey {
    const OUTPUT_SIZE: usize = PK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; PK_BYTES] {
        let mut res = [0u8; PK_BYTES];

        let (g, hzero, h, u, z) = mut_array_refs![&mut res, 96, 48, HASH_PARAMETER_SIZE, 48, 288];
        *g = self.g.to_compressed();
        *hzero = self.hzero.to_compressed();
        *h = self.h.to_bytes();
        *u = self.u.to_compressed();
        *z = self.z.to_compressed();
        res
    }

    fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        let (g, hzero, h, u, z) = array_refs![&bytes, 96, 48, HASH_PARAMETER_SIZE, 48, 288];

        // from_compressed_unchecked doesn't check whether the element has
        // a cofactor.  To mount an attack using a cofactor an attacker
        // must be able to manipulate the public parameters.  But then the
        // attacker can simply use parameters they generated themselves.
        // Thus checking for a cofactor is superfluous.
        let g = G2Affine::from_compressed_unchecked(g);
        let hzero = G1Affine::from_compressed_unchecked(hzero);
        let h = HashParameters::from_bytes(h);
        let u = G1Affine::from_compressed_unchecked(u);
        let z = Gt::from_compressed_unchecked(z);

        g.and_then(|g| {
            hzero.and_then(|hzero| {
                h.and_then(|h| u.and_then(|u| z.map(|z| PublicKey { g, hzero, h, u, z })))
            })
        })
    }
}

impl Compress for SecretKey {
    const OUTPUT_SIZE: usize = SK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; SK_BYTES] {
        self.alpha.to_compressed()
    }

    fn from_bytes(bytes: &[u8; SK_BYTES]) -> CtOption<Self> {
        G1Affine::from_compressed(bytes).map(|alpha| SecretKey { alpha })
    }
}

impl Compress for UserSecretKey {
    const OUTPUT_SIZE: usize = USK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut res = [0u8; USK_BYTES];
        let (d1, d2, d3) = mut_array_refs![&mut res, 48, 96, 48];
        *d1 = self.d1.to_compressed();
        *d2 = self.d2.to_compressed();
        *d3 = self.d3.to_compressed();
        res
    }

    fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let (d1, d2, d3) = array_refs![bytes, 48, 96, 48];

        let d1 = G1Affine::from_compressed(d1);
        let d2 = G2Affine::from_compressed(d2);
        let d3 = G1Affine::from_compressed(d3);

        d1.and_then(|d1| d2.and_then(|d2| d3.map(|d3| UserSecretKey { d1, d2, d3 })))
    }
}

impl Compress for CipherText {
    const OUTPUT_SIZE: usize = CT_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; CT_BYTES] {
        let mut res = [0u8; CT_BYTES];
        let (c1, c2) = mut_array_refs![&mut res, 96, 48];
        *c1 = self.c1.to_compressed();
        *c2 = self.c2.to_compressed();

        res
    }

    fn from_bytes(bytes: &[u8; CT_BYTES]) -> CtOption<Self> {
        let (c1, c2) = array_refs![bytes, 96, 48];

        let c1 = G2Affine::from_compressed(c1);
        let c2 = G1Affine::from_compressed(c2);

        c1.and_then(|c1| c2.map(|c2| CipherText { c1, c2 }))
    }
}

impl ConditionallySelectable for CipherText {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        CipherText {
            c1: G2Affine::conditional_select(&a.c1, &b.c1, choice),
            c2: G1Affine::conditional_select(&a.c2, &b.c2, choice),
        }
    }
}

#[cfg(feature = "mkem")]
impl crate::kem::mkem::MultiRecipient for KV1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Derive;

    test_kem!(KV1);

    #[cfg(feature = "mkem")]
    test_multi_kem!(KV1);
}
