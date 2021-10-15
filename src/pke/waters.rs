//! IND-ID-CPA secure IBE from the Waters scheme on the [BLS12-381 pairing-friendly elliptic curve](https://github.com/zkcrypto/bls12_381).
//! * From: "[Efficient Identity-Based Encryption Without Random Oracles](https://link.springer.com/chapter/10.1007/11426639_7)"
//! * Published in: EUROCRYPT, 2005

use crate::util::*;
use crate::{pke::IBE, Compress, Derive};
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use irmaseal_curve::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar};
use rand::{CryptoRng, Rng};
use subtle::{Choice, ConditionallySelectable, CtOption};

#[allow(unused_imports)]
use group::Group;

const HASH_BIT_LEN: usize = 256;
const HASH_BYTE_LEN: usize = HASH_BIT_LEN / 8;

const CHUNKS: usize = HASH_BIT_LEN;
const PARAMETERSIZE: usize = CHUNKS * 48;

/// Size of the compressed message in bytes.
pub const MSG_BYTES: usize = GT_BYTES;

/// Size of the compressed master public key in bytes.
pub const PK_BYTES: usize = 2 * 48 + 2 * 96 + PARAMETERSIZE;

/// Size of the compressed master secret key in bytes.
pub const SK_BYTES: usize = G1_BYTES;

/// Size of the compressed user secret key in bytes.
pub const USK_BYTES: usize = G1_BYTES + G2_BYTES;

/// Size of the compressed ciphertext key in bytes.
pub const CT_BYTES: usize = G1_BYTES + G2_BYTES + GT_BYTES;

/// Public key parameters used for entanglement with identities.
struct Parameters([G1Affine; CHUNKS]);

/// Public key parameters generated by the PKG used to encrypt messages.
#[derive(Clone, Copy, PartialEq)]
pub struct PublicKey {
    g: G2Affine,
    g1: G1Affine,
    g2: G2Affine,
    uprime: G1Affine,
    u: Parameters,
}

/// Secret key parameter generated by the PKG used to extract user secret keys.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct SecretKey {
    g1prime: G1Affine,
}

/// Points on the paired curves that form the user secret key.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct UserSecretKey {
    d1: G1Affine,
    d2: G2Affine,
}

/// Field parameters for an identity.
///
/// Effectively a hash of an identity, mapped to the curve field.
/// Together with the public key parameters generated by the PKG forms the user public key.
pub struct Identity([u8; HASH_BYTE_LEN]);

/// A point on the paired curve that can be encrypted and decrypted.
///
/// You can use the byte representation to derive an AES key.
pub type Msg = Gt;

/// Encrypted message. Can only be decrypted with an user secret key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CipherText {
    c1: Gt,
    c2: G2Affine,
    c3: G1Affine,
}

/// Common operation used in extraction and encryption to entangle
/// PublicKey with Identity into a point on G1.
fn entangle(pk: &PublicKey, v: &Identity) -> G1Projective {
    let mut ucoll: G1Projective = pk.uprime.into();
    for (ui, vi) in pk.u.0.iter().zip(bits(&v.0)) {
        ucoll = G1Projective::conditional_select(&ucoll, &(ui + ucoll), vi);
    }
    ucoll
}

/// The Waters identity-based encryption scheme.
pub struct Waters;

impl IBE for Waters {
    type Pk = PublicKey;
    type Sk = SecretKey;
    type Usk = UserSecretKey;
    type Ct = CipherText;
    type Msg = Msg;
    type Id = Identity;
    type RngBytes = [u8; 64];

    const PK_BYTES: usize = PK_BYTES;
    const SK_BYTES: usize = SK_BYTES;
    const USK_BYTES: usize = USK_BYTES;
    const CT_BYTES: usize = CT_BYTES;
    const MSG_BYTES: usize = MSG_BYTES;

    /// Generate a keypair used by the Private Key Generator (PKG).
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> (PublicKey, SecretKey) {
        let g: G2Affine = rand_g2(rng).into();

        let alpha = rand_scalar(rng);
        let g2 = (g * alpha).into();

        let g1 = rand_g1(rng).into();
        let uprime = rand_g1(rng).into();

        let mut u = Parameters([G1Affine::default(); CHUNKS]);
        for ui in u.0.iter_mut() {
            *ui = rand_g1(rng).into();
        }

        let pk = PublicKey {
            g,
            g1,
            g2,
            uprime,
            u,
        };

        let g1prime: G1Affine = (g1 * alpha).into();

        let sk = SecretKey { g1prime };

        (pk, sk)
    }

    /// Extract an user secret key for a given identity.
    fn extract_usk<R: Rng + CryptoRng>(
        opk: Option<&PublicKey>,
        sk: &SecretKey,
        v: &Identity,
        rng: &mut R,
    ) -> UserSecretKey {
        let pk = opk.unwrap();

        let r = rand_scalar(rng);
        let ucoll = entangle(pk, v);
        let d1 = (sk.g1prime + (ucoll * r)).into();
        let d2 = (pk.g * r).into();

        UserSecretKey { d1, d2 }
    }

    /// Encrypt a message using the PKG public key and an identity.
    fn encrypt(pk: &PublicKey, v: &Identity, m: &Msg, rng_bytes: &Self::RngBytes) -> CipherText {
        let t = Scalar::from_bytes_wide(rng_bytes);

        let c3coll = entangle(pk, v);
        let c1 = irmaseal_curve::pairing(&pk.g1, &pk.g2) * t + m;
        let c2 = (pk.g * t).into();
        let c3 = (c3coll * t).into();

        CipherText { c1, c2, c3 }
    }

    /// Decrypt ciphertext to a message using a user secret key.
    fn decrypt(usk: &UserSecretKey, c: &CipherText) -> Msg {
        let m = c.c1
            + multi_miller_loop(&[
                (&c.c3, &G2Prepared::from(usk.d2)),
                (&-usk.d1, &G2Prepared::from(c.c2)),
            ])
            .final_exponentiation();

        m
    }
}

impl Parameters {
    pub fn to_bytes(&self) -> [u8; PARAMETERSIZE] {
        let mut res = [0u8; PARAMETERSIZE];
        for i in 0..CHUNKS {
            *array_mut_ref![&mut res, i * 48, 48] = self.0[i].to_compressed();
        }
        res
    }

    pub fn from_bytes(bytes: &[u8; PARAMETERSIZE]) -> CtOption<Self> {
        let mut res = [G1Affine::default(); CHUNKS];
        let mut is_some = Choice::from(1u8);
        for i in 0..CHUNKS {
            is_some &= G1Affine::from_compressed(array_ref![bytes, i * 48, 48])
                .map(|s| {
                    res[i] = s;
                })
                .is_some();
        }
        CtOption::new(Parameters(res), is_some)
    }
}

impl ConditionallySelectable for Parameters {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = [G1Affine::default(); CHUNKS];
        for (i, (ai, bi)) in a.0.iter().zip(b.0.iter()).enumerate() {
            res[i] = G1Affine::conditional_select(&ai, &bi, choice);
        }
        Parameters(res)
    }
}

impl Clone for Parameters {
    fn clone(&self) -> Self {
        let mut res = [G1Affine::default(); CHUNKS];
        for (src, dst) in self.0.iter().zip(res.as_mut().iter_mut()) {
            *dst = *src;
        }
        Parameters(res)
    }
}

impl Copy for Parameters {}

impl PartialEq for Parameters {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.iter().zip(rhs.0.iter()).all(|(x, y)| x.eq(y))
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters([G1Affine::default(); CHUNKS])
    }
}

impl Derive for Identity {
    /// Hash a byte slice to a set of Identity parameters, which acts as a user public key.
    /// Uses sha3-256 internally.
    fn derive(b: &[u8]) -> Identity {
        Identity(sha3_256(b))
    }

    /// Hash a string slice to a set of Identity parameters.
    /// Directly converts characters to UTF-8 byte representation.
    fn derive_str(s: &str) -> Identity {
        Self::derive(s.as_bytes())
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        let mut res = [u8::default(); HASH_BYTE_LEN];
        for (src, dst) in self.0.iter().zip(res.as_mut().iter_mut()) {
            *dst = *src;
        }
        Identity(res)
    }
}

impl Copy for Identity {}

impl Compress for PublicKey {
    const OUTPUT_SIZE: usize = PK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; PK_BYTES] {
        let mut res = [0u8; PK_BYTES];
        let (g, g1, g2, uprime, u) = mut_array_refs![&mut res, 96, 48, 96, 48, PARAMETERSIZE];
        *g = self.g.to_compressed();
        *g1 = self.g1.to_compressed();
        *g2 = self.g2.to_compressed();
        *uprime = self.uprime.to_compressed();
        *u = self.u.to_bytes();
        res
    }

    fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        let (g, g1, g2, uprime, u) = array_refs![bytes, 96, 48, 96, 48, PARAMETERSIZE];

        let g = G2Affine::from_compressed(g);
        let g1 = G1Affine::from_compressed(g1);
        let g2 = G2Affine::from_compressed(g2);
        let uprime = G1Affine::from_compressed(uprime);
        let u = Parameters::from_bytes(u);

        g.and_then(|g| {
            g1.and_then(|g1| {
                g2.and_then(|g2| {
                    uprime.and_then(|uprime| {
                        u.map(|u| PublicKey {
                            g,
                            g1,
                            g2,
                            uprime,
                            u,
                        })
                    })
                })
            })
        })
    }
}

impl Compress for SecretKey {
    const OUTPUT_SIZE: usize = SK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; SK_BYTES] {
        self.g1prime.to_compressed()
    }

    fn from_bytes(bytes: &[u8; SK_BYTES]) -> CtOption<Self> {
        G1Affine::from_compressed(bytes).map(|g1prime| SecretKey { g1prime })
    }
}

impl Compress for UserSecretKey {
    const OUTPUT_SIZE: usize = USK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut res = [0u8; USK_BYTES];
        let (d1, d2) = mut_array_refs![&mut res, 48, 96];
        *d1 = self.d1.to_compressed();
        *d2 = self.d2.to_compressed();
        res
    }

    fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let (d1, d2) = array_refs![bytes, 48, 96];

        let d1 = G1Affine::from_compressed(d1);
        let d2 = G2Affine::from_compressed(d2);

        d1.and_then(|d1| d2.map(|d2| UserSecretKey { d1, d2 }))
    }
}

impl Compress for CipherText {
    const OUTPUT_SIZE: usize = CT_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; CT_BYTES] {
        let mut res = [0u8; CT_BYTES];
        let (c1, c2, c3) = mut_array_refs![&mut res, 288, 96, 48];
        *c1 = self.c1.to_compressed();
        *c2 = self.c2.to_compressed();
        *c3 = self.c3.to_compressed();
        res
    }

    fn from_bytes(bytes: &[u8; CT_BYTES]) -> CtOption<Self> {
        let (c1, c2, c3) = array_refs![bytes, 288, 96, 48];

        let c1 = Gt::from_compressed(c1);
        let c2 = G2Affine::from_compressed(c2);
        let c3 = G1Affine::from_compressed(c3);

        c1.and_then(|c1| c2.and_then(|c2| c3.map(|c3| CipherText { c1, c2, c3 })))
    }
}

#[cfg(test)]
mod tests {
    test_ibe!(Waters);
}
