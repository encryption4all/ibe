//! IND-ID-CPA secure IBE from Waters-Naccache scheme.
//!  * Inspired by: [CHARM implementation](https://github.com/JHUISI/charm/blob/dev/charm/schemes/ibenc/ibenc_waters05.py)
//!  * From: "[Secure and Practical Identity-Based Encryption](http://eprint.iacr.org/2005/369.pdf)"
//!  * Published in: IET Information Security, 2007

use crate::util::*;
use crate::{ibe::IBE, Compress, Derive};
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use pg_curve::{multi_miller_loop, G1Affine, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
use rand::{CryptoRng, Rng};
use subtle::{Choice, ConditionallySelectable, CtOption};

#[allow(unused_imports)]
use group::Group;

const HASH_BIT_LEN: usize = 512;
const HASH_BYTE_LEN: usize = HASH_BIT_LEN / 8;

const BITSIZE: usize = 32;
const CHUNKSIZE: usize = BITSIZE / 8;
const CHUNKS: usize = HASH_BYTE_LEN / CHUNKSIZE;

const PARAMETERSIZE: usize = CHUNKS * 96;

/// Size of the compressed message in bytes.
pub const MSG_BYTES: usize = GT_BYTES;

/// Size of the compressed master public key in bytes.
pub const PK_BYTES: usize = 2 * 48 + 2 * 96 + PARAMETERSIZE;

/// Size of the compressed master secret key in bytes.
pub const SK_BYTES: usize = G2_BYTES;

/// Size of the compressed user secret key in bytes.
pub const USK_BYTES: usize = G1_BYTES + G2_BYTES;

/// Size of the compressed ciphertext key in bytes.
pub const CT_BYTES: usize = G1_BYTES + G2_BYTES + GT_BYTES;

#[derive(Default, Clone, Copy, PartialEq, Debug)]
struct Parameters([G2Affine; CHUNKS]);

/// Public key parameters generated by the PKG used to encrypt messages.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PublicKey {
    g: G1Affine,
    g1: G1Affine,
    g2: G2Affine,
    uprime: G2Affine,
    u: Parameters,
}

/// Field parameters for an identity.
///
/// Effectively a hash of an identity, mapped to the curve field.
/// Together with the public key parameters generated by the PKG forms the user public key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Identity([Scalar; CHUNKS]);

/// Secret key parameter generated by the PKG used to extract user secret keys.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SecretKey {
    g2prime: G2Affine,
}

/// Points on the paired curves that form the user secret key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UserSecretKey {
    d1: G2Affine,
    d2: G1Affine,
}

/// Encrypted message. Can only be decrypted with an user secret key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CipherText {
    c1: Gt,
    c2: G1Affine,
    c3: G2Affine,
}

/// A point on the paired curve that can be encrypted and decrypted.
///
/// You can use the byte representation to derive an AES key.
type Msg = Gt;

/// Common operation used in extraction and encryption to entangle
/// PublicKey with Identity into a point on G2.
fn entangle(pk: &PublicKey, v: &Identity) -> G2Projective {
    let mut ucoll: G2Projective = pk.uprime.into();
    for (ui, vi) in pk.u.0.iter().zip(&v.0) {
        ucoll += ui * vi;
    }
    ucoll
}

/// The Waters-Naccache identity-based encryption scheme.
#[derive(Debug)]
pub struct WatersNaccache;

impl IBE for WatersNaccache {
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
        let g: G1Affine = rand_g1(rng).into();

        let alpha = rand_scalar(rng);
        let g1 = (g * alpha).into();

        let g2 = rand_g2(rng).into();
        let uprime = rand_g2(rng).into();

        let mut u = Parameters([G2Affine::default(); CHUNKS]);
        for ui in u.0.iter_mut() {
            *ui = rand_g2(rng).into();
        }

        let pk = PublicKey {
            g,
            g1,
            g2,
            uprime,
            u,
        };

        let g2prime: G2Affine = (g2 * alpha).into();

        let sk = SecretKey { g2prime };

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
        let d1 = (sk.g2prime + (ucoll * r)).into();
        let d2 = (pk.g * r).into();

        UserSecretKey { d1, d2 }
    }

    /// Encrypt a message using the PKG public key and an identity.
    fn encrypt(pk: &PublicKey, v: &Identity, m: &Msg, rng_bytes: &Self::RngBytes) -> CipherText {
        let t = Scalar::from_bytes_wide(rng_bytes);

        let c3coll = entangle(pk, v);
        let c1 = pg_curve::pairing(&pk.g1, &pk.g2) * t + m;
        let c2 = (pk.g * t).into();
        let c3 = (c3coll * t).into();

        CipherText { c1, c2, c3 }
    }

    /// Decrypt ciphertext to a message using a user secret key.
    fn decrypt(usk: &UserSecretKey, c: &CipherText) -> Msg {
        let m = c.c1
            + multi_miller_loop(&[
                (&usk.d2, &G2Prepared::from(c.c3)),
                (&-c.c2, &G2Prepared::from(usk.d1)),
            ])
            .final_exponentiation();

        m
    }
}

impl ConditionallySelectable for Parameters {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut res = [G2Affine::default(); CHUNKS];
        for (i, (ai, bi)) in a.0.iter().zip(b.0.iter()).enumerate() {
            res[i] = G2Affine::conditional_select(&ai, &bi, choice);
        }
        Parameters(res)
    }
}

impl Parameters {
    pub fn to_bytes(&self) -> [u8; PARAMETERSIZE] {
        let mut res = [0u8; PARAMETERSIZE];
        for i in 0..CHUNKS {
            *array_mut_ref![&mut res, i * 96, 96] = self.0[i].to_compressed();
        }
        res
    }

    pub fn from_bytes(bytes: &[u8; PARAMETERSIZE]) -> CtOption<Self> {
        let mut res = [G2Affine::default(); CHUNKS];
        let mut is_some = Choice::from(1u8);
        for i in 0..CHUNKS {
            is_some &= G2Affine::from_compressed(array_ref![bytes, i * 96, 96])
                .map(|s| {
                    res[i] = s;
                })
                .is_some();
        }
        CtOption::new(Parameters(res), is_some)
    }
}

impl Compress for PublicKey {
    const OUTPUT_SIZE: usize = PK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; PK_BYTES] {
        let mut res = [0u8; PK_BYTES];
        let (g, g1, g2, uprime, u) = mut_array_refs![&mut res, 48, 48, 96, 96, PARAMETERSIZE];
        *g = self.g.to_compressed();
        *g1 = self.g1.to_compressed();
        *g2 = self.g2.to_compressed();
        *uprime = self.uprime.to_compressed();
        *u = self.u.to_bytes();
        res
    }

    fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        let (g, g1, g2, uprime, u) = array_refs![bytes, 48, 48, 96, 96, PARAMETERSIZE];

        let g = G1Affine::from_compressed(g);
        let g1 = G1Affine::from_compressed(g1);
        let g2 = G2Affine::from_compressed(g2);
        let uprime = G2Affine::from_compressed(uprime);
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
    type Output = [u8; SK_BYTES];

    fn to_bytes(&self) -> [u8; SK_BYTES] {
        self.g2prime.to_compressed()
    }

    fn from_bytes(bytes: &[u8; SK_BYTES]) -> CtOption<Self> {
        G2Affine::from_compressed(bytes).map(|g2prime| SecretKey { g2prime })
    }
}

impl Compress for CipherText {
    const OUTPUT_SIZE: usize = CT_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; CT_BYTES] {
        let mut res = [0u8; CT_BYTES];
        let (c1, c2, c3) = mut_array_refs![&mut res, 288, 48, 96];
        *c1 = self.c1.to_compressed();
        *c2 = self.c2.to_compressed();
        *c3 = self.c3.to_compressed();
        res
    }

    fn from_bytes(bytes: &[u8; CT_BYTES]) -> CtOption<Self> {
        let (c1, c2, c3) = array_refs![bytes, 288, 48, 96];

        let c1 = Gt::from_compressed(c1);
        let c2 = G1Affine::from_compressed(c2);
        let c3 = G2Affine::from_compressed(c3);

        c1.and_then(|c1| c2.and_then(|c2| c3.map(|c3| CipherText { c1, c2, c3 })))
    }
}

impl Compress for UserSecretKey {
    const OUTPUT_SIZE: usize = USK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut res = [0u8; USK_BYTES];
        let (d1, d2) = mut_array_refs![&mut res, 96, 48];
        *d1 = self.d1.to_compressed();
        *d2 = self.d2.to_compressed();
        res
    }

    fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let (d1, d2) = array_refs![bytes, 96, 48];

        let d1 = G2Affine::from_compressed(d1);
        let d2 = G1Affine::from_compressed(d2);

        d1.and_then(|d1| d2.map(|d2| UserSecretKey { d1, d2 }))
    }
}

impl Derive for Identity {
    /// Hash a byte slice to a set of Identity parameters, which acts as a user public key.
    /// Uses sha3-512 internally.
    fn derive(b: &[u8]) -> Identity {
        let hash = sha3_512(b);

        let mut result = [Scalar::zero(); CHUNKS];
        for (i, r) in result.iter_mut().enumerate().take(CHUNKS) {
            *r = u64::from(u32::from_le_bytes(*array_ref![
                hash,
                i * CHUNKSIZE,
                CHUNKSIZE
            ]))
            .into();
        }

        Identity(result)
    }

    /// Hash a string slice to a set of Identity parameters.
    /// Directly converts characters to UTF-8 byte representation.
    fn derive_str(s: &str) -> Identity {
        Self::derive(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    test_ibe!(WatersNaccache);
}
