//! IND-sID-CPA secure IBE from the Boyen & Waters IBE scheme.
//! * From: "[Anonymous Hierarchical Identity-Based Encryption (Without Random Oracles)](https://link.springer.com/content/pdf/10.1007/11818175_17.pdf)"
//!
//! The structure of the byte serialisation of the various datastructures is not guaranteed
//! to remain constant between releases of this library.
//! All operations in this library are implemented to run in constant time.

use core::convert::TryInto;

use crate::util::*;
use crate::{ibe::IBE, Compress};
use arrayref::{array_refs, mut_array_refs};
use irmaseal_curve::{multi_miller_loop, pairing, G1Affine, G2Affine, G2Prepared, Scalar};
use rand::{CryptoRng, Rng};
use subtle::CtOption;

#[allow(unused_imports)]
use group::Group;

pub use irmaseal_curve::Gt;

/// Size of the compressed message in bytes.
pub const MSG_BYTES: usize = GT_BYTES;

/// Size of the compressed master public key in bytes.
pub const PK_BYTES: usize = 6 * G1_BYTES + 2 * G2_BYTES + GT_BYTES;

/// Size of the compressed master secret key in bytes.
pub const SK_BYTES: usize = 5 * SCALAR_BYTES;

/// Size of the compressed user secret key in bytes.
pub const USK_BYTES: usize = 5 * G2_BYTES;

/// Size of the compressed ciphertext key in bytes.
pub const CT_BYTES: usize = 5 * G1_BYTES + GT_BYTES;

/// Public key parameters generated by the PKG used to encrypt messages.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKey {
    omega: Gt,
    g0: G1Affine,
    g1: G1Affine,
    h0: G2Affine,
    h1: G2Affine,
    v1: G1Affine,
    v2: G1Affine,
    v3: G1Affine,
    v4: G1Affine,
}

/// Secret key parameter generated by the PKG used to extract user secret keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SecretKey {
    alpha: Scalar,
    t1: Scalar,
    t2: Scalar,
    t3: Scalar,
    t4: Scalar,
}

/// Points on the paired curves that form the user secret key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UserSecretKey {
    d: [G2Affine; 5],
}

/// Encrypted message. Can only be decrypted with an user secret key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CipherText {
    c: [G1Affine; 5],
    cprime: Gt,
}

/// A point on the paired curve that can be encrypted and decrypted.
///
/// You can use the byte representation to derive an AES key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SharedSecret(Gt);

/// A message that can be encrypted using the PKE.
pub type Msg = Gt;

fn hash_to_scalar(v: &Identity) -> Scalar {
    Scalar::from_bytes_wide(&v.0)
}

/// The Boyen & Waters identity-based encryption scheme.
#[derive(Debug)]
pub struct BoyenWaters;

impl IBE for BoyenWaters {
    type Pk = PublicKey;
    type Sk = SecretKey;
    type Usk = UserSecretKey;
    type Ct = CipherText;
    type Msg = Msg;
    type Id = Identity;
    type RngBytes = [u8; 192];

    const PK_BYTES: usize = PK_BYTES;
    const SK_BYTES: usize = SK_BYTES;
    const USK_BYTES: usize = USK_BYTES;
    const CT_BYTES: usize = CT_BYTES;
    const MSG_BYTES: usize = MSG_BYTES;

    /// Generate a keypair used by the Private Key Generator (PKG).
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> (PublicKey, SecretKey) {
        let g = G1Affine::generator();
        let h = G2Affine::generator();

        let [z0, z1] = [rand_scalar(rng), rand_scalar(rng)];
        let g0: G1Affine = (g * z0).into();
        let g1: G1Affine = (g * z1).into();
        let h0: G2Affine = (h * z0).into();
        let h1: G2Affine = (h * z1).into();

        let alpha = rand_scalar(rng);

        let t1 = rand_scalar(rng);
        let t2 = rand_scalar(rng);
        let t3 = rand_scalar(rng);
        let t4 = rand_scalar(rng);

        let omega: Gt = pairing(&g, &h) * (t1 * t2 * alpha);

        let v1: G1Affine = (g * t1).into();
        let v2: G1Affine = (g * t2).into();
        let v3: G1Affine = (g * t3).into();
        let v4: G1Affine = (g * t4).into();

        (
            PublicKey {
                omega,
                g0,
                g1,
                h0,
                h1,
                v1,
                v2,
                v3,
                v4,
            },
            SecretKey {
                alpha,
                t1,
                t2,
                t3,
                t4,
            },
        )
    }

    /// Extract an user secret key for a given identity.
    fn extract_usk<R: Rng + CryptoRng>(
        opk: Option<&PublicKey>,
        sk: &SecretKey,
        v: &Identity,
        rng: &mut R,
    ) -> UserSecretKey {
        let pk = opk.unwrap();

        let h = G2Affine::generator();

        let r1 = rand_scalar(rng);
        let r2 = rand_scalar(rng);

        let id = hash_to_scalar(v);
        let x = pk.h0 + (pk.h1 * id);

        let d0: G2Affine = (h * (r1 * sk.t1 * sk.t2 + r2 * sk.t3 * sk.t4)).into();
        let d1: G2Affine = (h * (-sk.alpha * sk.t2) + x * (-r1 * sk.t2)).into();
        let d2: G2Affine = (h * (-sk.alpha * sk.t1) + x * (-r1 * sk.t1)).into();
        let d3: G2Affine = (x * (-r2 * sk.t4)).into();
        let d4: G2Affine = (x * (-r2 * sk.t3)).into();

        UserSecretKey {
            d: [d0, d1, d2, d3, d4],
        }
    }

    /// Generate a symmetric key and corresponding CipherText for that key.
    fn encrypt(pk: &PublicKey, v: &Identity, m: &Msg, rng_bytes: &Self::RngBytes) -> CipherText {
        let s = Scalar::from_bytes_wide(rng_bytes[0..64].try_into().unwrap());
        let s1 = Scalar::from_bytes_wide(rng_bytes[64..128].try_into().unwrap());
        let s2 = Scalar::from_bytes_wide(rng_bytes[128..192].try_into().unwrap());

        let id = hash_to_scalar(v);

        let cprime = pk.omega * s + m;
        let c0: G1Affine = ((pk.g0 + (pk.g1 * id)) * s).into();
        let c1: G1Affine = (pk.v1 * (s - s1)).into();
        let c2: G1Affine = (pk.v2 * s1).into();
        let c3: G1Affine = (pk.v3 * (s - s2)).into();
        let c4: G1Affine = (pk.v4 * s2).into();

        CipherText {
            c: [c0, c1, c2, c3, c4],
            cprime,
        }
    }

    /// Decrypt ciphertext to a SharedSecret using a user secret key.
    fn decrypt(usk: &UserSecretKey, ct: &CipherText) -> Msg {
        ct.cprime
            + multi_miller_loop(&[
                (&ct.c[0], &G2Prepared::from(usk.d[0])),
                (&ct.c[1], &G2Prepared::from(usk.d[1])),
                (&ct.c[2], &G2Prepared::from(usk.d[2])),
                (&ct.c[3], &G2Prepared::from(usk.d[3])),
                (&ct.c[4], &G2Prepared::from(usk.d[4])),
            ])
            .final_exponentiation()
    }
}

impl Compress for PublicKey {
    const OUTPUT_SIZE: usize = PK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; PK_BYTES] {
        let mut res = [0u8; PK_BYTES];
        let (omega, g0, g1, h0, h1, v1, v2, v3, v4) = mut_array_refs![
            &mut res, GT_BYTES, G1_BYTES, G1_BYTES, G2_BYTES, G2_BYTES, G1_BYTES, G1_BYTES,
            G1_BYTES, G1_BYTES
        ];

        *omega = self.omega.to_compressed();
        *g0 = self.g0.to_compressed();
        *g1 = self.g1.to_compressed();
        *h0 = self.h0.to_compressed();
        *h1 = self.h1.to_compressed();
        *v1 = self.v1.to_compressed();
        *v2 = self.v2.to_compressed();
        *v3 = self.v3.to_compressed();
        *v4 = self.v4.to_compressed();

        res
    }

    fn from_bytes(bytes: &[u8; PK_BYTES]) -> CtOption<Self> {
        let (omega, g0, g1, h0, h1, v1, v2, v3, v4) = array_refs![
            bytes, GT_BYTES, G1_BYTES, G1_BYTES, G2_BYTES, G2_BYTES, G1_BYTES, G1_BYTES, G1_BYTES,
            G1_BYTES
        ];
        // from_compressed_unchecked doesn't check whether the element has
        // a cofactor.  To mount an attack using a cofactor an attacker
        // must be able to manipulate the public parameters.  But then the
        // attacker can simply use parameters they generated themselves.
        // Thus checking for a cofactor is superfluous.

        let omega = Gt::from_compressed_unchecked(omega);
        let g0 = G1Affine::from_compressed_unchecked(g0);
        let g1 = G1Affine::from_compressed_unchecked(g1);
        let h0 = G2Affine::from_compressed_unchecked(h0);
        let h1 = G2Affine::from_compressed_unchecked(h1);
        let v1 = G1Affine::from_compressed_unchecked(v1);
        let v2 = G1Affine::from_compressed_unchecked(v2);
        let v3 = G1Affine::from_compressed_unchecked(v3);
        let v4 = G1Affine::from_compressed_unchecked(v4);

        omega.and_then(|omega| {
            g0.and_then(|g0| {
                g1.and_then(|g1| {
                    h0.and_then(|h0| {
                        h1.and_then(|h1| {
                            v1.and_then(|v1| {
                                v2.and_then(|v2| {
                                    v3.and_then(|v3| {
                                        v4.map(|v4| PublicKey {
                                            omega,
                                            g0,
                                            g1,
                                            h0,
                                            h1,
                                            v1,
                                            v2,
                                            v3,
                                            v4,
                                        })
                                    })
                                })
                            })
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
        let mut res = [0u8; SK_BYTES];
        let (alpha, t1, t2, t3, t4) = mut_array_refs![
            &mut res,
            SCALAR_BYTES,
            SCALAR_BYTES,
            SCALAR_BYTES,
            SCALAR_BYTES,
            SCALAR_BYTES
        ];

        *alpha = self.alpha.to_bytes();
        *t1 = self.t1.to_bytes();
        *t2 = self.t2.to_bytes();
        *t3 = self.t3.to_bytes();
        *t4 = self.t4.to_bytes();

        res
    }

    fn from_bytes(bytes: &[u8; SK_BYTES]) -> CtOption<Self> {
        let (alpha, t1, t2, t3, t4) = array_refs![
            bytes,
            SCALAR_BYTES,
            SCALAR_BYTES,
            SCALAR_BYTES,
            SCALAR_BYTES,
            SCALAR_BYTES
        ];

        let alpha = Scalar::from_bytes(alpha);
        let t1 = Scalar::from_bytes(t1);
        let t2 = Scalar::from_bytes(t2);
        let t3 = Scalar::from_bytes(t3);
        let t4 = Scalar::from_bytes(t4);

        alpha.and_then(|alpha| {
            t1.and_then(|t1| {
                t2.and_then(|t2| {
                    t3.and_then(|t3| {
                        t4.map(|t4| SecretKey {
                            alpha,
                            t1,
                            t2,
                            t3,
                            t4,
                        })
                    })
                })
            })
        })
    }
}

impl Compress for UserSecretKey {
    const OUTPUT_SIZE: usize = USK_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; USK_BYTES] {
        let mut res = [0u8; USK_BYTES];
        let (d0, d1, d2, d3, d4) =
            mut_array_refs![&mut res, G2_BYTES, G2_BYTES, G2_BYTES, G2_BYTES, G2_BYTES];

        *d0 = self.d[0].to_compressed();
        *d1 = self.d[1].to_compressed();
        *d2 = self.d[2].to_compressed();
        *d3 = self.d[3].to_compressed();
        *d4 = self.d[4].to_compressed();

        res
    }

    fn from_bytes(bytes: &[u8; USK_BYTES]) -> CtOption<Self> {
        let (d0, d1, d2, d3, d4) =
            array_refs![bytes, G2_BYTES, G2_BYTES, G2_BYTES, G2_BYTES, G2_BYTES];

        let d0 = G2Affine::from_compressed(d0);
        let d1 = G2Affine::from_compressed(d1);
        let d2 = G2Affine::from_compressed(d2);
        let d3 = G2Affine::from_compressed(d3);
        let d4 = G2Affine::from_compressed(d4);

        d0.and_then(|d0| {
            d1.and_then(|d1| {
                d2.and_then(|d2| {
                    d3.and_then(|d3| {
                        d4.map(|d4| UserSecretKey {
                            d: [d0, d1, d2, d3, d4],
                        })
                    })
                })
            })
        })
    }
}

impl Compress for CipherText {
    const OUTPUT_SIZE: usize = CT_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; CT_BYTES] {
        let mut res = [0u8; CT_BYTES];
        let (c0, c1, c2, c3, c4, cprime) =
            mut_array_refs![&mut res, G1_BYTES, G1_BYTES, G1_BYTES, G1_BYTES, G1_BYTES, GT_BYTES];

        *c0 = self.c[0].to_compressed();
        *c1 = self.c[1].to_compressed();
        *c2 = self.c[2].to_compressed();
        *c3 = self.c[3].to_compressed();
        *c4 = self.c[4].to_compressed();
        *cprime = self.cprime.to_compressed();

        res
    }

    fn from_bytes(bytes: &[u8; CT_BYTES]) -> CtOption<Self> {
        let (c0, c1, c2, c3, c4, cprime) =
            array_refs![bytes, G1_BYTES, G1_BYTES, G1_BYTES, G1_BYTES, G1_BYTES, GT_BYTES];

        let c0 = G1Affine::from_compressed(c0);
        let c1 = G1Affine::from_compressed(c1);
        let c2 = G1Affine::from_compressed(c2);
        let c3 = G1Affine::from_compressed(c3);
        let c4 = G1Affine::from_compressed(c4);
        let cprime = Gt::from_compressed(cprime);

        c0.and_then(|c0| {
            c1.and_then(|c1| {
                c2.and_then(|c2| {
                    c3.and_then(|c3| {
                        c4.and_then(|c4| {
                            cprime.map(|cprime| CipherText {
                                c: [c0, c1, c2, c3, c4],
                                cprime,
                            })
                        })
                    })
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    test_ibe!(BoyenWaters);
}