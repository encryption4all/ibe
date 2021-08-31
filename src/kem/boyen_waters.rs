//! Boyen & Waters IBE scheme: https://link.springer.com/content/pdf/10.1007/11818175_17.pdf
//!
//! The structure of the byte serialisation of the various datastructures is not guaranteed
//! to remain constant between releases of this library.
//! All operations in this library are implemented to run in constant time.

use crate::util::*;
use arrayref::{array_refs, mut_array_refs};
use irmaseal_curve::{multi_miller_loop, pairing, G1Affine, G2Affine, G2Prepared, Gt, Scalar};
use rand::Rng;
use subtle::CtOption;

const K: usize = 256;
const N: usize = 2 * K;
const N_BYTE_LEN: usize = N / 8;

const G1_SIZE: usize = 48;
const G2_SIZE: usize = 96;
const GT_SIZE: usize = 288;
const SCALAR_SIZE: usize = 32;

const PUBLICKEYSIZE: usize = 6 * G1_SIZE + 2 * G2_SIZE + GT_SIZE;
const SECRETKEYSIZE: usize = 5 * SCALAR_SIZE;
const USERSECRETKEYSIZE: usize = 5 * G2_SIZE;
const CIPHERTEXTSIZE: usize = 5 * G1_SIZE;

/// Public key parameters generated by the PKG used to encrypt messages.
#[derive(Clone, Copy, PartialEq)]
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
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SecretKey {
    alpha: Scalar,
    t1: Scalar,
    t2: Scalar,
    t3: Scalar,
    t4: Scalar,
}

/// Points on the paired curves that form the user secret key.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct UserSecretKey {
    d: [G2Affine; 5],
}

/// Byte representation of an identity.
///
/// Can be hashed to the curve together with some parameters from the Public Key.
pub struct Identity([u8; N_BYTE_LEN]);

/// Encrypted message. Can only be decrypted with an user secret key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CipherText {
    c: [G1Affine; 5],
}

/// A point on the paired curve that can be encrypted and decrypted.
///
/// You can use the byte representation to derive an AES key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SymmetricKey(Gt);

/// Generate a keypair used by the Private Key Generator (PKG).
pub fn setup<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
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

fn hash_to_scalar(v: &Identity) -> Scalar {
    Scalar::from_bytes_wide(&v.0)
}

/// Extract an user secret key for a given identity.
pub fn extract_usk<R: Rng>(
    pk: &PublicKey,
    sk: &SecretKey,
    v: &Identity,
    rng: &mut R,
) -> UserSecretKey {
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
pub fn encrypt<R: Rng>(pk: &PublicKey, v: &Identity, rng: &mut R) -> (CipherText, SymmetricKey) {
    let s = rand_scalar(rng);
    let s1 = rand_scalar(rng);
    let s2 = rand_scalar(rng);

    let id = hash_to_scalar(v);

    // We use omega^s directly as shared secret
    let cprime = pk.omega * s;
    let c0: G1Affine = ((pk.g0 + (pk.g1 * id)) * s).into();
    let c1: G1Affine = (pk.v1 * (s - s1)).into();
    let c2: G1Affine = (pk.v2 * s1).into();
    let c3: G1Affine = (pk.v3 * (s - s2)).into();
    let c4: G1Affine = (pk.v4 * s2).into();

    (
        CipherText {
            c: [-c0, -c1, -c2, -c3, -c4],
        },
        SymmetricKey(cprime),
    )
}

/// Decrypt ciphertext to a SymmetricKey using a user secret key.
pub fn decrypt(usk: &UserSecretKey, ct: &CipherText) -> SymmetricKey {
    let m = multi_miller_loop(&[
        (&ct.c[0], &G2Prepared::from(usk.d[0])),
        (&ct.c[1], &G2Prepared::from(usk.d[1])),
        (&ct.c[2], &G2Prepared::from(usk.d[2])),
        (&ct.c[3], &G2Prepared::from(usk.d[3])),
        (&ct.c[4], &G2Prepared::from(usk.d[4])),
    ])
    .final_exponentiation();

    SymmetricKey(m)
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

impl SymmetricKey {
    pub fn to_bytes(&self) -> [u8; GT_SIZE] {
        self.0.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; GT_SIZE]) -> CtOption<Self> {
        Gt::from_compressed(bytes).map(Self)
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; PUBLICKEYSIZE] {
        let mut res = [0u8; PUBLICKEYSIZE];
        let (omega, g0, g1, h0, h1, v1, v2, v3, v4) = mut_array_refs![
            &mut res, GT_SIZE, G1_SIZE, G1_SIZE, G2_SIZE, G2_SIZE, G1_SIZE, G1_SIZE, G1_SIZE,
            G1_SIZE
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

    pub fn from_bytes(bytes: &[u8; PUBLICKEYSIZE]) -> CtOption<Self> {
        let (omega, g0, g1, h0, h1, v1, v2, v3, v4) = array_refs![
            bytes, GT_SIZE, G1_SIZE, G1_SIZE, G2_SIZE, G2_SIZE, G1_SIZE, G1_SIZE, G1_SIZE, G1_SIZE
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

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; SECRETKEYSIZE] {
        let mut res = [0u8; SECRETKEYSIZE];
        let (alpha, t1, t2, t3, t4) = mut_array_refs![
            &mut res,
            SCALAR_SIZE,
            SCALAR_SIZE,
            SCALAR_SIZE,
            SCALAR_SIZE,
            SCALAR_SIZE
        ];

        *alpha = self.alpha.to_bytes();
        *t1 = self.t1.to_bytes();
        *t2 = self.t2.to_bytes();
        *t3 = self.t3.to_bytes();
        *t4 = self.t4.to_bytes();

        res
    }

    pub fn from_bytes(bytes: &[u8; SECRETKEYSIZE]) -> CtOption<Self> {
        let (alpha, t1, t2, t3, t4) = array_refs![
            bytes,
            SCALAR_SIZE,
            SCALAR_SIZE,
            SCALAR_SIZE,
            SCALAR_SIZE,
            SCALAR_SIZE
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

impl UserSecretKey {
    pub fn to_bytes(&self) -> [u8; USERSECRETKEYSIZE] {
        let mut res = [0u8; USERSECRETKEYSIZE];
        let (d0, d1, d2, d3, d4) =
            mut_array_refs![&mut res, G2_SIZE, G2_SIZE, G2_SIZE, G2_SIZE, G2_SIZE];

        *d0 = self.d[0].to_compressed();
        *d1 = self.d[1].to_compressed();
        *d2 = self.d[2].to_compressed();
        *d3 = self.d[3].to_compressed();
        *d4 = self.d[4].to_compressed();

        res
    }

    pub fn from_bytes(bytes: &[u8; USERSECRETKEYSIZE]) -> CtOption<Self> {
        let (d0, d1, d2, d3, d4) = array_refs![bytes, G2_SIZE, G2_SIZE, G2_SIZE, G2_SIZE, G2_SIZE];

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

impl CipherText {
    pub fn to_bytes(&self) -> [u8; CIPHERTEXTSIZE] {
        let mut res = [0u8; CIPHERTEXTSIZE];
        let (c0, c1, c2, c3, c4) =
            mut_array_refs![&mut res, G1_SIZE, G1_SIZE, G1_SIZE, G1_SIZE, G1_SIZE];

        *c0 = self.c[0].to_compressed();
        *c1 = self.c[1].to_compressed();
        *c2 = self.c[2].to_compressed();
        *c3 = self.c[3].to_compressed();
        *c4 = self.c[4].to_compressed();

        res
    }

    pub fn from_bytes(bytes: &[u8; CIPHERTEXTSIZE]) -> CtOption<Self> {
        let (c0, c1, c2, c3, c4) = array_refs![bytes, G1_SIZE, G1_SIZE, G1_SIZE, G1_SIZE, G1_SIZE];

        let c0 = G1Affine::from_compressed(c0);
        let c1 = G1Affine::from_compressed(c1);
        let c2 = G1Affine::from_compressed(c2);
        let c3 = G1Affine::from_compressed(c3);
        let c4 = G1Affine::from_compressed(c4);

        c0.and_then(|c0| {
            c1.and_then(|c1| {
                c2.and_then(|c2| {
                    c3.and_then(|c3| {
                        c4.map(|c4| CipherText {
                            c: [c0, c1, c2, c3, c4],
                        })
                    })
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &'static str = "email:w.geraedts@sarif.nl";

    #[allow(dead_code)]
    struct DefaultSubResults {
        kid: Identity,
        pk: PublicKey,
        sk: SecretKey,
        usk: UserSecretKey,
        c: CipherText,
        k: SymmetricKey,
    }

    fn perform_default() -> DefaultSubResults {
        let mut rng = rand::thread_rng();

        let id = ID.as_bytes();
        let kid = Identity::derive(id);

        let (pk, sk) = setup(&mut rng);
        let usk = extract_usk(&pk, &sk, &kid, &mut rng);

        let (c, k) = encrypt(&pk, &kid, &mut rng);

        DefaultSubResults {
            kid,
            pk,
            sk,
            usk,
            c,
            k,
        }
    }

    #[test]
    fn eq_encrypt_decrypt() {
        let results = perform_default();
        let k2 = decrypt(&results.usk, &results.c);

        assert_eq!(results.k, k2);
    }

    #[test]
    fn eq_serialize_deserialize() {
        let result = perform_default();

        assert_eq!(
            result.k,
            SymmetricKey::from_bytes(&result.k.to_bytes()).unwrap()
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