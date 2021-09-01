//! Fully-secure Identity Based Encryption by Chen, Gay and Wee.
//! * From: "[Improved Dual System ABE in Prime-Order Groups via Predicate Encodings](https://link.springer.com/chapter/10.1007/978-3-540-79263-5_14)"
//!
//! CCA security due to a general approach by Fujisaki and Okamoto.
//! * From: "[A Modular Analysis of the Fujisaki-Okamoto Transformation](https://eprint.iacr.org/2017/604.pdf)"
//!
//! Symmetric primitives G and H instantiated using sha3_512 and sha3_256, respectively.
//! To output a bigger secret SHAKE256 can be used for example.
//!
//! A drawback of a Fujisaki-Okamoto transform is that we now need the public key to decapsulate :(

use crate::pke::cgw_cpa::{
    decrypt, encrypt, CipherText, Message, MSG_BYTES, N_BYTE_LEN, USK_BYTES,
};
use arrayref::{array_refs, mut_array_refs};
use rand::Rng;
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};
use tiny_keccak::{Hasher, Sha3};

// These struct are identical for the CCA KEM
pub use crate::pke::cgw_cpa::{Identity, PublicKey, SecretKey};

// The USK includes a random message and the identity (needed for re-encryption)
const CCA_USK_BYTES: usize = USK_BYTES + MSG_BYTES + N_BYTE_LEN;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedSecret([u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UserSecretKey {
    usk: crate::pke::cgw_cpa::UserSecretKey,
    s: Message,
    id: Identity,
}

impl UserSecretKey {
    pub fn to_bytes(&self) -> [u8; CCA_USK_BYTES] {
        let mut buf = [0u8; CCA_USK_BYTES];
        let (usk, s, id) = mut_array_refs![&mut buf, USK_BYTES, MSG_BYTES, N_BYTE_LEN];

        *usk = self.usk.to_bytes();
        *s = self.s.to_bytes();
        id.copy_from_slice(&self.id.0);

        buf
    }

    pub fn from_bytes(bytes: &[u8; CCA_USK_BYTES]) -> CtOption<Self> {
        let (usk, s, id) = array_refs![&bytes, USK_BYTES, MSG_BYTES, N_BYTE_LEN];

        let usk = crate::pke::cgw_cpa::UserSecretKey::from_bytes(usk);
        let s = Message::from_bytes(s);

        usk.and_then(|usk| {
            s.map(|s| UserSecretKey {
                usk,
                s,
                id: crate::pke::cgw_cpa::Identity(*id),
            })
        })
    }
}

pub fn setup<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
    crate::pke::cgw_cpa::setup(rng)
}

pub fn extract_usk<R: Rng>(sk: &SecretKey, id: &Identity, rng: &mut R) -> UserSecretKey {
    let usk = crate::pke::cgw_cpa::extract_usk(sk, id, rng);

    // include a random message to return in case of decapsulation failure
    let s = Message::random(rng);

    UserSecretKey { usk, s, id: *id }
}

pub fn encaps<R: Rng>(pk: &PublicKey, id: &Identity, rng: &mut R) -> (CipherText, SharedSecret) {
    // Generate a random message in the message space of the PKE
    let m = Message::random(rng);

    // encrypt() takes 64 bytes of randomness in this case
    // deterministically generate the randomness as G(m, id)
    // the message using G = sha3_512
    let mut g = Sha3::v512();
    let mut coins = [0u8; 64];
    g.update(&m.to_bytes());
    g.update(&id.0);
    g.finalize(&mut coins);

    // encrypt the message using deterministic randomness
    let c = encrypt(pk, id, &m, &coins);

    // output the shared secret as H(m, c) using H = sha3_256
    let mut h = Sha3::v256();
    let mut k = [0u8; 32];
    h.update(&m.to_bytes());
    h.update(&c.to_bytes());
    h.finalize(&mut k);

    (c, SharedSecret(k))
}

pub fn decaps(pk: &PublicKey, usk: &UserSecretKey, c: &CipherText) -> SharedSecret {
    // Attempt to decrypt the message from the ciphertext
    let mut m = decrypt(&usk.usk, c);

    // Regenerate the deterministic randomness as G(m, id)
    let mut g = Sha3::v512();
    let mut coins = [0u8; 64];
    g.update(&m.to_bytes());
    g.update(&usk.id.0);
    g.finalize(&mut coins);

    // Re-encrypt the message
    let c2 = encrypt(pk, &usk.id, &m, &coins);

    // If the ciphertexts were unequal, return H(s, c), otherwise H(m, c)
    m.conditional_assign(&usk.s, !c.ct_eq(&c2));

    let mut h = Sha3::v256();
    let mut k = [0u8; 32];
    h.update(&m.to_bytes());
    h.update(&c.to_bytes());
    h.finalize(&mut k);

    SharedSecret(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &'static [u8] = b"email:w.geraedts@sarif.nl";

    #[allow(dead_code)]
    struct DefaultSubResults {
        pk: PublicKey,
        id: Identity,
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

        DefaultSubResults {
            pk,
            id: kid,
            sk,
            usk,
            c,
            ss,
        }
    }

    #[test]
    fn eq_encaps_decaps() {
        let results = perform_default();
        let ss2 = decaps(&results.pk, &results.usk, &results.c);

        assert_eq!(results.ss, ss2);
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
