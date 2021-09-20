use group::{ff::Field, Group};
use irmaseal_curve::{G1Projective, G2Projective, Scalar};
use rand::RngCore;
use tiny_keccak::Hasher;

#[inline(always)]
pub fn rand_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
}

#[inline(always)]
pub fn rand_g1<R: RngCore>(rng: &mut R) -> G1Projective {
    G1Projective::random(rng)
}

#[inline(always)]
pub fn rand_g2<R: RngCore>(rng: &mut R) -> G2Projective {
    G2Projective::random(rng)
}

pub fn bits<'a>(slice: &'a [u8]) -> impl Iterator<Item = subtle::Choice> + 'a {
    slice
        .iter()
        .rev()
        .zip((0..8).rev())
        .map(|(x, i)| subtle::Choice::from((*x >> i) & 1))
}

pub fn sha3_256(slice: &[u8]) -> [u8; 32] {
    let mut digest = tiny_keccak::Sha3::v256();
    digest.update(slice);

    let mut buf = [0u8; 32];
    digest.finalize(&mut buf);

    buf
}

pub fn sha3_512(slice: &[u8]) -> [u8; 64] {
    let mut digest = tiny_keccak::Sha3::v512();
    digest.update(slice);

    let mut buf = [0u8; 64];
    digest.finalize(&mut buf);

    buf
}

#[cfg(test)]
#[macro_use]
mod test_macros {
    macro_rules! test_kem {
        ($name: ident) => {
            use super::*;

            const ID1: &'static str = "email:w.geraedts@sarif.nl";
            #[allow(dead_code)]
            const ID2: &'static str = "email:l.botros@cs.ru.nl";

            #[allow(dead_code)]
            struct DefaultSubResults {
                kid: Identity,
                pk: PublicKey,
                sk: SecretKey,
                usk: UserSecretKey,
                c: CipherText,
                k: SharedSecret,
            }

            fn perform_default() -> DefaultSubResults {
                let mut rng = rand::thread_rng();
                let id = ID1.as_bytes();
                let kid = Identity::derive(id);
                let (pk, sk) = $name::setup(&mut rng);
                let usk = $name::extract_usk(Some(&pk), &sk, &kid, &mut rng);
                let (c, k) = $name::encaps(&pk, &kid, &mut rng);

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
            fn eq_encaps_decaps() {
                let results = perform_default();
                let k2 = $name::decaps(Some(&results.pk), &results.usk, &results.c);

                assert_eq!(results.k, k2);
            }

            #[test]
            fn eq_multi_encaps_decaps() {
                let mut rng = rand::thread_rng();
                let ids = [ID1.as_bytes(), ID2.as_bytes()];
                let kid = [Identity::derive(ids[0]), Identity::derive(ids[1])];

                let (pk, sk) = $name::setup(&mut rng);
                let usk1 = $name::extract_usk(Some(&pk), &sk, &kid[0], &mut rng);
                let usk2 = $name::extract_usk(Some(&pk), &sk, &kid[1], &mut rng);

                let (cts, k) = $name::multi_encaps::<_, 2>(&pk, &[&kid[0], &kid[1]], &mut rng);

                let k1 = $name::decaps(Some(&pk), &usk1, &cts[0]);
                let k2 = $name::decaps(Some(&pk), &usk2, &cts[1]);

                assert!(k == k1 && k == k2);
                assert_ne!(cts[0], cts[1])
            }

            #[test]
            fn eq_serialize_deserialize() {
                let result = perform_default();

                assert_eq!(
                    result.k,
                    SharedSecret::from_bytes(&result.k.to_bytes()).unwrap()
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
        };
    }

    macro_rules! test_ibe {
        ($name: ident) => {
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

                let (pk, sk) = $name::setup(&mut rng);
                let usk = $name::extract_usk(Some(&pk), &sk, &kid, &mut rng);

                let m = Message::random(&mut rng);

                type Rng = <$name as IBE>::RngBytes;
                let mut rand_bytes: Rng = [0u8; core::mem::size_of::<Rng>()];
                rng.fill_bytes(&mut rand_bytes);

                let c = $name::encrypt(&pk, &kid, &m, &rand_bytes);

                DefaultSubResults { pk, sk, usk, c, m }
            }

            #[test]
            fn eq_encrypt_decrypt() {
                let results = perform_default();
                let m2 = $name::decrypt(&results.usk, &results.c);

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
        };
    }
}
