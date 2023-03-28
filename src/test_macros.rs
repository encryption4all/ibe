macro_rules! test_kem {
    ($name: ident) => {
        const ID1: &'static str = "email:w.geraedts@sarif.nl";

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
            let kid = <$name as IBKEM>::Id::derive_str(ID1);
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
            let k2 = <$name as IBKEM>::decaps(Some(&results.pk), &results.usk, &results.c).unwrap();

            assert_eq!(results.k, k2);
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

macro_rules! test_multi_kem {
    ($name: ident) => {
        #[test]
        fn eq_multi_encaps_decaps() {
            use crate::kem::mkem::{Ciphertext, MultiRecipient};
            use rayon::iter::IndexedParallelIterator;
            use rayon::prelude::*;

            let mut rng = rand::thread_rng();

            let id1 = "email:w.geraedts@sarif.nl";
            let id2 = "email:l.botros@cs.ru.nl";

            let kid = [
                <$name as IBKEM>::Id::derive_str(id1),
                <$name as IBKEM>::Id::derive_str(id2),
            ];

            let (pk, sk) = $name::setup(&mut rng);

            let usk1 = $name::extract_usk(Some(&pk), &sk, &kid[0], &mut rng);
            let usk2 = $name::extract_usk(Some(&pk), &sk, &kid[1], &mut rng);

            let usks = [usk1, usk2];

            let (cts, k) = $name::multi_encaps_par(&pk, &kid, &mut rng);

            cts.enumerate().for_each(|(i, ct)| {
                let compressed = ct.to_bytes();
                let decompressed = Ciphertext::<$name>::from_bytes(&compressed).unwrap();

                let k_i = $name::multi_decaps(Some(&pk), &usks[i], &decompressed).unwrap();
                assert_eq!(k, k_i);
            });

            assert_ne!(k, SharedSecret([0u8; 32]));
        }
    };
}

macro_rules! test_ibe {
    ($name: ident) => {
        use super::*;
        use crate::Derive;

        const ID: &'static [u8] = b"email:w.geraedts@sarif.nl";

        #[allow(dead_code)]
        struct DefaultSubResults {
            pk: PublicKey,
            sk: SecretKey,
            usk: UserSecretKey,
            c: CipherText,
            m: Msg,
        }

        fn perform_default() -> DefaultSubResults {
            use group::Group;
            use rand::RngCore;

            let mut rng = rand::thread_rng();

            let kid = <$name as IBE>::Id::derive(ID);

            let (pk, sk) = $name::setup(&mut rng);
            let usk = $name::extract_usk(Some(&pk), &sk, &kid, &mut rng);

            let m = Msg::random(&mut rng);

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
