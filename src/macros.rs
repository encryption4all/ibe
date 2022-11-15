macro_rules! test_ibe {
    ($scheme: ident, { $pk: ident, $sk: ident, $usk: ident }, { $ep: expr, $dp: expr }) => {
        use group::Group;

        #[test]
        fn test_encrypt_decrypt() {
            let mut rng = rand::thread_rng();
            let id = <$scheme as IBE>::Id::from("email:w.geraedts@sarif.nl");
            let ($pk, $sk) = $scheme::setup(&mut rng);
            let $usk = $scheme::extract_usk($ep, &id, &mut rng);
            let m = Msg::random(&mut rng);
            type Rng = <$scheme as IBE>::RngBytes;
            let mut rand_bytes: Rng = [0u8; core::mem::size_of::<Rng>()];
            rng.fill_bytes(&mut rand_bytes);
            let c = $scheme::encrypt(&$pk, &id, &m, &rand_bytes);
            let m2 = $scheme::decrypt($dp, &c);

            assert_eq!(m, m2);
        }

        #[test]
        fn test_eq_serialize_deserialize() {
            let mut rng = rand::thread_rng();
            let id = <$scheme as IBE>::Id::from("email:w.geraedts@sarif.nl");
            let ($pk, $sk) = $scheme::setup(&mut rng);
            let $usk = $scheme::extract_usk($ep, &id, &mut rng);
            let m = Msg::random(&mut rng);
            type Rng = <$scheme as IBE>::RngBytes;
            let mut rand_bytes: Rng = [0u8; core::mem::size_of::<Rng>()];
            rng.fill_bytes(&mut rand_bytes);
            let c = $scheme::encrypt(&$pk, &id, &m, &rand_bytes);

            assert_eq!(
                $pk.to_bytes().as_ref(),
                PublicKey::from_bytes(&$pk.to_bytes())
                    .unwrap()
                    .to_bytes()
                    .as_ref()
            );
            assert_eq!(
                $sk.to_bytes().as_ref(),
                SecretKey::from_bytes(&$sk.to_bytes())
                    .unwrap()
                    .to_bytes()
                    .as_ref()
            );
            assert_eq!(
                $usk.to_bytes().as_ref(),
                UserSecretKey::from_bytes(&$usk.to_bytes())
                    .unwrap()
                    .to_bytes()
                    .as_ref()
            );
            assert_eq!(
                c.to_bytes().as_ref(),
                CipherText::from_bytes(&c.to_bytes())
                    .unwrap()
                    .to_bytes()
                    .as_ref()
            );
        }
    };
}

macro_rules! test_kem {
    ($scheme: ident, { $pk: ident, $sk: ident, $usk: ident }, { $ep: expr, $dp: expr }) => {
        #[test]
        fn test_encaps_decaps() {
            let mut rng = rand::thread_rng();
            let id = Identity::from("email:w.geraedts@sarif.nl");
            let ($pk, $sk) = $scheme::setup(&mut rng);
            let $usk = $scheme::extract_usk($ep, &id, &mut rng);
            let (c, k) = $scheme::encaps(&$pk, &id, &mut rng);
            let k2 = $scheme::decaps($dp, &c).unwrap();

            assert_eq!(k, k2);
        }

        #[test]
        fn test_eq_serialize_deserialize() {
            let mut rng = rand::thread_rng();
            let id = Identity::from("email:w.geraedts@sarif.nl");
            let ($pk, $sk) = $scheme::setup(&mut rng);
            let $usk = $scheme::extract_usk($ep, &id, &mut rng);
            let (c, _) = $scheme::encaps(&$pk, &id, &mut rng);

            assert_eq!(
                $pk.to_bytes().as_ref(),
                PublicKey::from_bytes(&$pk.to_bytes())
                    .unwrap()
                    .to_bytes()
                    .as_ref()
            );
            assert_eq!(
                $sk.to_bytes().as_ref(),
                SecretKey::from_bytes(&$sk.to_bytes())
                    .unwrap()
                    .to_bytes()
                    .as_ref()
            );
            assert_eq!(
                $usk.to_bytes().as_ref(),
                UserSecretKey::from_bytes(&$usk.to_bytes())
                    .unwrap()
                    .to_bytes()
                    .as_ref()
            );
            assert_eq!(
                c.to_bytes().as_ref(),
                CipherText::from_bytes(&c.to_bytes())
                    .unwrap()
                    .to_bytes()
                    .as_ref()
            );
        }
    };
}

macro_rules! test_multi_kem {
    ($scheme: ident, { $pk: ident, $sk: ident, $usks: ident, $i: ident }, { $ep: expr, $dp: expr }) => {
        #[test]
        fn eq_multi_encaps_decaps() {
            use crate::kem::mkem::MultiRecipient;
            use std::vec::Vec;

            let mut rng = rand::thread_rng();

            let ids = [
                Identity::from("email:w.geraedts@sarif.nl"),
                Identity::from("email:l.botros@cs.ru.nl"),
            ];

            let ($pk, $sk) = $scheme::setup(&mut rng);

            let $usks: Vec<<$scheme as IBKEM>::Usk> = ids
                .iter()
                .map(|id| $scheme::extract_usk($ep, &id, &mut rng))
                .collect();

            let (cts, k) = $scheme::multi_encaps(&$pk, &ids, &mut rng);

            for ($i, ct) in cts.enumerate() {
                let k_i = $scheme::multi_decaps($dp, &ct).unwrap();
                assert_eq!(k, k_i);
            }

            assert_ne!(k, SharedSecret([0u8; 32]));
        }
    };
}
