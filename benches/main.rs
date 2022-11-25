use criterion::{black_box, criterion_group, criterion_main, Criterion};
use paste::paste;
use std::time::Duration;

macro_rules! impl_bench_kem {
    ($scheme: ident, $struct: ident, { $pk: ident, $sk: ident, $usk: ident }, { $ep: expr, $dp: expr }) => {
        paste! {
            fn [<bench_kem_ $scheme>](criterion: &mut Criterion) {
                use ibe::kem::$scheme::*;
                use ibe::{kem::IBKEM};

                let mut rng = rand::thread_rng();

                let id = <$struct as IBKEM>::Id::from("email:w.geraedts@sarif.nl");
                let ($pk, $sk) = $struct::setup(&mut rng);
                let $usk = $struct::extract_usk($ep, &id, &mut rng);
                let (c, _k) = $struct::encaps(&$pk, &id, &mut rng);

                criterion.bench_function(
                    &format!("kem_{} setup", stringify!($scheme)).to_string(),
                    |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| $struct::setup(&mut rng))
                    },
                );
                criterion.bench_function(
                    &format!("kem_{} extract", stringify!($scheme)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| {
                            $struct::extract_usk(
                                black_box($ep),
                                black_box(&id),
                                &mut rng,
                            )
                        })
                    },
                );
                criterion.bench_function(
                    &format!("kem_{} encaps", stringify!($scheme)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| $struct::encaps(black_box(&$pk), black_box(&id), &mut rng))
                    },
                );
                criterion.bench_function(
                    &format!("kem_{} decaps", stringify!($scheme)).to_string(),
                    move |b| {
                        b.iter(|| {
                            $struct::decaps(black_box($dp), black_box(&c))
                        })
                    },
                );
            }
        }
    };
}

macro_rules! impl_bench_multi_kem {
    ($scheme: ident, $struct: ident) => {
        paste! {
            fn [<bench_multi_kem_ $scheme>](criterion: &mut Criterion) {
                use ibe::kem::$scheme::*;
                use ibe::kem::mkem::{MultiRecipient, MultiRecipientCiphertext};
                use ibe::{kem::IBKEM};
                use std::vec::Vec;

                let mut rng = rand::thread_rng();
                let id = <$struct as IBKEM>::Id::from("email:l.botros@cs.ru.nl");
                let ids = [id; 10];
                let (pk, _) = $struct::setup(&mut rng);

                // We only benchmark multi-encaps.
                criterion.bench_function(
                    &format!("kem_{} multi-encaps x10", stringify!($scheme)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| {
                            let (iter, _) = $struct::multi_encaps(
                                black_box(&pk),
                                black_box(&ids),
                                &mut rng
                            );
                            let _: Vec<MultiRecipientCiphertext<$struct>> = iter.collect();
                        })
                    },
                );
            }
        }
    };
}

macro_rules! impl_bench_ibe {
    ($scheme: ident, $struct: ident, { $pk: ident, $sk: ident, $usk: ident }, { $ep: expr, $dp: expr }) => {
        paste! {
            fn [<bench_ibe_ $scheme>](criterion: &mut Criterion) {
                use group::Group;
                use ibe::ibe::$scheme::*;
                use ibe::{ibe::IBE};
                use rand::RngCore;

                let mut rng = rand::thread_rng();

                let id = <$struct as IBE>::Id::from("email:w.geraedts@sarif.nl");
                let ($pk, $sk) = $struct::setup(&mut rng);
                let $usk = $struct::extract_usk($ep, &id, &mut rng);
                let m = <$struct as IBE>::Msg::random(&mut rng);
                type Rng = <$struct as IBE>::RngBytes;
                let mut rand_bytes: Rng = [0u8; core::mem::size_of::<Rng>()];
                rng.fill_bytes(&mut rand_bytes);
                let c = $struct::encrypt(&$pk, &id, &m, &rand_bytes);

                criterion.bench_function(
                    &format!("ibe_{} setup", stringify!($scheme)).to_string(),
                    |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| $struct::setup(&mut rng))
                    },
                );
                criterion.bench_function(
                    &format!("ibe_{} extract", stringify!($scheme)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| {
                            $struct::extract_usk(
                                black_box($ep),
                                black_box(&id),
                                &mut rng,
                            )
                        })
                    },
                );
                criterion.bench_function(
                    &format!("ibe_{} encrypt", stringify!($scheme)).to_string(),
                    move |b| {
                        b.iter(|| {
                            $struct::encrypt(
                                black_box(&$pk),
                                black_box(&id),
                                black_box(&m),
                                black_box(&rand_bytes),
                            )
                        })
                    },
                );
                criterion.bench_function(
                    &format!("ibe_{} decrypt", stringify!($scheme)).to_string(),
                    move |b| b.iter(|| $struct::decrypt(black_box(&$dp), black_box(&c))),
                );
            }
        }
    };
}

impl_bench_kem!(kiltz_vahlis_one, KV1, { pk, sk, usk }, { (&pk, &sk), &usk });
impl_bench_kem!(cgw_kv, CGWKV, { pk, sk, usk }, { &sk, &usk });
impl_bench_kem!(cgw_fo, CGWFO, { pk, sk, usk }, { &sk, (&pk, &usk) });

impl_bench_multi_kem!(kiltz_vahlis_one, KV1);
impl_bench_multi_kem!(cgw_kv, CGWKV);
impl_bench_multi_kem!(cgw_fo, CGWFO);

impl_bench_ibe!(boyen_waters, BoyenWaters, { pk, sk, usk }, { (&pk, &sk), &usk });
impl_bench_ibe!(cgw, CGW, { pk, sk, usk }, { &sk, &usk });
impl_bench_ibe!(waters, Waters, { pk, sk, usk }, { (&pk, &sk), &usk });
impl_bench_ibe!(waters_naccache, WatersNaccache, { pk, sk, usk }, { (&pk, &sk), &usk });

criterion_group!(
    name = kem_benches;
    config = Criterion::default().warm_up_time(Duration::new(0, 500));
    targets =
    bench_kem_kiltz_vahlis_one,
    bench_kem_cgw_fo,
    bench_kem_cgw_kv,
    bench_multi_kem_kiltz_vahlis_one,
    bench_multi_kem_cgw_kv,
    bench_multi_kem_cgw_fo,
);

criterion_group!(
    name = multi_kem_benches;
    config = Criterion::default().warm_up_time(Duration::new(0, 500));
    targets =
    bench_multi_kem_kiltz_vahlis_one,
    bench_multi_kem_cgw_kv,
    bench_multi_kem_cgw_fo,
);

criterion_group!(
    name = ibe_benches;
    config = Criterion::default().warm_up_time(Duration::new(0, 500));
    targets =
    bench_ibe_waters,
    bench_ibe_waters_naccache,
    bench_ibe_boyen_waters,
    bench_ibe_cgw,
);

criterion_main!(kem_benches, multi_kem_benches, ibe_benches);
