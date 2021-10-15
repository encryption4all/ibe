use criterion::{black_box, criterion_group, criterion_main, Criterion};
use paste::paste;
use std::time::Duration;

macro_rules! bench_kem {
    ($scheme: ident, $struct: ident) => {
        paste! {
            fn [<bench_kem_ $scheme>](criterion: &mut Criterion) {
                use ibe::kem::$scheme::*;
                use ibe::{kem::IBKEM, Compress, Derive};

                let mut rng = rand::thread_rng();

                let id = "email:w.geraedts@sarif.nl".as_bytes();
                let kid = <$struct as IBKEM>::Id::derive(id);

                let (pk, sk) = $struct::setup(&mut rng);
                let usk = $struct::extract_usk(Some(&pk), &sk, &kid, &mut rng);

                let ppk = pk.to_bytes();
                criterion.bench_function(
                    &format!("kem_{} unpack_pk", stringify!($scheme)).to_string(),
                    |b| b.iter(|| PublicKey::from_bytes(&ppk)),
                );

                let (c, _k) = $struct::encaps(&pk, &kid, &mut rng);

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
                                black_box(Some(&pk)),
                                black_box(&sk),
                                black_box(&kid),
                                &mut rng,
                            )
                        })
                    },
                );
                criterion.bench_function(
                    &format!("kem_{} encaps", stringify!($scheme)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| $struct::encaps(black_box(&pk), black_box(&kid), &mut rng))
                    },
                );
                criterion.bench_function(
                    &format!("kem_{} decaps", stringify!($scheme)).to_string(),
                    move |b| {
                        b.iter(|| {
                            $struct::decaps(black_box(Some(&pk)), black_box(&usk), black_box(&c))
                        })
                    },
                );
            }
        }
    };
}

macro_rules! bench_multi_kem {
    ($scheme: ident, $struct: ident) => {
        paste! {
            fn [<bench_multi_kem_ $scheme>](criterion: &mut Criterion) {
                use ibe::kem::$scheme::*;
                use ibe::{kem::IBKEM, Derive};

                let mut rng = rand::thread_rng();

                let id = "email:w.geraedts@sarif.nl".as_bytes();
                let kid = <$struct as IBKEM>::Id::derive(id);

                let (pk, _sk) = $struct::setup(&mut rng);

                criterion.bench_function(
                    &format!("kem_{} multi-encaps x10", stringify!($scheme)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| {
                            $struct::multi_encaps(black_box(&pk), black_box(&[&kid; 10]), &mut rng)
                        })
                    },
                );
            }
        }
    };
}

macro_rules! bench_ibe {
    ($scheme: ident, $struct: ident) => {
        paste! {
            fn [<bench_ibe_ $scheme>](criterion: &mut Criterion) {
                use group::Group;
                use ibe::pke::$scheme::*;
                use ibe::{pke::IBE, Derive};
                use rand::RngCore;

                let mut rng = rand::thread_rng();

                let id = "email:w.geraedts@sarif.nl".as_bytes();
                let kid = <$struct as IBE>::Id::derive(id);

                let (pk, sk) = $struct::setup(&mut rng);
                let usk = $struct::extract_usk(Some(&pk), &sk, &kid, &mut rng);

                // let ppk = pk.to_bytes();
                // criterion.bench_function(
                //     &format!("ibe_{} unpack_pk", stringify!($scheme)).to_string(),
                //     |b| b.iter(|| PublicKey::from_bytes(&ppk)),
                // );

                let m = <$struct as IBE>::Msg::random(&mut rng);
                type RngBytes = <$struct as IBE>::RngBytes;
                let mut rand_bytes: RngBytes = [0u8; core::mem::size_of::<RngBytes>()];
                rng.fill_bytes(&mut rand_bytes);

                let c = $struct::encrypt(&pk, &kid, &m, &rand_bytes);

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
                                black_box(Some(&pk)),
                                black_box(&sk),
                                black_box(&kid),
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
                                black_box(&pk),
                                black_box(&kid),
                                black_box(&m),
                                black_box(&rand_bytes),
                            )
                        })
                    },
                );
                criterion.bench_function(
                    &format!("ibe_{} decrypt", stringify!($scheme)).to_string(),
                    move |b| b.iter(|| $struct::decrypt(black_box(&usk), black_box(&c))),
                );
            }
        }
    };
}

bench_kem!(kiltz_vahlis_one, KV1);
bench_kem!(cgw_kv1, CGWKV1);
bench_kem!(cgw_kv2, CGWKV2);
bench_kem!(cgw_kv3, CGWKV3);
bench_kem!(cgw_fo, CGWFO);

bench_ibe!(boyen_waters, BoyenWaters);
bench_ibe!(waters, Waters);
bench_ibe!(waters_naccache, WatersNaccache);
bench_ibe!(cgw, CGW);

bench_multi_kem!(cgw_fo, CGWFO);
bench_multi_kem!(cgw_kv1, CGWKV1);
bench_multi_kem!(cgw_kv2, CGWKV2);
bench_multi_kem!(cgw_kv3, CGWKV3);

criterion_group!(
    name = kem_benches;
    config = Criterion::default().warm_up_time(Duration::new(0, 500));
    targets =
    bench_kem_kiltz_vahlis_one,
    bench_kem_cgw_fo,
    bench_kem_cgw_kv1,
    bench_kem_cgw_kv2,
    bench_kem_cgw_kv3,
    bench_multi_kem_cgw_fo,
    bench_multi_kem_cgw_kv1,
    bench_multi_kem_cgw_kv2,
    bench_multi_kem_cgw_kv3,
);

criterion_group!(
    name = pke_benches;
    config = Criterion::default().warm_up_time(Duration::new(0, 500));
    targets =
    bench_ibe_waters,
    bench_ibe_waters_naccache,
    bench_ibe_boyen_waters,
    bench_ibe_cgw,
);

criterion_main!(kem_benches, pke_benches);
