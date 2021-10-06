use criterion::{black_box, criterion_group, criterion_main, Criterion};
use paste::paste;
use std::time::Duration;

macro_rules! bench_kem {
    ($scheme_name: ident, $struct_name: ident) => {
        paste! {
            fn [<bench_kem_ $scheme_name>](criterion: &mut Criterion) {
                use ibe::kem::$scheme_name::*;
                use ibe::{kem::IBKEM, Compressable};

                let mut rng = rand::thread_rng();

                let id = "email:w.geraedts@sarif.nl".as_bytes();
                let kid = Identity::derive(id);

                let (pk, sk) = $struct_name::setup(&mut rng);
                let usk = $struct_name::extract_usk(Some(&pk), &sk, &kid, &mut rng);

                let ppk = pk.to_bytes();
                criterion.bench_function(
                    &format!("kem_{} unpack_pk", stringify!($scheme_name)).to_string(),
                    |b| b.iter(|| PublicKey::from_bytes(&ppk)),
                );

                let (c, _k) = $struct_name::encaps(&pk, &kid, &mut rng);

                criterion.bench_function(
                    &format!("kem_{} setup", stringify!($scheme_name)).to_string(),
                    |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| $struct_name::setup(&mut rng))
                    },
                );
                criterion.bench_function(
                    &format!("kem_{} extract", stringify!($scheme_name)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| {
                            $struct_name::extract_usk(
                                black_box(Some(&pk)),
                                black_box(&sk),
                                black_box(&kid),
                                &mut rng,
                            )
                        })
                    },
                );
                criterion.bench_function(
                    &format!("kem_{} encaps", stringify!($scheme_name)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| $struct_name::encaps(black_box(&pk), black_box(&kid), &mut rng))
                    },
                );
                criterion.bench_function(
                    &format!("kem_{} decaps", stringify!($scheme_name)).to_string(),
                    move |b| {
                        b.iter(|| {
                            $struct_name::decaps(black_box(Some(&pk)), black_box(&usk), black_box(&c))
                        })
                    },
                );
            }
        }
    }
}

macro_rules! bench_ibe {
    ($scheme_name: ident, $struct_name: ident) => {
        paste! {
            fn [<bench_ibe_ $scheme_name>](criterion: &mut Criterion) {
                use group::Group;
                use ibe::pke::$scheme_name::*;
                use ibe::pke::IBE;
                use rand::RngCore;

                let mut rng = rand::thread_rng();

                let id = "email:w.geraedts@sarif.nl".as_bytes();
                let kid = Identity::derive(id);

                let (pk, sk) = $struct_name::setup(&mut rng);
                let usk = $struct_name::extract_usk(Some(&pk), &sk, &kid, &mut rng);

                // let ppk = pk.to_bytes();
                // criterion.bench_function(
                //     &format!("ibe_{} unpack_pk", stringify!($scheme_name)).to_string(),
                //     |b| b.iter(|| PublicKey::from_bytes(&ppk)),
                // );

                let m = <$struct_name as IBE>::Message::random(&mut rng);
                type RngBytes = <$struct_name as IBE>::RngBytes;
                let mut rand_bytes: RngBytes = [0u8; core::mem::size_of::<RngBytes>()];
                rng.fill_bytes(&mut rand_bytes);

                let c = $struct_name::encrypt(&pk, &kid, &m, &rand_bytes);

                criterion.bench_function(
                    &format!("ibe_{} setup", stringify!($scheme_name)).to_string(),
                    |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| $struct_name::setup(&mut rng))
                    },
                );
                criterion.bench_function(
                    &format!("ibe_{} extract", stringify!($scheme_name)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| {
                            $struct_name::extract_usk(
                                black_box(Some(&pk)),
                                black_box(&sk),
                                black_box(&kid),
                                &mut rng,
                            )
                        })
                    },
                );
                criterion.bench_function(
                    &format!("ibe_{} encrypt", stringify!($scheme_name)).to_string(),
                    move |b| {
                        b.iter(|| {
                            $struct_name::encrypt(
                                black_box(&pk),
                                black_box(&kid),
                                black_box(&m),
                                black_box(&rand_bytes),
                            )
                        })
                    },
                );
                criterion.bench_function(
                    &format!("ibe_{} decrypt", stringify!($scheme_name)).to_string(),
                    move |b| b.iter(|| $struct_name::decrypt(black_box(&usk), black_box(&c))),
                );
            }
        }
    };
}

macro_rules! bench_multi_kem {
    ($scheme_name: ident, $struct_name: ident) => {
        paste! {
            fn [<bench_multi_kem_ $scheme_name>](criterion: &mut Criterion) {
                use ibe::kem::$scheme_name::*;
                use ibe::kem::IBKEM;

                let mut rng = rand::thread_rng();

                let id = "email:w.geraedts@sarif.nl".as_bytes();
                let kid = Identity::derive(id);

                let (pk, _sk) = $struct_name::setup(&mut rng);

                criterion.bench_function(
                    &format!("kem_{} multi-encaps x10", stringify!($scheme_name)).to_string(),
                    move |b| {
                        let mut rng = rand::thread_rng();
                        b.iter(|| {
                            $struct_name::multi_encaps(black_box(&pk), black_box(&[&kid; 10]), &mut rng)
                        })
                    },
                );
            }
        }
    }
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
