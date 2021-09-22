use criterion::{black_box, criterion_group, criterion_main, Criterion};

macro_rules! bench_kem {
    ($scheme_name: ident, $fn_name: ident, $struct_name: ident) => {
        fn $fn_name(criterion: &mut Criterion) {
            use ibe::kem::$scheme_name::*;
            use ibe::kem::IBKEM;

            let mut rng = rand::thread_rng();

            let id = "email:w.geraedts@sarif.nl".as_bytes();
            let kid = Identity::derive(id);

            let (pk, sk) = $struct_name::setup(&mut rng);
            let usk = $struct_name::extract_usk(Some(&pk), &sk, &kid, &mut rng);

            // let ppk = pk.to_bytes();
            // criterion.bench_function(
            //     &format!("{} unpack_pk", stringify!($scheme_name)).to_string(),
            //     |b| b.iter(|| PublicKey::from_bytes(&ppk)),
            // );

            let (c, _k) = $struct_name::encaps(&pk, &kid, &mut rng);

            criterion.bench_function(
                &format!("{} setup", stringify!($scheme_name)).to_string(),
                |b| {
                    let mut rng = rand::thread_rng();
                    b.iter(|| $struct_name::setup(&mut rng))
                },
            );
            criterion.bench_function(
                &format!("{} extract", stringify!($scheme_name)).to_string(),
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
                &format!("{} encaps", stringify!($scheme_name)).to_string(),
                move |b| {
                    let mut rng = rand::thread_rng();
                    b.iter(|| $struct_name::encaps(black_box(&pk), black_box(&kid), &mut rng))
                },
            );
            criterion.bench_function(
                &format!("{} multi-encaps x10", stringify!($scheme_name)).to_string(),
                move |b| {
                    let mut rng = rand::thread_rng();
                    b.iter(|| {
                        $struct_name::multi_encaps(black_box(&pk), black_box(&[&kid; 10]), &mut rng)
                    })
                },
            );
            criterion.bench_function(
                &format!("{} decaps", stringify!($scheme_name)).to_string(),
                move |b| {
                    b.iter(|| {
                        $struct_name::decaps(black_box(Some(&pk)), black_box(&usk), black_box(&c))
                    })
                },
            );
        }
    };
}

macro_rules! bench_ibe {
    ($scheme_name: ident, $fn_name: ident, $struct_name: ident) => {
        fn $fn_name(criterion: &mut Criterion) {
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
            //     &format!("{} unpack_pk", stringify!($scheme_name)).to_string(),
            //     |b| b.iter(|| PublicKey::from_bytes(&ppk)),
            // );

            let m = <$struct_name as IBE>::Message::random(&mut rng);
            type RngBytes = <$struct_name as IBE>::RngBytes;
            let mut rand_bytes: RngBytes = [0u8; core::mem::size_of::<RngBytes>()];
            rng.fill_bytes(&mut rand_bytes);

            let c = $struct_name::encrypt(&pk, &kid, &m, &rand_bytes);

            criterion.bench_function(
                &format!("{} setup", stringify!($scheme_name)).to_string(),
                |b| {
                    let mut rng = rand::thread_rng();
                    b.iter(|| $struct_name::setup(&mut rng))
                },
            );
            criterion.bench_function(
                &format!("{} extract", stringify!($scheme_name)).to_string(),
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
                &format!("{} encrypt", stringify!($scheme_name)).to_string(),
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
                &format!("{} decrypt", stringify!($scheme_name)).to_string(),
                move |b| b.iter(|| $struct_name::decrypt(black_box(&usk), black_box(&c))),
            );
        }
    };
}

bench_kem!(kiltz_vahlis_one, criterion_kiltz_vahlis_one_benchmark, KV1);
bench_kem!(cgw_kv1, criterion_cgw_kem_kv1_benchmark, CGWKV1);
bench_kem!(cgw_kv2, criterion_cgw_kem_kv2_benchmark, CGWKV2);
bench_kem!(cgw_kv3, criterion_cgw_kem_kv3_benchmark, CGWKV3);
bench_kem!(cgw_fo, criterion_cgw_kem_fo_benchmark, CGWFO);

bench_ibe!(
    boyen_waters,
    criterion_boyen_waters_ibe_benchmark,
    BoyenWaters
);
bench_ibe!(waters, criterion_waters_ibe_benchmark, Waters);
bench_ibe!(
    waters_naccache,
    criterion_waters_naccache_ibe_benchmark,
    WatersNaccache
);

criterion_group!(
    benches,
    criterion_waters_ibe_benchmark,
    criterion_waters_naccache_ibe_benchmark,
    criterion_boyen_waters_ibe_benchmark,
    criterion_kiltz_vahlis_one_benchmark,
    criterion_cgw_kem_fo_benchmark,
    criterion_cgw_kem_kv1_benchmark,
    criterion_cgw_kem_kv2_benchmark,
    criterion_cgw_kem_kv3_benchmark,
);
criterion_main!(benches);
