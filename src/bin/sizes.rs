//! This file produces a binary that prints the sizes of several IBE/KEM components
//! such as the MPK, MSK, USK, CT and MSG.

macro_rules! print_sizes_kem {
    ($scheme_name: ident) => {{
        use ibe::kem::$scheme_name::*;
        println!(stringify!($scheme_name));
        println!("MPK:\t{}", PK_BYTES);
        println!("MSK:\t{}", SK_BYTES);
        println!("USK:\t{}", USK_BYTES);
        println!("CT:\t{}\n", CT_BYTES);
    }};
}

macro_rules! print_sizes_pke {
    ($scheme_name: ident) => {{
        use ibe::pke::$scheme_name::*;
        println!(stringify!($scheme_name));
        println!("MPK:\t{}", PK_BYTES);
        println!("MSK:\t{}", SK_BYTES);
        println!("USK:\t{}", USK_BYTES);
        println!("CT:\t{}", CT_BYTES);
        println!("MSG:\t{}\n", MSG_BYTES);
    }};
}

fn main() {
    println!("KEM sizes in bytes:\n");
    print_sizes_kem!(cgw_fo);
    print_sizes_kem!(cgw_kv1);
    print_sizes_kem!(cgw_kv2);
    print_sizes_kem!(cgw_kv3);
    print_sizes_kem!(kiltz_vahlis_one);
    println!("PKE sizes in bytes:\n");
    print_sizes_pke!(waters);
    print_sizes_pke!(waters_naccache);
    print_sizes_pke!(boyen_waters);
    print_sizes_pke!(cgw);
}
