use crate::Compress;
use group::{ff::Field, Group, UncompressedEncoding};
use irmaseal_curve::{G1Projective, G2Projective, Gt, Scalar};
use rand_core::{CryptoRng, RngCore};
use subtle::CtOption;
use tiny_keccak::Hasher;

/// Size of a compressed target group element.
pub(crate) const GT_BYTES: usize = 288;

/// Size of a compressed G1 group element.
pub(crate) const G1_BYTES: usize = 48;

/// Size of a compressed G2 group element.
pub(crate) const G2_BYTES: usize = 96;

/// Size of a serialized scalar.
pub(crate) const SCALAR_BYTES: usize = 32;

/// Size of the (default) identity buffer.
pub(crate) const ID_BYTES: usize = 64;

#[inline(always)]
pub fn rand_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
}

#[inline(always)]
pub fn rand_g1<R: RngCore + CryptoRng>(rng: &mut R) -> G1Projective {
    G1Projective::random(rng)
}

#[inline(always)]
pub fn rand_g2<R: RngCore + CryptoRng>(rng: &mut R) -> G2Projective {
    G2Projective::random(rng)
}

#[inline(always)]
pub fn rand_gt<R: RngCore + CryptoRng>(rng: &mut R) -> Gt {
    Gt::random(rng)
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

pub fn shake256<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut digest = tiny_keccak::Shake::v256();
    digest.update(slice);

    let mut buf = [0u8; N];
    digest.finalize(&mut buf);

    buf
}

/// Random-prefix collision resistant (RPC) hash function.
pub fn rpc<Gr: UncompressedEncoding>(k: &[u8; 32], gs: &[Gr]) -> Scalar {
    let mut digest = tiny_keccak::Sha3::v512();

    digest.update(k);

    for g in gs.iter() {
        digest.update(g.to_uncompressed().as_ref())
    }

    let mut buf = [0u8; 64];
    digest.finalize(&mut buf);

    Scalar::from_bytes_wide(&buf)
}

/// Byte representation of an identity.
/// Most schemes (not all) use the same representation.
///
/// This identity is obtained by hashing using sha3_512.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Identity(pub [u8; ID_BYTES]);

impl Default for Identity {
    fn default() -> Self {
        Self([0u8; ID_BYTES])
    }
}

impl<T: AsRef<[u8]>> From<T> for Identity {
    fn from(b: T) -> Self {
        Identity(sha3_512(b.as_ref()))
    }
}

impl Identity {
    /// Create a scalar from an identity.
    #[allow(unused)]
    pub(crate) fn to_scalar(self) -> Scalar {
        Scalar::from_bytes_wide(&self.0)
    }
}

impl Compress for Gt {
    const OUTPUT_SIZE: usize = GT_BYTES;
    type Output = [u8; Self::OUTPUT_SIZE];

    fn to_bytes(&self) -> [u8; GT_BYTES] {
        self.to_compressed()
    }

    fn from_bytes(bytes: &[u8; GT_BYTES]) -> CtOption<Self> {
        Self::from_compressed(bytes)
    }
}
