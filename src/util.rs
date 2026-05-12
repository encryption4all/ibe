use crate::{Compress, Derive};
use group::{ff::Field, Group, UncompressedEncoding};
use pg_curve::{G1Projective, G2Projective, Gt, Scalar};
use rand::{CryptoRng, RngCore};
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
    slice.iter().rev().flat_map(|byte| {
        (0..8u8)
            .rev()
            .map(move |i| subtle::Choice::from((byte >> i) & 1))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_produces_eight_bits_per_byte() {
        let data = [0xABu8; 64];
        assert_eq!(bits(&data).count(), 64 * 8);

        let data = [0xCDu8; 32];
        assert_eq!(bits(&data).count(), 32 * 8);

        let data = [0u8; 0];
        assert_eq!(bits(&data).count(), 0);

        let data = [0xFFu8; 1];
        let bits_vec: std::vec::Vec<u8> = bits(&data).map(|c| c.unwrap_u8()).collect();
        assert_eq!(bits_vec, [1, 1, 1, 1, 1, 1, 1, 1]);
    }

    #[test]
    fn bits_reflects_exact_bit_pattern() {
        // 0b1010_0101 = 0xA5, high bit (bit 7) first.
        let data = [0xA5u8];
        let bits_vec: std::vec::Vec<u8> = bits(&data).map(|c| c.unwrap_u8()).collect();
        assert_eq!(bits_vec, [1, 0, 1, 0, 0, 1, 0, 1]);
    }
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

impl Derive for Identity {
    /// Hash a byte slice to a set of Identity parameters, which acts as a user public key.
    /// Uses sha3-512 internally.
    fn derive(b: &[u8]) -> Identity {
        Identity(sha3_512(b))
    }

    /// Hash a string slice to a set of Identity parameters.
    /// Directly converts characters to UTF-8 byte representation.
    fn derive_str(s: &str) -> Identity {
        Self::derive(s.as_bytes())
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
