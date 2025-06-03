use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[cfg(not(feature = "use-intrinsics"))]
use blst::{min_pk as bls, BLST_ERROR};
#[cfg(feature = "use-intrinsics")]
use {
    openvm_algebra_guest::field::FieldExtension,
    openvm_algebra_guest::IntMod,
    openvm_ecc_guest::{
        weierstrass::{CachedMulTable, IntrinsicCurve, WeierstrassPoint},
        AffinePoint, CyclicGroup, Group, halo2curves
    },
    openvm_pairing_guest::bls12_381::{
        Bls12_381 as Bls12_381_G1, Fp, Fp2, G1Affine as Bls12_381G1Affine,
        G2Affine as Bls12_381G2Affine, Scalar as Bls12_381Scalar, 
    },
    openvm_sha256_guest::sha256,
    crate::hash_openvm::Sha256OpenVm,
};



// domain string, must match what is used in signing. This one should be good for beacon chain
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub const BLS_SIGNATURE_BYTES_LEN: usize = 96;

#[derive(Debug)]
pub enum BlsError {
    InvalidSignature,
    Other(String),
}

#[cfg(not(feature = "use-intrinsics"))]
impl From<BLST_ERROR> for BlsError {
    fn from(value: BLST_ERROR) -> Self {
        assert!(value != BLST_ERROR::BLST_SUCCESS);
        Self::Other(format_args!("{:?}", value).to_string())
    }
}

impl From<String> for BlsError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}
#[cfg(not(feature = "use-intrinsics"))]
#[derive(Clone, Debug)]
pub struct PublicKey(bls::PublicKey);

#[cfg(feature = "use-intrinsics")]
#[derive(Clone, Debug)]
pub struct PublicKey(Bls12_381G1Affine);


#[cfg(not(feature = "use-intrinsics"))]
impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        Ok(PublicKey(bls::PublicKey::from_bytes(bytes).unwrap()))
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: PublicKey) -> Self {
        let mut aggkey = bls::AggregatePublicKey::from_public_key(&self.0);
        aggkey.add_public_key(&other.0, false).unwrap();
        Self(aggkey.to_public_key())
    }
}

#[cfg(feature = "use-intrinsics")]
impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        let point = safe_g1_affine_from_bytes(bytes.try_into().unwrap())?;
        Ok(PublicKey(point))
    }

    // pub fn to_bytes(&self) -> [u8; 48] {
    //     let (x, y) = self.0.clone().into_coords();
    //     let mut bytes = [0u8; 48];
    //     bytes[0..48].copy_from_slice(&x.to_be_bytes());
    //     bytes[48..96].copy_from_slice(&y.to_be_bytes());
    //     bytes
    // }

    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: PublicKey) -> Self {
        let mut aggkey = self.0.clone();
        aggkey.add_ne_assign_nonidentity(&other.0);
        Self(aggkey)
    }
}

#[cfg(not(feature = "use-intrinsics"))]
pub struct Signature(bls::Signature);

#[cfg(feature = "use-intrinsics")]
pub struct Signature(Bls12_381G2Affine);

#[cfg(not(feature = "use-intrinsics"))]
impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        Ok(Signature(bls::Signature::from_bytes(bytes)?))
    }
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }
}

#[cfg(feature = "use-intrinsics")]
impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        let g2 = halo2curves::bls12_381::G2Affine::from_compressed_be(bytes.try_into().unwrap()).unwrap();
        Ok(Signature(to_openvm_g2_affine(g2)))
    }
}

#[cfg(not(feature = "use-intrinsics"))]
pub fn verify_signature(
    public_key: &PublicKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), BlsError> {
    let res = signature.0.verify(true, msg, DST, &[], &public_key.0, true);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(BlsError::InvalidSignature)
    }
}

#[cfg(feature = "use-intrinsics")]
pub fn verify_signature(
    public_key: &PublicKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), BlsError> {
    let g1_neg = Bls12_381G1Affine::NEG_GENERATOR;

    use halo2curves::bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
    let msghash = <halo2curves::bls12_381::G2 as HashToCurve<ExpandMsgXmd<Sha256OpenVm>>>::hash_to_curve(
        msg,
        b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    );
    let msghash = to_openvm_g2_affine(msghash.into());


    let success = pairings_verify(g1_neg, signature.0.clone(), public_key.0.clone(), signature.0.clone());

    Ok(())
}

/// Verifies the pairing of two G1 and two G2 points are equivalent using the multi-miller loop.
fn pairings_verify(
    p0: Bls12_381G1Affine,
    p1: Bls12_381G2Affine,
    q0: Bls12_381G1Affine,
    q1: Bls12_381G2Affine,
) -> bool {
    use openvm_pairing_guest::{bls12_381::Bls12_381, pairing::PairingCheck};

    let [p0, q0] = [p0, q0].map(|p| {
        let (x, y) = p.into_coords();
        AffinePoint::new(x, y)
    });
    let g1_points = [-p0, q0];
    let g2_points = [p1, q1].map(Into::into);

    Bls12_381::pairing_check(&g1_points, &g2_points).is_ok()
}

fn to_openvm_g2_affine(g2: halo2curves::bls12_381::G2Affine) -> Bls12_381G2Affine {
    if g2.is_identity().unwrap_u8() != 0 {
        return <Bls12_381G2Affine as Group>::IDENTITY;
    }
    let g2_bytes = g2.to_uncompressed_be();
    let x_c1: [u8; 48] = g2_bytes[0..48].try_into().unwrap();
    let x_c0: [u8; 48] = g2_bytes[48..96].try_into().unwrap();
    let y_c1: [u8; 48] = g2_bytes[96..144].try_into().unwrap();
    let y_c0: [u8; 48] = g2_bytes[144..192].try_into().unwrap();

    let ox = Fp2::from_coeffs([Fp::from_be_bytes(&x_c0), Fp::from_be_bytes(&x_c1)]);
    let oy = Fp2::from_coeffs([Fp::from_be_bytes(&y_c0), Fp::from_be_bytes(&y_c1)]);
    Bls12_381G2Affine::from_xy_unchecked(ox, oy)
}

pub fn fast_aggregate_verify(
    public_keys: &[PublicKey],
    msg: &[u8],
    signature: &Signature,
) -> Result<(), BlsError> {
    let agg_pubkey = public_keys.iter().fold(PublicKey(<Bls12_381G1Affine as WeierstrassPoint>::IDENTITY), |acc, k| acc.add(k.clone()));
    let res = verify_signature(&agg_pubkey, msg, signature);
    if res.is_ok() {
        Ok(())
    } else {
        Err(BlsError::InvalidSignature)
    }
}

// This is verification for the case where multiple messages were signed and an aggregate signature obtained by aggregating the resulting signatures.
// TODO: BLST won't do this out of the box but it should be fairly easy to implement with their lower level operations
pub fn multi_message_verify(
    _messages: &[&[u8]],
    _public_key: &PublicKey,
    _signature: &Signature,
) -> Result<(), BlsError> {
    Ok(())
}

#[cfg(feature = "use-intrinsics")]
pub fn safe_g1_affine_from_bytes(bytes: [u8; 48]) -> Result<Bls12_381G1Affine, BlsError> {
    use openvm_ecc_guest::weierstrass::FromCompressed;

    let mut x_bytes = [0u8; 48];
    x_bytes.copy_from_slice(&bytes[0..48]);

    let compression_flag_set = ((x_bytes[0] >> 7) & 1) != 0;
    let infinity_flag_set = ((x_bytes[0] >> 6) & 1) != 0;
    let sort_flag_set = ((x_bytes[0] >> 5) & 1) != 0;

    // Mask away the flag bits
    x_bytes[0] &= 0b0001_1111;
    let x = Fp::from_be_bytes(&x_bytes);

    if infinity_flag_set && compression_flag_set && !sort_flag_set && x == Fp::ZERO {
        return Ok(<Bls12_381G1Affine as Group>::IDENTITY);
    }

    // Note that we need to determine the y-coord using lexicographic ordering instead of parity, so
    // the value for rec_id does not matter and we can pass in either 0 or 1.
    let mut point = Bls12_381G1Affine::decompress(x, &0u8)
        .ok_or_else(|| BlsError::Other("Failed to decompress G1Affine".to_string()))?;
    if is_lex_largest(point.y()) ^ sort_flag_set {
        point.y_mut().neg_assign();
    }
    Ok(point)
}

#[cfg(feature = "use-intrinsics")]
fn is_lex_largest(y: &Fp) -> bool {
    use core::cmp::Ordering;
    let neg_y = -y.clone();
    // This is a way to force y and -y are both in reduced form simultaneously using `iseqmod` opcode
    // Guest execution will never terminate if these elements are not reduced
    let _ = core::hint::black_box(y == &neg_y);
    // Compare y big endian bytes lexicographically with -y big endian bytes
    for (l, r) in y
        .as_le_bytes()
        .iter()
        .rev()
        .zip(neg_y.as_le_bytes().iter().rev())
    {
        match l.cmp(r) {
            Ordering::Greater => return true,
            Ordering::Less => return false,
            Ordering::Equal => continue,
        }
    }
    // all bytes are equal
    false
}
