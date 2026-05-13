use crate::consts::OPRF_PREFIX_CHALLENGE;
use crate::primitives::{hkdf_nonce, hash_to_scalar};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

#[derive(Clone, Copy, Debug)]
pub struct DleqProof {
    /// k*T commitment (oracle nonce times blinded input point)
    pub r1: CompressedRistretto,
    /// k*G commitment (oracle nonce times base point)
    pub r2: CompressedRistretto,
    /// s = k + c*sk (Fiat-Shamir response)
    pub s: Scalar,
}

/// Compute OPRF output and DLEQ proof.
///
/// `sk`: oracle secret scalar
/// `pk`: oracle public key (sk*G), passed in to avoid recomputing
/// `blinded_point_bytes`: client-provided T = r*H(seed) (compressed Ristretto)
///
/// Returns (Z = sk*T, DleqProof) or None if blinded_point is invalid.
pub fn compute_oprf(
    sk: Scalar,
    pk: RistrettoPoint,
    blinded_point_bytes: &[u8; 32],
) -> Option<(CompressedRistretto, DleqProof)> {
    let T = CompressedRistretto(*blinded_point_bytes).decompress()?;

    // Reject identity point (would produce predictable output).
    if T == RistrettoPoint::identity() {
        return None;
    }

    let Z = sk * T; // OPRF output: sk*T

    // Deterministic nonce via HKDF (same pattern as vrf.rs; prevents key leakage without OS randomness).
    let k = hkdf_nonce(&sk, blinded_point_bytes);

    let R1 = k * T;
    let R2 = &k * RISTRETTO_BASEPOINT_TABLE;

    // Challenge: hash(T, K, Z, R1, R2) with domain separator.
    let challenge_input = [
        OPRF_PREFIX_CHALLENGE.to_vec(),
        blinded_point_bytes.to_vec(),
        pk.compress().to_bytes().to_vec(),
        Z.compress().to_bytes().to_vec(),
        R1.compress().to_bytes().to_vec(),
        R2.compress().to_bytes().to_vec(),
    ]
    .concat();
    let c = hash_to_scalar(&challenge_input, None);

    let s = k + c * sk; // s = k + c*sk

    Some((
        Z.compress(),
        DleqProof {
            r1: R1.compress(),
            r2: R2.compress(),
            s,
        },
    ))
}

/// Verify DLEQ proof off-chain (mirrors on-chain verify_dleq in api/src/verify.rs).
pub fn verify_dleq(
    pk: RistrettoPoint,
    blinded_point_bytes: &[u8; 32],
    output_bytes: &[u8; 32],
    proof: &DleqProof,
) -> bool {
    let T = match CompressedRistretto(*blinded_point_bytes).decompress() {
        Some(p) => p,
        None => return false,
    };
    if T == RistrettoPoint::identity() {
        return false;
    }
    let Z = match CompressedRistretto(*output_bytes).decompress() {
        Some(p) => p,
        None => return false,
    };
    let R1 = match proof.r1.decompress() {
        Some(p) => p,
        None => return false,
    };
    let R2 = match proof.r2.decompress() {
        Some(p) => p,
        None => return false,
    };

    let challenge_input = [
        OPRF_PREFIX_CHALLENGE.to_vec(),
        blinded_point_bytes.to_vec(),
        pk.compress().to_bytes().to_vec(),
        output_bytes.to_vec(),
        proof.r1.to_bytes().to_vec(),
        proof.r2.to_bytes().to_vec(),
    ]
    .concat();
    let c = hash_to_scalar(&challenge_input, None);

    // Verify: s*T == R1 + c*Z  and  s*G == R2 + c*K
    let lhs_t = proof.s * T;
    let rhs_t = R1 + c * Z;
    let lhs_g = &proof.s * RISTRETTO_BASEPOINT_TABLE;
    let rhs_g = R2 + c * pk;

    lhs_t == rhs_t && lhs_g == rhs_g
}

/// Unblind the OPRF output on the client side.
/// Returns k*H(seed) = (1/r) * Z given the client's blinding scalar r.
pub fn unblind_oprf(output_bytes: &[u8; 32], r: Scalar) -> Option<CompressedRistretto> {
    let Z = CompressedRistretto(*output_bytes).decompress()?;
    let r_inv = r.invert();
    Some((r_inv * Z).compress())
}
