use crate::consts::VRF_PREFIX_NONCE;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha512;

/// Derive a deterministic nonce scalar via HKDF(sk || input).
/// Used identically by VRF and OPRF proof generation.
pub fn hkdf_nonce(sk: &Scalar, input: &[u8]) -> Scalar {
    let ikm = [&sk.to_bytes()[..], input].concat();
    let hkdf = Hkdf::<Sha512>::new(Some(VRF_PREFIX_NONCE), &ikm);
    let mut okm = [0u8; 64];
    hkdf.expand(b"VRF-Nonce", &mut okm).expect("HKDF expansion failed");
    Scalar::from_bytes_mod_order(okm[..32].try_into().expect("slice error"))
}
