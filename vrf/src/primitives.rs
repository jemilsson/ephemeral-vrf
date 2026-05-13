use crate::consts::VRF_PREFIX_NONCE;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha512;
use solana_sdk::hash::hash;

/// Derive a deterministic nonce scalar via HKDF(sk || input).
/// Used identically by VRF and OPRF proof generation.
pub fn hkdf_nonce(sk: &Scalar, input: &[u8]) -> Scalar {
    let ikm = [&sk.to_bytes()[..], input].concat();
    let hkdf = Hkdf::<Sha512>::new(Some(VRF_PREFIX_NONCE), &ikm);
    let mut okm = [0u8; 64];
    hkdf.expand(b"VRF-Nonce", &mut okm).expect("HKDF expansion failed");
    Scalar::from_bytes_mod_order(okm[..32].try_into().expect("slice error"))
}

/// Hash bytes to a scalar.
///
/// If `outer_prefix` is `Some(prefix)`, performs a double-hash:
///   `SHA256(prefix || SHA256(input))`
/// This preserves the VRF protocol's double-hash-with-domain-separation construction.
///
/// If `outer_prefix` is `None`, performs a single hash:
///   `SHA256(input)`
/// This matches the OPRF challenge construction where `input` already carries a domain prefix.
pub fn hash_to_scalar(input: &[u8], outer_prefix: Option<&[u8]>) -> Scalar {
    let inner = hash(input);
    let final_input: Vec<u8> = match outer_prefix {
        Some(prefix) => [prefix, &inner.to_bytes()[..]].concat(),
        None => inner.to_bytes().to_vec(),
    };
    let outer = hash(&final_input);
    Scalar::from_bytes_mod_order(outer.to_bytes())
}
