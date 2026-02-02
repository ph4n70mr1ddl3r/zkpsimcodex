use crate::error::{Result, ZkpError};
use k256::{
    elliptic_curve::{
        bigint::U256,
        ff::Field,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        subtle::ConstantTimeEq,
        Group,
    },
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const MIN_RING_SIZE: usize = 2;
const CHALLENGE_PREFIX: &[u8] = b"zkpsimcodex-ring-challenge";

/// Compact Schnorr ring signature proving ownership of one secret key among a set of public keys.
///
/// The signature consists of an initial challenge and a vector of scalar responses,
/// one for each public key in the ring. The verifier cannot determine which key
/// was used to create the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingSignature {
    pub c0: Scalar,
    pub s: Vec<Scalar>,
}

#[inline]
fn hash_to_scalar(data: impl AsRef<[u8]>) -> Scalar {
    let digest = Sha256::digest(data);
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(digest))
}

#[inline]
fn hash_challenge(message: &[u8], r_point: &ProjectivePoint) -> Scalar {
    let encoded_point = r_point.to_affine().to_encoded_point(true);
    let mut transcript =
        Vec::with_capacity(CHALLENGE_PREFIX.len() + message.len() + encoded_point.as_bytes().len());
    transcript.extend_from_slice(CHALLENGE_PREFIX);
    transcript.extend_from_slice(message);
    transcript.extend_from_slice(encoded_point.as_bytes());
    hash_to_scalar(transcript)
}

#[inline]
fn validate_public_key(pk_bytes: &EncodedPoint) -> Result<ProjectivePoint> {
    let point = ProjectivePoint::from_encoded_point(pk_bytes)
        .into_option()
        .ok_or(ZkpError::InvalidPublicKey)?;
    if bool::from(point.is_identity()) {
        return Err(ZkpError::InvalidPublicKey);
    }
    Ok(point)
}

/// Create a non-linkable Schnorr ring signature over secp256k1 public keys.
///
/// The signer proves knowledge of the private key corresponding to `public_keys[signer_index]`
/// without revealing which key is used.
///
/// # Security Notes
/// - The random number generator must be cryptographically secure
/// - The same secret scalar must not be reused across different signatures
/// - The nonce `k` must be unique for each signature to prevent private key exposure
///
/// # Arguments
/// * `message` - The message being signed
/// * `public_keys` - The ring of public keys (must contain at least 2 keys)
/// * `signer_index` - Index of the signer's public key in the ring
/// * `secret_scalar` - The signer's private key scalar
/// * `rng` - Random number generator
///
/// # Errors
/// Returns an error if the ring has fewer than 2 members, if signer_index is out of bounds,
/// or if any public key is invalid.
pub fn ring_sign(
    message: &[u8],
    public_keys: &[EncodedPoint],
    signer_index: usize,
    secret_scalar: &Scalar,
    rng: &mut StdRng,
) -> Result<RingSignature> {
    let n = public_keys.len();
    if n < MIN_RING_SIZE {
        return Err(ZkpError::InvalidRingSize(MIN_RING_SIZE));
    }
    if signer_index >= n {
        return Err(ZkpError::InvalidSignerIndex(signer_index, n));
    }
    let unique_keys: HashSet<_> = public_keys.iter().collect();
    if unique_keys.len() != n {
        return Err(ZkpError::DuplicatePublicKey);
    }
    if secret_scalar == &Scalar::ZERO {
        return Err(ZkpError::InvalidSecretKey);
    }

    let mut s_values = vec![Scalar::ZERO; n];
    let mut c_values = vec![Scalar::ZERO; n];

    let k = Scalar::random(&mut *rng);
    let r_signer = ProjectivePoint::GENERATOR * k;

    let start = (signer_index + 1) % n;
    c_values[start] = hash_challenge(message, &r_signer);

    // Walk around the ring generating random responses and chained challenges,
    // skipping the signer position for now.
    for offset in 0..(n - 1) {
        let i = (start + offset) % n;
        let next = (i + 1) % n;
        if i == signer_index {
            continue;
        }

        let pub_point = validate_public_key(&public_keys[i])?;

        s_values[i] = Scalar::random(&mut *rng);
        let r_i = ProjectivePoint::GENERATOR * s_values[i] + (pub_point * (-c_values[i]));
        c_values[next] = hash_challenge(message, &r_i);
    }

    // Complete the loop with the signer response.
    let c_signer = c_values[signer_index];
    s_values[signer_index] = k + (c_signer * secret_scalar);

    Ok(RingSignature {
        c0: c_values[0],
        s: s_values,
    })
}

/// Verify a Schnorr ring signature.
///
/// Returns true if the signature is valid for the given message and public keys,
/// false otherwise.
///
/// # Security Notes
/// - This function performs constant-time comparison to prevent timing attacks
/// - Verification must be performed with the exact same public keys used during signing
/// - The message must be identical to the one that was signed
///
/// # Arguments
/// * `message` - The message that was signed
/// * `public_keys` - The ring of public keys used to create the signature
/// * `signature` - The ring signature to verify
///
/// # Errors
/// Returns an error if the public keys set is empty.
pub fn ring_verify(
    message: &[u8],
    public_keys: &[EncodedPoint],
    signature: &RingSignature,
) -> Result<bool> {
    if public_keys.is_empty() {
        return Err(ZkpError::InvalidPublicKeySet);
    }
    let n = public_keys.len();
    if signature.s.len() != n {
        return Ok(false);
    }

    let mut c = signature.c0;
    for (s_i, pk_bytes) in signature.s.iter().zip(public_keys.iter()) {
        let pub_point = match validate_public_key(pk_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };

        let r_i = ProjectivePoint::GENERATOR * s_i + (pub_point * (-c));
        c = hash_challenge(message, &r_i);
    }

    Ok(c.ct_eq(&signature.c0).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::SecretKey;
    use rand::SeedableRng;

    #[test]
    fn test_ring_sign_verify() {
        let mut rng = StdRng::seed_from_u64(42);
        let secret_key = SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();

        let mut public_keys = vec![public_key.to_encoded_point(true)];
        for _ in 0..4 {
            let sk = SecretKey::random(&mut rng);
            public_keys.push(sk.public_key().to_encoded_point(true));
        }

        let secret_scalar = *secret_key.to_nonzero_scalar();
        let message = b"test message";

        let signature = ring_sign(message, &public_keys, 0, &secret_scalar, &mut rng).unwrap();
        assert!(ring_verify(message, &public_keys, &signature).unwrap());

        assert!(!ring_verify(b"wrong message", &public_keys, &signature).unwrap());
    }

    #[test]
    fn test_ring_sign_verify_different_signer() {
        let mut rng = StdRng::seed_from_u64(123);
        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();

        for _ in 0..5 {
            let sk = SecretKey::random(&mut rng);
            public_keys.push(sk.public_key().to_encoded_point(true));
            secret_keys.push(sk);
        }

        let signer_index = 2;
        let secret_scalar = *secret_keys[signer_index].to_nonzero_scalar();
        let message = b"test message";

        let signature = ring_sign(
            message,
            &public_keys,
            signer_index,
            &secret_scalar,
            &mut rng,
        )
        .unwrap();
        assert!(ring_verify(message, &public_keys, &signature).unwrap());
    }

    #[test]
    fn test_ring_sign_min_ring_size() {
        let mut rng = StdRng::seed_from_u64(999);
        let secret_key = SecretKey::random(&mut rng);
        let secret_scalar = *secret_key.to_nonzero_scalar();
        let message = b"test message";

        let public_keys = vec![
            secret_key.public_key().to_encoded_point(true),
            SecretKey::random(&mut rng)
                .public_key()
                .to_encoded_point(true),
        ];

        let signature = ring_sign(message, &public_keys, 0, &secret_scalar, &mut rng).unwrap();
        assert!(ring_verify(message, &public_keys, &signature).unwrap());
    }

    #[test]
    fn test_ring_sign_invalid_ring_size() {
        let mut rng = StdRng::seed_from_u64(777);
        let secret_key = SecretKey::random(&mut rng);
        let secret_scalar = *secret_key.to_nonzero_scalar();
        let message = b"test message";

        let public_keys = vec![secret_key.public_key().to_encoded_point(true)];

        let result = ring_sign(message, &public_keys, 0, &secret_scalar, &mut rng);
        assert!(matches!(result, Err(ZkpError::InvalidRingSize(_))));
    }

    #[test]
    fn test_ring_sign_invalid_signer_index() {
        let mut rng = StdRng::seed_from_u64(888);
        let secret_key = SecretKey::random(&mut rng);
        let secret_scalar = *secret_key.to_nonzero_scalar();
        let message = b"test message";

        let public_keys = vec![
            secret_key.public_key().to_encoded_point(true),
            SecretKey::random(&mut rng)
                .public_key()
                .to_encoded_point(true),
        ];

        let result = ring_sign(message, &public_keys, 5, &secret_scalar, &mut rng);
        assert!(matches!(result, Err(ZkpError::InvalidSignerIndex(_, _))));
    }
}
