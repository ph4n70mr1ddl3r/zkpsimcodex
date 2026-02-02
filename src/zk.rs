use k256::{
    elliptic_curve::{
        bigint::U256,
        ff::Field,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Group,
    },
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};

const MIN_RING_SIZE: usize = 2;
const CHALLENGE_PREFIX: &[u8] = b"zkpsimcodex-ring-challenge";

/// Compact Schnorr ring signature proving ownership of one secret key among a set of public keys.
///
/// The signature consists of an initial challenge and a vector of scalar responses,
/// one for each public key in the ring. The verifier cannot determine which key
/// was used to create the signature.
#[derive(Clone, Debug)]
pub struct RingSignature {
    pub c0: Scalar,
    pub s: Vec<Scalar>,
}

fn hash_to_scalar(data: impl AsRef<[u8]>) -> Scalar {
    let digest = Sha256::digest(data);
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(digest))
}

fn hash_challenge(message: &[u8], r_point: &ProjectivePoint) -> Scalar {
    let encoded_point = r_point.to_affine().to_encoded_point(true);
    let mut transcript =
        Vec::with_capacity(CHALLENGE_PREFIX.len() + message.len() + encoded_point.as_bytes().len());
    transcript.extend_from_slice(CHALLENGE_PREFIX);
    transcript.extend_from_slice(message);
    transcript.extend_from_slice(encoded_point.as_bytes());
    hash_to_scalar(transcript)
}

fn validate_public_key(pk_bytes: &EncodedPoint) -> Option<ProjectivePoint> {
    let point = ProjectivePoint::from_encoded_point(pk_bytes).into_option()?;
    if bool::from(point.is_identity()) {
        return None;
    }
    Some(point)
}

/// Create a non-linkable Schnorr ring signature over secp256k1 public keys.
///
/// The signer proves knowledge of the private key corresponding to `public_keys[signer_index]`
/// without revealing which key is used.
///
/// # Arguments
/// * `message` - The message being signed
/// * `public_keys` - The ring of public keys (must contain at least 2 keys)
/// * `signer_index` - Index of the signer's public key in the ring
/// * `secret_scalar` - The signer's private key scalar
/// * `rng` - Random number generator
///
/// # Panics
/// Panics if the ring has fewer than 2 members or if signer_index is out of bounds.
pub fn ring_sign(
    message: &[u8],
    public_keys: &[EncodedPoint],
    signer_index: usize,
    secret_scalar: &Scalar,
    rng: &mut StdRng,
) -> RingSignature {
    let n = public_keys.len();
    assert!(n >= MIN_RING_SIZE, "ring must contain at least two members");
    assert!(signer_index < n, "signer index out of bounds");

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

        let pub_point =
            validate_public_key(&public_keys[i]).expect("all public keys must be valid");

        s_values[i] = Scalar::random(&mut *rng);
        let r_i = ProjectivePoint::GENERATOR * s_values[i] + (pub_point * (-c_values[i]));
        c_values[next] = hash_challenge(message, &r_i);
    }

    // Complete the loop with the signer response.
    let c_signer = c_values[signer_index];
    s_values[signer_index] = k + (c_signer * secret_scalar);

    RingSignature {
        c0: c_values[0],
        s: s_values,
    }
}

/// Verify a Schnorr ring signature.
///
/// Returns true if the signature is valid for the given message and public keys,
/// false otherwise.
///
/// # Arguments
/// * `message` - The message that was signed
/// * `public_keys` - The ring of public keys used to create the signature
/// * `signature` - The ring signature to verify
#[must_use]
pub fn ring_verify(
    message: &[u8],
    public_keys: &[EncodedPoint],
    signature: &RingSignature,
) -> bool {
    let n = public_keys.len();
    if n == 0 || signature.s.len() != n {
        return false;
    }

    let mut c = signature.c0;
    for (s_i, pk_bytes) in signature.s.iter().zip(public_keys.iter()) {
        let pub_point = match validate_public_key(pk_bytes) {
            Some(p) => p,
            None => return false,
        };

        let r_i = ProjectivePoint::GENERATOR * s_i + (pub_point * (-c));
        c = hash_challenge(message, &r_i);
    }

    c == signature.c0
}
