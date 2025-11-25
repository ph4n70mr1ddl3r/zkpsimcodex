use k256::{
    elliptic_curve::{
        bigint::U256,
        ff::Field,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};

/// Compact Schnorr ring signature proving ownership of one secret key among a set of public keys.
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
    let mut transcript = Vec::with_capacity(message.len() + 33);
    transcript.extend_from_slice(message);
    transcript.extend_from_slice(r_point.to_affine().to_encoded_point(true).as_bytes());
    hash_to_scalar(transcript)
}

/// Create a non-linkable Schnorr ring signature over secp256k1 public keys.
/// The signer proves knowledge of the private key corresponding to `public_keys[signer_index]`
/// without revealing which key is used.
pub fn ring_sign(
    message: &[u8],
    public_keys: &[EncodedPoint],
    signer_index: usize,
    secret_scalar: &Scalar,
    rng: &mut StdRng,
) -> RingSignature {
    let n = public_keys.len();
    assert!(n > 1, "ring must contain at least two members");
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

        let pub_point = ProjectivePoint::from_encoded_point(&public_keys[i])
            .into_option()
            .expect("public key should decode");

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
        let pub_point = match ProjectivePoint::from_encoded_point(pk_bytes).into_option() {
            Some(p) => p,
            None => return false,
        };

        let r_i = ProjectivePoint::GENERATOR * s_i + (pub_point * (-c));
        c = hash_challenge(message, &r_i);
    }

    c == signature.c0
}
