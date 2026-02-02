use thiserror::Error;

/// Error types for the ZKP simulator.
#[derive(Error, Debug)]
pub enum ZkpError {
    #[error("ring must contain at least {0} members")]
    InvalidRingSize(usize),

    #[error("signer index {0} is out of bounds (ring size: {1})")]
    InvalidSignerIndex(usize, usize),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("signer's public key not found in the public keys set")]
    SignerNotFound,

    #[error("duplicate public key in ring")]
    DuplicatePublicKey,

    #[error("invalid secret key (zero)")]
    InvalidSecretKey,

    #[error("public keys set is empty")]
    InvalidPublicKeySet,
}

/// Result type alias for ZKP operations.
pub type Result<T> = std::result::Result<T, ZkpError>;
