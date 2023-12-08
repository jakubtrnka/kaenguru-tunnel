pub mod initiator;

pub mod responder;

pub use initiator::Initiator;
pub use responder::Responder;

use crate::frontend::PublicKey;

#[derive(Debug)]
pub enum HandshakeError {
    InitializationError(String),
    AuthorizeError(String),
    CryptoError(String),
    IoError(std::io::Error),
}

impl From<std::io::Error> for HandshakeError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl From<snow::Error> for HandshakeError {
    fn from(value: snow::Error) -> Self {
        Self::CryptoError(value.to_string())
    }
}

pub trait Authenticator {
    type Error: ToString;

    fn authorize(&mut self, remote_static_public_key: &[u8]) -> Result<(), Self::Error>;
}

pub struct NaiveAuthenticator(pub PublicKey);
impl Authenticator for NaiveAuthenticator {
    type Error = String;

    fn authorize(&mut self, remote_static_public_key: &[u8]) -> Result<(), Self::Error> {
        if self.0.as_ref() != remote_static_public_key {
            return Err("Unknown remote public key".into());
        }
        Ok(())
    }
}
