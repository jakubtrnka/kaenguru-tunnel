use crate::frontend::PrivateKey;
use crate::handshake::{Authenticator, HandshakeError};

use std::io::{Read, Write};

pub struct Responder<A> {
    handshake_state: snow::HandshakeState,
    authenticator: A,
}

impl<A: Authenticator> Responder<A> {
    pub fn new(authenticator: A, private_key: PrivateKey) -> Self {
        let handshake_state = snow::Builder::new(crate::handshake_params())
            .local_private_key(private_key.as_ref())
            .build_responder()
            .expect("Bug in key size management");
        Self {
            handshake_state,
            authenticator,
        }
    }

    /// noise-protocol:
    /// -> e
    /// <- e, ee, s, es
    /// -> s, se
    pub fn run<W>(mut self, mut io: W) -> Result<crate::Encryption<W>, HandshakeError>
    where
        W: Read + Write,
    {
        let mut msg_buf = [0; 96];

        // Read remote ephemeral key (32 B)
        // -> e
        io.read_exact(&mut msg_buf[..32])?;
        self.handshake_state.read_message(&msg_buf[..32], &mut [])?;

        // Issue initial response: ephemeral pubkey (32 B), perform ephemeral ECDH,
        // send encrypted static key (32 + 16 B), perform static ECDH, empty payload (0 + 16 B)
        // <- e, ee, s, es
        self.handshake_state.write_message(&[], &mut msg_buf)?;
        io.write_all(msg_buf.as_slice())?;

        // Read last last msg: encrypted static pubkey (32 + 16 + 16 B), perform static ECDH
        io.read_exact(&mut msg_buf[..64])?;
        self.handshake_state
            .read_message(&msg_buf[..64], &mut [0; 1000])?;

        let remote_static = self
            .handshake_state
            .get_remote_static()
            .expect("remote static key must be known at this stage");
        // Authorize the counterparty
        self.authenticator
            .authorize(remote_static)
            .map_err(|e| HandshakeError::AuthorizeError(e.to_string()))?;
        let inner_state = self
            .handshake_state
            .into_transport_mode()
            .map_err(|e| HandshakeError::CryptoError(e.to_string()))?;
        Ok(crate::Encryption { inner_state, io })
    }
}
