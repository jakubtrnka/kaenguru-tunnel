use crate::frontend::PrivateKey;
use crate::handshake::{Authenticator, HandshakeError};

use std::io::{Read, Write};

pub struct Initiator<A> {
    handshake_state: snow::HandshakeState,
    authenticator: A,
}

impl<A: Authenticator> Initiator<A> {
    pub fn new(authenticator: A, private_key: PrivateKey) -> Self {
        let handshake_state = snow::Builder::new(crate::handshake_params())
            .local_private_key(private_key.as_ref())
            .build_initiator()
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
        // Generate and send ephemeral pubkey (32B). Empty initial plaintext payload
        self.handshake_state
            .write_message(&[], &mut msg_buf[..48])
            .map_err(|e| HandshakeError::CryptoError(e.to_string()))?;

        io.write_all(&msg_buf[..32])?;
        // Read response from responder remote ephemeral pubkey (32B),
        // perform ephemeral ECDH, read encrypted remote static key (32 + 16 B),
        // perform static ECDH, enpty payload (0 + 16 B)
        io.read_exact(&mut msg_buf)?;
        self.handshake_state.read_message(&msg_buf, &mut [])?;

        // Send encrypted static pubkey (32 + 16 B), perform static ECDH, zero payload (0 + 16 B)
        self.handshake_state
            .write_message(&[], &mut msg_buf[..64])?;
        io.write_all(&msg_buf[..64])?;

        let remote_static = self
            .handshake_state
            .get_remote_static()
            .expect("remote static key must be known at this stage");
        // Authorize the counterparty
        self.authenticator
            .authorize(remote_static)
            .map_err(|e| HandshakeError::AuthorizeError(e.to_string()))?;

        let inner_state = self.handshake_state.into_transport_mode()?;
        Ok(crate::Encryption { inner_state, io })
    }
}
