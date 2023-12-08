use crate::*;

use snow::params::HashChoice;
use snow::resolvers::CryptoResolver;
use std::io::{Read, Write};

pub struct TransmissionStats {
    pub hash: [u8; 32],
    pub bytes_processed: usize,
}

impl TransmissionStats {
    pub fn hash(&self) -> String {
        hex::encode(&self.hash)
    }
}

const NAIVE_HEADER_LEN: usize = 2;
impl<W: Read + Write> Encryption<W> {
    /// Chunks input data to the chunks of a specified max length and prefix each chunk with a
    /// 2 bytes little-endian length prefix (i. e. encrypted as a 18 byte header).
    /// Length prefix relates to the ciphertext, not plaintext.
    /// End of stream is convayed by sending an empty chunk
    pub fn encrypt_with_naive_framing<I>(
        &mut self,
        max_chunk_length: u16,
        mut input: I,
    ) -> Result<TransmissionStats, TransportError>
    where
        I: Read,
    {
        if max_chunk_length > MAX_PLAINTEXT_CHUNK_LENGTH {
            return Err(TransportError::ConfigError(
                "Too large chunk length. Max allowed 65519",
            ));
        }
        let mut buf = vec![0_u8; max_chunk_length as usize];
        let mut encrypted_buf =
            vec![0_u8; NAIVE_HEADER_LEN + max_chunk_length as usize + MAC_LENGTH];

        // Calcualte hash of the data being sent;
        let mut hasher = snow::resolvers::RingResolver::default()
            .resolve_hash(&HashChoice::SHA256)
            .unwrap();
        let mut total_bytes_encrypted = 0;
        loop {
            let bytes_read = input.read(&mut buf).map_err(TransportError::IoError)?;

            let ciphertext_payload_len = bytes_read + MAC_LENGTH;
            // encrypt payload length prefix
            let hdr_len = NAIVE_HEADER_LEN + MAC_LENGTH;
            let pt_hdr = (ciphertext_payload_len as u16).to_le_bytes();
            self.inner_state
                .write_message(&pt_hdr, &mut encrypted_buf[..hdr_len])?;

            self.io
                .write_all(&encrypted_buf[..hdr_len])
                .map_err(TransportError::IoError)?;

            // encrypt chunk
            self.inner_state.write_message(
                &buf[..bytes_read],
                &mut encrypted_buf[..ciphertext_payload_len],
            )?;
            hasher.input(&buf[..bytes_read]);
            total_bytes_encrypted += bytes_read;

            self.io
                .write_all(&encrypted_buf[..ciphertext_payload_len])
                .map_err(TransportError::IoError)?;
            if bytes_read == 0 {
                // finish - empty chunk terminates stream
                break;
            }
        }
        let mut hash = [0; 32];
        hasher.result(&mut hash);
        Ok(TransmissionStats {
            hash,
            bytes_processed: total_bytes_encrypted,
        })
    }

    /// Reads frames consisting of 18-byte encrypted header which is encrypted 2-bytes length prefix
    /// in little-endian (16 bytes is MAC) followed by encrypted payloads of a given length.
    /// Empty chunk signalizes end of stream
    pub fn decrypt_with_naive_framing<O>(
        &mut self,
        mut output: O,
    ) -> Result<TransmissionStats, TransportError>
    where
        O: Write,
    {
        let mut encrypted_buf = vec![0_u8; MAX_PLAINTEXT_CHUNK_LENGTH as usize + MAC_LENGTH];
        let mut buf = vec![0_u8; MAX_PLAINTEXT_CHUNK_LENGTH as usize + MAC_LENGTH];

        let mut encrypted_length_prefix = [0_u8; 2 + MAC_LENGTH];

        // Calcualte hash of the data being sent;
        let mut hasher = snow::resolvers::RingResolver::default()
            .resolve_hash(&HashChoice::SHA256)
            .unwrap();
        let mut total_bytes_decrypted = 0;

        loop {
            self.io
                .read_exact(&mut encrypted_length_prefix)
                .map_err(TransportError::IoError)?;
            let mut decrypted_length_prefix = [0_u8; 2 + MAC_LENGTH];
            self.inner_state
                .read_message(&encrypted_length_prefix, &mut decrypted_length_prefix)?;
            let raw_length = TryFrom::try_from(&decrypted_length_prefix[..2]).unwrap();
            let encrypted_pld_length = u16::from_le_bytes(raw_length) as usize;
            if encrypted_pld_length < MAC_LENGTH {
                return Err(TransportError::FramingError(
                    "Invalid payload length received".into(),
                ));
            };
            let pt_pld_len = encrypted_pld_length - MAC_LENGTH;
            self.io
                .read_exact(&mut encrypted_buf[..encrypted_pld_length])
                .map_err(TransportError::IoError)?;
            // println!("Decrpting {:?} chunk", encrypted_pld_length);
            // decrypt chunk
            self.inner_state.read_message(
                &encrypted_buf[..encrypted_pld_length],
                &mut buf[..pt_pld_len],
            )?;
            hasher.input(&buf[..pt_pld_len]);
            total_bytes_decrypted += pt_pld_len;

            if encrypted_pld_length == MAC_LENGTH {
                // zero payload => end of stream
                let mut hash = [0; 32];
                hasher.result(&mut hash);
                return Ok(TransmissionStats {
                    hash,
                    bytes_processed: total_bytes_decrypted,
                });
            }

            output
                .write_all(&mut buf[..pt_pld_len])
                .map_err(TransportError::IoError)?;
        }
    }
}
