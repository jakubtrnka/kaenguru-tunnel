pub mod frontend;
pub mod handshake;
pub mod naive_framing;

use snow::params::NoiseParams;

/// From noise standard
const MAX_PLAINTEXT_CHUNK_LENGTH: u16 = 65519;
const MAC_LENGTH: usize = 16;

fn handshake_params() -> NoiseParams {
    "Noise_XX_25519_AESGCM_BLAKE2b"
        .parse::<NoiseParams>()
        .expect("Typo in the param string")
}

#[derive(Debug)]
pub enum TransportError {
    CryptoError(String),
    FramingError(String),
    ConfigError(&'static str),
    IoError(std::io::Error),
}

impl From<snow::Error> for TransportError {
    fn from(value: snow::Error) -> Self {
        Self::CryptoError(value.to_string())
    }
}

pub struct Encryption<W> {
    inner_state: snow::TransportState,
    io: W,
}

#[cfg(test)]
mod tests {
    use crate::frontend::{PrivateKey, PublicKey};
    use crate::handshake::*;
    use std::io::{Read, Write};

    use rand::{random, Rng, RngCore};
    use snow::Keypair;

    use snow::params::HashChoice;
    use snow::resolvers::CryptoResolver;
    use std::os::unix::net::{UnixListener, UnixStream};

    struct RandomizedDataSource {
        data_generated: usize,
        limit: usize,
        max_chunk_size: usize,
        cumulative_hash: Box<dyn snow::types::Hash>,
    }

    impl Read for RandomizedDataSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut rng = rand::thread_rng();
            let chunk_length = rng.gen_range(1..self.max_chunk_size);
            let remaining = self.limit - self.data_generated;
            let to_be_generated = chunk_length.min(remaining).min(buf.len());
            self.data_generated += to_be_generated;
            rng.fill_bytes(&mut buf[..to_be_generated]);
            self.cumulative_hash.input(&buf[..to_be_generated]);

            Ok(to_be_generated)
        }
    }

    struct TrackedDataSink {
        data_received: usize,
        cumulative_hash: Box<dyn snow::types::Hash>,
    }

    impl Write for TrackedDataSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.data_received += buf.len();
            self.cumulative_hash.input(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lifecycle() {
        let init_private = PrivateKey::from(random::<[u8; 32]>());
        let resp_private = PrivateKey::from(random::<[u8; 32]>());
        let init_keypair = Keypair::from(init_private);
        let resp_keypair = Keypair::from(resp_private);

        let init_pub = PublicKey::try_from(&init_keypair).unwrap();
        let resp_pub = PublicKey::try_from(&resp_keypair).unwrap();
        let initiator = Initiator::new(NaiveAuthenticator(resp_pub), init_private);
        let responder = Responder::new(NaiveAuthenticator(init_pub), resp_private);
        std::fs::remove_file("/tmp/sock1234").ok();
        let listener = UnixListener::bind("/tmp/sock1234").unwrap();

        let rh = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            responder.run(stream).unwrap()
        });

        let ih = std::thread::spawn(move || {
            let stream = UnixStream::connect("/tmp/sock1234").unwrap();
            initiator.run(stream).unwrap()
        });

        let mut i_encryption = ih.join().unwrap();
        let mut r_encryption = rh.join().unwrap();
        let payload = (0_u8..10).collect::<Vec<_>>();
        let mut decrypt_buf = std::io::Cursor::new(Vec::<_>::new());
        i_encryption
            .encrypt_with_naive_framing(1024, payload.as_slice())
            .unwrap();
        r_encryption
            .decrypt_with_naive_framing(&mut decrypt_buf)
            .unwrap();
        r_encryption
            .encrypt_with_naive_framing(1024, b"ahoj".as_slice())
            .unwrap();
        let mut decr_buf = std::io::Cursor::new(Vec::<_>::new());
        i_encryption
            .decrypt_with_naive_framing(&mut decr_buf)
            .unwrap();
        let timer = std::time::Instant::now();
        let src_limit = 0x2_000_000; //  32 MiB
        let a = std::thread::spawn(move || {
            let mut src = RandomizedDataSource {
                data_generated: 0,
                limit: src_limit,
                max_chunk_size: 10000000,
                cumulative_hash: snow::resolvers::DefaultResolver
                    .resolve_hash(&HashChoice::Blake2b)
                    .unwrap(),
            };
            i_encryption
                .encrypt_with_naive_framing(65519, &mut src)
                .unwrap();
            let mut result = [0; 64];
            src.cumulative_hash.result(&mut result);
            result
        });

        let mut snk = TrackedDataSink {
            data_received: 0,
            cumulative_hash: snow::resolvers::DefaultResolver
                .resolve_hash(&HashChoice::Blake2b)
                .unwrap(),
        };

        r_encryption.decrypt_with_naive_framing(&mut snk).unwrap();

        let mut b_result = [0; 64];
        snk.cumulative_hash.result(&mut b_result);
        let a_result = a.join().unwrap();
        assert_eq!(a_result, b_result);
        assert_eq!(snk.data_received, src_limit);
        println!(
            "{}",
            src_limit as f64 / 1_000_000.0 / timer.elapsed().as_secs_f64()
        );
        std::fs::remove_file("/tmp/sock1234").ok();
    }
}
