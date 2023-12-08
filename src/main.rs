use kaenguru_tunel::frontend::{gen_keypair, PrivateKey, PublicKey};
use kaenguru_tunel::handshake::{Initiator, NaiveAuthenticator, Responder};
use structopt::StructOpt;

use std::fs::File;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;

#[derive(StructOpt)]
enum Cli {
    /// Generate a static private key
    GenKey,
    /// Send a file over a network
    SendFile(SendCommand),
    /// Receive a file from the network
    ReceiveFile(ReceiveCommand),
}

#[derive(StructOpt)]
struct SendCommand {
    /// File on a local filesystem to be sent
    #[structopt(short, long)]
    file_to_send: PathBuf,
    /// Endpoint to send the file to
    #[structopt(short, long)]
    endpoint: String,
    /// Remote static public key
    #[structopt(short, long)]
    remote_key: PublicKey,
    /// Local static private key
    #[structopt(short, long)]
    local_key: PrivateKey,
}

#[derive(StructOpt)]
struct ReceiveCommand {
    /// Where to store the incoming file
    #[structopt(short, long)]
    destination: ReceiverBackend,
    /// Listen at
    #[structopt(short, long, default_value = "127.0.0.1:3890")]
    endpoint: SocketAddr,
    /// Remote static public key
    #[structopt(short, long)]
    remote_key: PublicKey,
    /// Local static private key
    #[structopt(short, long)]
    local_key: PrivateKey,
}

enum ReceiverBackend {
    File(PathBuf),
    Tcp(SocketAddr),
}

impl FromStr for ReceiverBackend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let item = if let Some(path) = s.strip_prefix("file://") {
            Self::File(PathBuf::from(path))
        } else if let Some(sock_addr) = s.strip_prefix("tcp://") {
            Self::Tcp(sock_addr.parse::<SocketAddr>().map_err(|e| e.to_string())?)
        } else {
            return Err("Invalid descriptor. Must begin with tcp:// or file://".into());
        };
        Ok(item)
    }
}

impl ReceiverBackend {
    fn to_sink(&self) -> Result<Box<dyn Write>, String> {
        match self {
            Self::File(path) => {
                let file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(path)
                    .map_err(|e| e.to_string())?;
                Ok(Box::new(file))
            }
            Self::Tcp(sock) => {
                let mut error = "uninit".into();
                for i in 1..=5 {
                    match TcpStream::connect(sock) {
                        Ok(t) => {
                            println!("Connected to {sock}");
                            return Ok(Box::new(t));
                        }
                        Err(e) => {
                            error = e.to_string();
                            eprintln!(
                                "Attempt {i}/5 Failed to connect to the endpoint {sock}. Waiting 15 s"
                            );
                            std::thread::sleep(std::time::Duration::from_secs(15));
                        }
                    }
                }
                Err(error)
            }
        }
    }
}

impl SendCommand {
    fn execute(self) {
        let file_to_read = match File::open(&self.file_to_send) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{e}");
                exit(1);
            }
        };

        let raw_stream = match TcpStream::connect(&self.endpoint) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("Failed to connect: {e}");
                exit(1);
            }
        };
        let initiator = Initiator::new(NaiveAuthenticator(self.remote_key), self.local_key);
        let mut encrypted_stream = match initiator.run(raw_stream) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Tunnel initialization failed: {e:?}");
                exit(1);
            }
        };
        println!(
            "Encrypted stream established, counterparty key {}",
            self.remote_key
        );
        println!("Sending a file");
        let result = encrypted_stream.encrypt_with_naive_framing(8192, file_to_read);
        let stats = match result {
            Ok(stats) => stats,
            Err(e) => {
                eprintln!("Transmission failed: {:?}", e);
                exit(1);
            }
        };
        let bytes = stats.bytes_processed;
        let size = if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < (1 << 20) {
            format!("{:.3} KiB", bytes as f64 / 1024.)
        } else if bytes < (1 << 30) {
            format!("{:.3} MiB", bytes as f64 / 1024. / 1024.)
        } else {
            format!("{:.3} GiB", bytes as f64 / 1024. / 1024. / 1024.)
        };
        println!(
            "File sent successfully. Encrypted {size}, file sha256: {}",
            stats.hash()
        );
    }
}

impl ReceiveCommand {
    fn execute(self) {
        let listener = match TcpListener::bind(self.endpoint) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("Failed to connect: {e}");
                exit(1);
            }
        };
        println!("Bound to the {}. Waiting for connections", self.endpoint);
        let (raw_stream, peer) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept TCP connection: {e}");
                exit(1);
            }
        };
        println!("Accepted connection from {peer}");
        let responder = Responder::new(NaiveAuthenticator(self.remote_key), self.local_key);
        let mut encrypted_stream = match responder.run(raw_stream) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Tunnel initialization failed: {e:?}");
                exit(1);
            }
        };
        println!(
            "Encrypted stream established, counterparty key {}",
            self.remote_key
        );

        let file_to_write = match self.destination.to_sink() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Couldnt open a sink: {e}");
                exit(1);
            }
        };

        let stats = match encrypted_stream.decrypt_with_naive_framing(file_to_write) {
            Ok(stats) => stats,
            Err(e) => {
                eprintln!("Transmission failed: {:?}", e);
                exit(1);
            }
        };

        let bytes = stats.bytes_processed;
        let size = if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < (1 << 20) {
            format!("{:.3} KiB", bytes as f64 / 1024.)
        } else if bytes < (1 << 30) {
            format!("{:.3} MiB", bytes as f64 / 1024. / 1024.)
        } else {
            format!("{:.3} GiB", bytes as f64 / 1024. / 1024. / 1024.)
        };
        println!(
            "File received successfully. Decrypted {size}, file sha256: {}",
            stats.hash()
        );
    }
}

fn main() {
    let args = Cli::from_args();
    match args {
        Cli::GenKey => {
            let keypair = gen_keypair();
            let private_key = PrivateKey::try_from(&keypair).unwrap();
            let public_key = PublicKey::try_from(&keypair).unwrap();

            println!("Private key {private_key}");
            println!("Public key {public_key}");
        }
        Cli::SendFile(cmd) => cmd.execute(),
        Cli::ReceiveFile(cmd) => cmd.execute(),
    }
}
