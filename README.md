# Känguru tunnel

Securely transfer files over an insecure network.

Program works by establishing encrypted session with the `Noise_XX_25519_AESGCM_BLAKE2b` noise protocol:
(see https://noiseprotocol.org/noise.html). I. e. both parties (initiator and responder) perform multiple rounds of ed25519-elliptic-curve diffie-hellman key exchange involving both ephemeral and static keys. Resulting cipher is AES-GCM.

File is segmented into chungs of maximum 65519 bytes.

## Build and run:

1. Install Rust toolchain: see `https://rustup.rs/`
2. Build project `cargo build --release`
3. Run for help ` cargo run --release -- help`

### Details about keys:
Private key consists of [166, 184, 175, 106] prefix followed by 32-byte raw ed25519 keys.
Data is encoded using base64 code with alphabet.
The prefix ensures that the encoded private key begins with "priva".
The prefix prevents mistaking private keys with public keys, who are encoded with [166, 230, 229, 137] prefix, making the code begin with string "publi".

### Run as a sender:
1. Generate an ed25519 keypair `cargo run --release -- gen-key`
2. Obtain remote party's public key
3. Send the file: `cargo run --release -- push-file --endpoint 127.0.0.1:3890 --file-to-send ./a.jpg --local-key privagNydHUku1JL1MzTbOR9tvn/vYu5o9lWmPTegUjGeLDl --remote-key publiX8pUOUWVq3XXH+K5U/57QJ8vfRv9/d2btLrpHeBuSRq`

### Run as a receiver:
1. Generate an ed25519 keypair `cargo run --release -- gen-key`
2. Obtain remote party's public key
4. Receive into a file `cargo run --release -- accept-file --destination file://./dstfile.jpg --local-key privarPAxN2To3f6WYn+04Dzv0IWfWT5d0n3DGuXx72zu0sy --remote-key publiTIrv788BvTgD2CytD0jdjJ9eEy216Zud6XMgetqPPAV`

### Receiving to a TCP socket
It is possible to route the incoming data into a TCP socket
1. establish the tcp socket, e. g. with netcat: `nc -l 12354`
2. `cargo run --release -- accept-file --destination tcp://127.0.0.1:12354 --local-key privarPAxN2To3f6WYn+04Dzv0IWfWT5d0n3DGuXx72zu0sy --remote-key publiTIrv788BvTgD2CytD0jdjJ9eEy216Zud6XMgetqPPAV` 