use base64::Engine;
use snow::Keypair;

use snow::resolvers::CryptoResolver;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PublicKey([u8; 32]);

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PrivateKey([u8; 32]);

impl PublicKey {
    /// Ensures padding-free publ prefix in the base64 encoded form
    const DISPLAY_PREFIX: [u8; 4] = [166, 230, 229, 137];
}

pub fn gen_keypair() -> Keypair {
    let builder = snow::Builder::new(crate::handshake_params());
    builder.generate_keypair().unwrap()
}

impl TryFrom<&Keypair> for PublicKey {
    type Error = InvalidKeyError;
    fn try_from(value: &Keypair) -> Result<Self, Self::Error> {
        if value.public.len() != 32 {
            return Err(InvalidKeyError(format!(
                "Invalid key length: {}",
                value.private.len()
            )));
        }
        let mut inner = [0_u8; 32];
        inner.copy_from_slice(&value.public);
        Ok(Self(inner))
    }
}

impl TryFrom<&Keypair> for PrivateKey {
    type Error = InvalidKeyError;
    fn try_from(value: &Keypair) -> Result<Self, Self::Error> {
        if value.private.len() != 32 {
            return Err(InvalidKeyError(format!(
                "Invalid key length: {}",
                value.private.len()
            )));
        }
        let mut inner = [0_u8; 32];
        inner.copy_from_slice(&value.private);
        Ok(Self(inner))
    }
}

impl From<PrivateKey> for Keypair {
    fn from(value: PrivateKey) -> Self {
        let params = crate::handshake_params();
        let x = snow::resolvers::DefaultResolver::default();
        let mut dh = x
            .resolve_dh(&params.dh)
            .expect("Missing DH operation for this particular handahske");
        assert_eq!(dh.priv_len(), 32);
        assert_eq!(dh.pub_len(), 32);
        dh.set(value.as_ref());
        let pubkey = PublicKey::try_from(dh.pubkey()).expect("The key length IS 32 bytes");
        Keypair {
            private: Vec::from(value.as_ref()),
            public: Vec::from(pubkey.as_ref()),
        }
    }
}

impl PrivateKey {
    /// Ensures padding-free priv prefix in the base64 encoded form
    const DISPLAY_PREFIX: [u8; 4] = [166, 184, 175, 106];
}

#[derive(Debug)]
pub struct InvalidKeyError(String);

impl Display for InvalidKeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid key: {}", self.0)
    }
}

macro_rules! frontend_impl {
    ($item:ty) => {
        impl From<[u8; 32]> for $item {
            fn from(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl TryFrom<&[u8]> for $item {
            type Error = InvalidKeyError;
            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let inner = <[u8; 32]>::try_from(value)
                    .map_err(|_| InvalidKeyError(format!("Invalid key length: {}", value.len())))?;
                Ok(Self::from(inner))
            }
        }

        impl From<$item> for [u8; 32] {
            fn from(value: $item) -> [u8; 32] {
                value.0
            }
        }

        impl AsRef<[u8]> for $item {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl Display for $item {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                let encoder = base64::engine::GeneralPurpose::new(
                    &base64::alphabet::STANDARD,
                    Default::default(),
                );
                let mut tmp = [0_u8; 36];
                tmp[..4].copy_from_slice(&<$item>::DISPLAY_PREFIX);
                tmp[4..].copy_from_slice(&self.0);
                let str_repr = encoder.encode(tmp);
                f.write_str(&str_repr)
            }
        }

        impl FromStr for $item {
            type Err = InvalidKeyError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let decoder = base64::engine::GeneralPurpose::new(
                    &base64::alphabet::STANDARD,
                    Default::default(),
                );
                let raw_key_w_prefix = decoder
                    .decode(s.trim())
                    .map_err(|e| InvalidKeyError(e.to_string()))?;
                if raw_key_w_prefix.len() != 36 {
                    return Err(InvalidKeyError("Invalid key length".into()))?;
                }
                if &raw_key_w_prefix[..4] != &<$item>::DISPLAY_PREFIX {
                    return Err(InvalidKeyError("Invalid key prefix".into()));
                }
                let mut output = [0; 32];
                output.copy_from_slice(&raw_key_w_prefix[4..]);
                Ok(Self(output))
            }
        }
    };
}

frontend_impl!(PublicKey);
frontend_impl!(PrivateKey);

#[cfg(test)]
mod tests {
    use crate::frontend::{PrivateKey, PublicKey};
    use rand::random;
    use snow::Keypair;

    #[test]
    fn conversion_consistency() {
        let builder = snow::Builder::new(crate::handshake_params());
        let keypair = builder.generate_keypair().unwrap();

        let pk = PublicKey::try_from(&keypair).unwrap();
        let sk = PrivateKey::try_from(&keypair).unwrap();

        let reconstructed = Keypair::try_from(sk).unwrap();
        let reconstructed_pk = PublicKey::try_from(&reconstructed).unwrap();
        assert_eq!(reconstructed.private, keypair.private);
        assert_eq!(reconstructed.public, keypair.public);
        assert_eq!(reconstructed_pk, pk);
    }

    #[test]
    fn key_formatting() {
        let rand_pub = PublicKey::from(random::<[u8; 32]>());
        let rand_pub_str = rand_pub.to_string();
        let reconstructed_key = rand_pub_str.parse::<PublicKey>().unwrap();
        assert_eq!(rand_pub, reconstructed_key);

        let rand_priv = PrivateKey::from(random::<[u8; 32]>());
        let rand_priv_str = rand_priv.to_string();
        let reconstructed_key = rand_priv_str.parse::<PrivateKey>().unwrap();
        assert_eq!(rand_priv, reconstructed_key);

        rand_pub_str
            .parse::<PrivateKey>()
            .expect_err("Error on parsing pubkey string to private key primitive");
        rand_priv_str
            .parse::<PublicKey>()
            .expect_err("Error on parsing privkey string to public key primitive");

        assert!(rand_pub_str.starts_with("publ"));
        assert!(rand_priv_str.starts_with("priv"));
    }
}
