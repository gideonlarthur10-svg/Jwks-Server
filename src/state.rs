use serde::Serialize;
use openssl::rsa::Rsa;
use openssl::bn::BigNumRef;
use crate::utils::{base64url};
use chrono::{Utc, DateTime, Duration};
use uuid::Uuid;
use std::sync::RwLock;
use anyhow::Result;

#[derive(Clone)]
pub struct StoredKey {
    pub kid: String,
    pub expiry: DateTime<Utc>,
    pub private_pem: Vec<u8>, // pkcs1 PEM
    pub public_pem: Vec<u8>,
    // cached n/e for JWK
    pub n: String,
    pub e: String,
}

pub struct KeyStore {
    keys: RwLock<Vec<StoredKey>>,
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    n: String,
    e: String,
    alg: String,
    use_field: String,
    kid: String,
}

#[derive(Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self { keys: RwLock::new(Vec::new()) }
    }

    /// Generate an RSA key pair, store it with `kid` and expiry seconds from now
    pub fn generate_key(&self, expires_in_seconds: i64) -> Result<String> {
        // 2048-bit RSA
        let rsa = Rsa::generate(2048)?;
        let private_pem = rsa.private_key_to_pem_pkcs1()?;
        let public_pem = rsa.public_key_to_pem_pkcs1()?;

        let kid = Uuid::new_v4().to_string();
        let expiry = Utc::now() + Duration::seconds(expires_in_seconds);

        // get modulus and exponent as base64url (no padding)
        let n = big_uint_to_b64url(rsa.n());
        let e = big_uint_to_b64url(rsa.e());

        let sk = StoredKey {
            kid: kid.clone(),
            expiry,
            private_pem,
            public_pem,
            n,
            e,
        };

        self.keys.write().unwrap().push(sk);
        Ok(kid)
    }

    /// Return JWKS containing only unexpired keys as of now
    pub fn jwks(&self) -> Jwks {
        let now = Utc::now();
        let keys = self.keys.read().unwrap();
        let mut jwk_vec = Vec::new();
        for k in keys.iter() {
            if k.expiry > now {
                jwk_vec.push(Jwk {
                    kty: "RSA".into(),
                    n: k.n.clone(),
                    e: k.e.clone(),
                    alg: "RS256".into(),
                    use_field: "sig".into(),
                    kid: k.kid.clone(),
                });
            }
        }
        Jwks { keys: jwk_vec }
    }

    /// Pick an unexpired key to sign (most-recent unexpired)
    pub fn pick_unexpired_key(&self) -> Option<StoredKey> {
        let now = Utc::now();
        let keys = self.keys.read().unwrap();
        keys.iter()
            .filter(|k| k.expiry > now)
            .max_by_key(|k| k.expiry) // newest expiry
            .cloned()
    }

    /// Pick an expired key (most-recent expired) for the `expired` behavior
    pub fn pick_expired_key(&self) -> Option<StoredKey> {
        let now = Utc::now();
        let keys = self.keys.read().unwrap();
        keys.iter()
            .filter(|k| k.expiry <= now)
            .max_by_key(|k| k.expiry)
            .cloned()
    }

    /// get stored key by kid
    pub fn get_by_kid(&self, kid: &str) -> Option<StoredKey> {
        let keys = self.keys.read().unwrap();
        keys.iter().find(|k| k.kid == kid).cloned()
    }
}

fn big_uint_to_b64url(n: &BigNumRef) -> String {
    let bytes = n.to_vec(); // big-endian
    base64url(&bytes)
}
