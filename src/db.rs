use anyhow::{anyhow, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use chrono::Utc;

use aes_gcm::{Aes256Gcm, Key, Nonce}; // OrKey, Nonce
use aes_gcm::aead::{Aead, KeyInit};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use openssl::rsa::Rsa;
use openssl::bn::BigNumRef;

use crate::utils::base64url;

pub type DbPool = Pool<SqliteConnectionManager>;

#[derive(Clone, Debug)]
pub struct KeyRowDecrypted {
    pub kid: i64,
    pub pem: String,
    pub exp: i64,
}

// === AES key material (derived from NOT_MY_KEY) ===
#[derive(Clone)]
pub struct AesKey(pub [u8; 32]);

pub fn derive_aes_key_from_env() -> Result<AesKey> {
    let raw = std::env::var("NOT_MY_KEY")
        .map_err(|_| anyhow!("NOT_MY_KEY not set"))?;
    // Derive a fixed 32-byte key from whatever string using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    Ok(AesKey(out))
}

pub fn init_db(pool: &DbPool) -> Result<()> {
    let conn = pool.get()?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,    -- AES-GCM ciphertext
            iv  BLOB NOT NULL,    -- nonce/IV used for encryption
            exp INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        "#,
    )?;
    Ok(())
}

pub fn count_keys(pool: &DbPool) -> Result<i64> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM keys")?;
    let cnt: i64 = stmt.query_row([], |row| row.get(0))?;
    Ok(cnt)
}

// === RSA generation + AES encrypt + insert ===
pub fn generate_encrypt_and_insert(pool: &DbPool, aes: &AesKey, exp_unix: i64) -> Result<i64> {
    let rsa = Rsa::generate(2048)?;
    let pem = rsa.private_key_to_pem_pkcs1()?;
    insert_encrypted_key(pool, aes, &pem, exp_unix)
}

pub fn insert_encrypted_key(pool: &DbPool, aes: &AesKey, pem_pkcs1: &[u8], exp_unix: i64) -> Result<i64> {
    // AES-256-GCM with random 96-bit nonce
    let key = Key::<Aes256Gcm>::from_slice(&aes.0);
    let cipher = Aes256Gcm::new(key);

    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher.encrypt(nonce, pem_pkcs1)
        .map_err(|e| anyhow!("encrypt: {e}"))?;

    let conn = pool.get()?;
    let mut stmt = conn.prepare("INSERT INTO keys(key, iv, exp) VALUES(?1, ?2, ?3)")?;
    stmt.execute(params![ciphertext, iv.to_vec(), exp_unix])?;
    Ok(conn.last_insert_rowid())
}

pub fn get_one_key_decrypted(pool: &DbPool, aes: &AesKey, expired: bool, now_unix: i64)
    -> Result<Option<KeyRowDecrypted>>
{
    let conn = pool.get()?;
    let sql = if expired {
        "SELECT kid, key, iv, exp FROM keys WHERE exp <= ?1 ORDER BY exp DESC LIMIT 1"
    } else {
        "SELECT kid, key, iv, exp FROM keys WHERE exp >  ?1 ORDER BY exp DESC LIMIT 1"
    };
    let mut stmt = conn.prepare(sql)?;
    let row = stmt.query_row(params![now_unix], |r| {
        let kid: i64 = r.get(0)?;
        let ct: Vec<u8> = r.get(1)?;
        let iv: Vec<u8> = r.get(2)?;
        let exp: i64 = r.get(3)?;

        let key = Key::<Aes256Gcm>::from_slice(&aes.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&iv);

        let plain = cipher.decrypt(nonce, ct.as_ref())
            .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(anyhow!("decrypt: {e}"))))?;

        let pem = String::from_utf8(plain)
            .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(anyhow!("pem utf8: {e}"))))?;
        Ok(KeyRowDecrypted { kid, pem, exp })
    }).optional()?;
    Ok(row)
}

pub struct KeyRowEnc {
    pub kid: i64,
    pub key_ct: Vec<u8>,
    pub iv: Vec<u8>,
    pub exp: i64,
}

// List unexpired keys (still encrypted) => decrypt to compute JWKS (n, e)
pub fn get_all_unexpired_enc(pool: &DbPool, now_unix: i64) -> Result<Vec<KeyRowEnc>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("SELECT kid, key, iv, exp FROM keys WHERE exp > ?1 ORDER BY exp DESC")?;
    let rows = stmt.query_map(params![now_unix], |r| {
        Ok(KeyRowEnc {
            kid: r.get(0)?,
            key_ct: r.get(1)?,
            iv: r.get(2)?,
            exp: r.get(3)?,
        })
    })?.collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

// Turn private PEM -> (n,e) for JWK
pub fn pem_to_n_e(pem_pkcs1: &str) -> Result<(String, String)> {
    let rsa = openssl::rsa::Rsa::private_key_from_pem(pem_pkcs1.as_bytes())?;
    Ok((bn_to_b64(rsa.n()), bn_to_b64(rsa.e())))
}

fn bn_to_b64(bn: &BigNumRef) -> String { base64url(&bn.to_vec()) }

// === Users & logs ===
pub fn insert_user(pool: &DbPool, username: &str, email: Option<&str>, password_hash: &str) -> Result<i64> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("INSERT INTO users(username, password_hash, email) VALUES(?1, ?2, ?3)")?;
    stmt.execute(params![username, password_hash, email])?;
    Ok(conn.last_insert_rowid())
}

pub fn find_user_by_username(pool: &DbPool, username: &str) -> Result<Option<(i64, String)>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("SELECT id, password_hash FROM users WHERE username = ?1")?;
    stmt.query_row(params![username], |r| Ok((r.get(0)?, r.get(1)?))).optional().map_err(Into::into)
}

pub fn touch_last_login(pool: &DbPool, user_id: i64) -> Result<()> {
    let conn = pool.get()?;
    conn.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?1", params![user_id])?;
    Ok(())
}

pub fn log_auth(pool: &DbPool, user_id: i64, ip: &str) -> Result<i64> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("INSERT INTO auth_logs(request_ip, user_id) VALUES(?1, ?2)")?;
    stmt.execute(params![ip, user_id])?;
    Ok(conn.last_insert_rowid())
}
  
