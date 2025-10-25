use anyhow::{anyhow, Result};
use chrono::Utc;
use openssl::rsa::Rsa;
use openssl::bn::BigNumRef;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

use crate::utils::base64url;

pub type DbPool = Pool<SqliteConnectionManager>;

#[derive(Clone, Debug)]
pub struct KeyRow {
    pub kid: i64,
    pub pem: String, // PKCS1 PEM (private)
    pub exp: i64,    // unix ts
}

pub fn init_db(pool: &DbPool) -> Result<()> {
    let conn = pool.get()?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
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

pub fn generate_and_insert_rsa_pem(pool: &DbPool, exp_unix: i64) -> Result<i64> {
    let rsa = Rsa::generate(2048)?;
    let pem = rsa.private_key_to_pem_pkcs1()?;
    insert_key(pool, std::str::from_utf8(&pem)?, exp_unix)
}

pub fn insert_key(pool: &DbPool, pem_pkcs1: &str, exp_unix: i64) -> Result<i64> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare("INSERT INTO keys(key, exp) VALUES(?1, ?2)")?;
    stmt.execute(params![pem_pkcs1.as_bytes(), exp_unix])?;
    let kid = conn.last_insert_rowid();
    Ok(kid)
}

/// Get one key based on desired expiry state.
pub fn get_one_key(pool: &DbPool, expired: bool, now_unix: i64) -> Result<Option<KeyRow>> {
    let conn = pool.get()?;
    let sql = if expired {
        "SELECT kid, key, exp FROM keys WHERE exp <= ?1 ORDER BY exp DESC LIMIT 1"
    } else {
        "SELECT kid, key, exp FROM keys WHERE exp >  ?1 ORDER BY exp DESC LIMIT 1"
    };
    let mut stmt = conn.prepare(sql)?;
    let row = stmt
        .query_row(params![now_unix], |r| {
            Ok(KeyRow {
                kid: r.get::<_, i64>(0)?,
                pem: {
                    let blob: Vec<u8> = r.get(1)?;
                    String::from_utf8(blob).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e)))?
                },
                exp: r.get(2)?,
            })
        })
        .optional()?;
    Ok(row)
}

/// All unexpired keys (for JWKS)
pub fn get_all_unexpired(pool: &DbPool, now_unix: i64) -> Result<Vec<KeyRow>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT kid, key, exp FROM keys WHERE exp > ?1 ORDER BY exp DESC",
    )?;
    let rows = stmt
        .query_map(params![now_unix], |r| {
            Ok(KeyRow {
                kid: r.get::<_, i64>(0)?,
                pem: {
                    let blob: Vec<u8> = r.get(1)?;
                    String::from_utf8(blob).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e)))?
                },
                exp: r.get(2)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Convert a PKCS1 private PEM to JWK n/e (base64url no padding)
pub fn pem_to_n_e(pem_pkcs1: &str) -> Result<(String, String)> {
    let rsa = Rsa::private_key_from_pem(pem_pkcs1.as_bytes())?;
    Ok((bn_to_b64(rsa.n()), bn_to_b64(rsa.e())))
}

fn bn_to_b64(bn: &BigNumRef) -> String {
    base64url(&bn.to_vec())
}
