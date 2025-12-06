use actix_web::{http::header, web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use jsonwebtoken::{Header, Algorithm, EncodingKey};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use password_hash::{SaltString, PasswordHash};
use uuid::Uuid;
use base64::{engine::general_purpose, Engine as _};

use crate::db;
use crate::db::DbPool;
use crate::AppState;

fn parse_basic(req: &HttpRequest) -> Option<(String, String)> {
    let hdr = req.headers().get(header::AUTHORIZATION)?;
    let s = hdr.to_str().ok()?;
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 2 || parts[0] != "Basic" { return None; }
    let decoded = general_purpose::STANDARD.decode(parts[1]).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let mut it = s.splitn(2, ':');
    Some((it.next()?.to_string(), it.next().unwrap_or("").to_string()))
}

// -------------------- REGISTER --------------------

#[derive(Deserialize)]
pub struct RegisterIn {
    username: String,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterOut {
    password: String,
}

pub async fn register(state: web::Data<AppState>, body: web::Json<RegisterIn>) -> impl Responder {
    // generate password
    let password = Uuid::new_v4().to_string();

    // hash with Argon2 (reasonable defaults; you can tune params)
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            log::error!("argon2 error: {e}");
            HttpResponse::InternalServerError().finish()
        })?
        .to_string();

    // store
    match db::insert_user(&state.pool, &body.username, body.email.as_deref(), &hash) {
        Ok(_) => HttpResponse::Created().json(RegisterOut { password }),
        Err(e) => {
            // uniqueness errors, etc.
            log::warn!("insert user failed: {e}");
            HttpResponse::BadRequest().body("username or email already exists")
        }
    }
}

// -------------------- AUTH --------------------

#[derive(Serialize)]
struct AuthOut<'a> {
    token: &'a str,
    kid: String,
    key_expiry: i64,
}

pub async fn auth(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    // rate limit: 10 req/s global
    if let Err(_) = state.limiter.check() {
        return HttpResponse::TooManyRequests().finish();
    }

    let (username, password) = match parse_basic(&req) {
        Some(v) => v,
        None => return HttpResponse::Unauthorized().body("Basic auth required"),
    };

    // verify user
    let (user_id, stored_hash) = match db::find_user_by_username(&state.pool, &username) {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::Unauthorized().finish(),
        Err(e) => return HttpResponse::InternalServerError().body(format!("db error: {e}")),
    };
    let parsed = PasswordHash::new(&stored_hash).map_err(|_| HttpResponse::InternalServerError())?;
    if Argon2::default().verify_password(password.as_bytes(), &parsed).is_err() {
        return HttpResponse::Unauthorized().finish();
    }

    // pick key (expired flag)
    let want_expired = query
        .get("expired")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let now = Utc::now().timestamp();

    let row = match db::get_one_key_decrypted(&state.pool, &state.aes, want_expired, now) {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::InternalServerError().body("no suitable key"),
        Err(e) => return HttpResponse::InternalServerError().body(format!("db err: {e}")),
    };

    // sign JWT
    #[derive(Serialize)]
    struct Claims {
        sub: String,
        iat: i64,
        exp: i64,
        username: String,
        uid: i64,
    }
    let iat = Utc::now();
    let claims = Claims {
        sub: "user".into(),
        iat: iat.timestamp(),
        exp: (iat + Duration::minutes(5)).timestamp(),
        username: username.clone(),
        uid: user_id,
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(row.kid.to_string());
    let enc = match EncodingKey::from_rsa_pem(row.pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => return HttpResponse::InternalServerError().body(format!("bad key: {e}")),
    };
    let token = match jsonwebtoken::encode(&header, &claims, &enc) {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().body(format!("sign error: {e}")),
    };

    // log success (only successful requests are logged)
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();
    let _ = db::log_auth(&state.pool, user_id, &ip);
    let _ = db::touch_last_login(&state.pool, user_id);

    HttpResponse::Ok().json(serde_json::json!({
        "token": token,
        "kid": row.kid.to_string(),
        "key_expiry": row.exp
    }))
}

// -------------------- JWKS --------------------

#[derive(Serialize)]
struct Jwk<'a> {
    kty: &'a str,
    alg: &'a str,
    #[serde(rename = "use")]
    use_field: &'a str,
    kid: String,
    n: String,
    e: String,
}
#[derive(Serialize)]
struct Jwks<'a> { keys: Vec<Jwk<'a>> }

pub async fn jwks(state: web::Data<AppState>) -> impl Responder {
    let now = Utc::now().timestamp();
    let enc_rows = match db::get_all_unexpired_enc(&state.pool, now) {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().body(format!("db err: {e}")),
    };

    // decrypt each private key to compute (n,e)
    let mut out = Vec::with_capacity(enc_rows.len());
    for r in enc_rows {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&state.aes.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&r.iv);
        match cipher.decrypt(nonce, r.key_ct.as_ref()) {
            Ok(plain) => {
                if let Ok(pem) = String::from_utf8(plain) {
                    if let Ok((n, e)) = db::pem_to_n_e(&pem) {
                        out.push(Jwk {
                            kty: "RSA",
                            alg: "RS256",
                            use_field: "sig",
                            kid: r.kid.to_string(),
                            n, e
                        });
                    }
                }
            }
            Err(e) => {
                log::warn!("decrypt failed for kid {}: {e}", r.kid);
            }
        }
    }

    HttpResponse::Ok().json(Jwks { keys: out })
}


  
  
