use actix_web::{http::header, web, HttpRequest, HttpResponse, Responder};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;
use serde::Serialize;

use crate::db;

type DbPool = Pool<SqliteConnectionManager>;

/// Quick/lenient Basic auth parser (mocked — we do not validate)
fn _parse_basic_auth(req: &HttpRequest) -> Option<(String, String)> {
    use base64::{engine::general_purpose, Engine as _};

    let hdr = req.headers().get(header::AUTHORIZATION)?;
    let s = hdr.to_str().ok()?;
    // Expect "Basic <b64>"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 2 || parts[0] != "Basic" {
        return None;
    }
    let decoded = general_purpose::STANDARD.decode(parts[1]).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    // Expect "user:pass"
    let mut it = decoded.splitn(2, ':');
    let u = it.next()?.to_string();
    let p = it.next().unwrap_or("").to_string();
    Some((u, p))
}

#[derive(Serialize)]
struct TokenResponse<'a> {
    token: &'a str,
    kid: String,
    key_expiry: i64,
}

/// POST /auth
/// - If `?expired=true`, use an expired key; otherwise use an unexpired key.
/// - JWT RS256 signed; header.kid set to DB `kid`.
pub async fn auth(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    // Parse (and ignore) HTTP Basic if present (for Gradebot)
    let _maybe_basic = _parse_basic_auth(&req);

    let want_expired = query
        .get("expired")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // pick key
    let now = Utc::now().timestamp();
    let row = match db::get_one_key(&pool, want_expired, now) {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::InternalServerError().body("no suitable key"),
        Err(e) => return HttpResponse::InternalServerError().body(format!("db error: {e}")),
    };

    // Build EncodingKey from PEM
    let encoding = match EncodingKey::from_rsa_pem(row.pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => return HttpResponse::InternalServerError().body(format!("bad key: {e}")),
    };

    // Claims
    #[derive(Serialize)]
    struct Claims {
        sub: String,
        iat: i64,
        exp: i64,
        username: String,
    }
    let now_dt = Utc::now();
    let exp = now_dt + Duration::minutes(5);
    let claims = Claims {
        sub: "fake-user".into(),
        iat: now_dt.timestamp(),
        exp: exp.timestamp(),
        username: "userABC".into(), // per spec; not actually validated
    };

    // JWT header with kid
    let mut hdr = Header::new(Algorithm::RS256);
    hdr.kid = Some(row.kid.to_string());

    let token = match jsonwebtoken::encode(&hdr, &claims, &encoding) {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().body(format!("sign error: {e}")),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "token": token,
        "kid": row.kid.to_string(),
        "key_expiry": row.exp
    }))
}

/// GET /.well-known/jwks.json
/// - Read all unexpired keys, convert each PEM to JWK (n,e),
///   and return a JWKS document.
pub async fn jwks(pool: web::Data<DbPool>) -> impl Responder {
    let now = Utc::now().timestamp();

    let rows = match db::get_all_unexpired(&pool, now) {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().body(format!("db error: {e}")),
    };

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
    struct Jwks<'a> {
        keys: Vec<Jwk<'a>>,
    }

    let mut keys = Vec::with_capacity(rows.len());
    for r in rows {
        match db::pem_to_n_e(&r.pem) {
            Ok((n, e)) => keys.push(Jwk {
                kty: "RSA",
                alg: "RS256",
                use_field: "sig",
                kid: r.kid.to_string(),
                n,
                e,
            }),
            Err(e) => {
                // skip bad rows; or you can return 500
                log::warn!("PEM parse failed for kid {}: {e}", r.kid);
            }
        }
    }

    HttpResponse::Ok().json(Jwks { keys })
}
