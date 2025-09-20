use actix_web::{web, HttpResponse, Responder, http::header};
use crate::state::{KeyStore};
use serde::{Serialize, Deserialize};
use jsonwebtoken::{EncodingKey, Header, Algorithm};
use chrono::{Utc, Duration};
use anyhow::Result;

#[derive(Serialize)]
struct JwksResponse {
    keys: serde_json::Value,
}

pub async fn jwks(store: web::Data<std::sync::Arc<KeyStore>>) -> impl Responder {
    let jwks = store.jwks();
    HttpResponse::Ok().json(jwks)
}

/// /auth: POST -> returns signed JWT.
/// Query: ?expired=1 to force signing with an expired key.
/// No body required (per assignment), but could be extended.
pub async fn auth(store: web::Data<std::sync::Arc<KeyStore>>, q: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let want_expired = q.get("expired").map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false);

    // choose key
    let maybe_key = if want_expired {
        store.pick_expired_key().or_else(|| store.pick_unexpired_key())
    } else {
        store.pick_unexpired_key()
    };

    let key = match maybe_key {
        Some(k) => k,
        None => {
            return HttpResponse::InternalServerError().body("No key available for signing");
        }
    };

    // build claims
    #[derive(Serialize)]
    struct Claims {
        sub: String,
        iat: i64,
        exp: i64,
    }

    let now = Utc::now();
    let exp = now + Duration::seconds(300); // token valid 5 minutes (for example)

    let claims = Claims {
        sub: "fake-user".into(),
        iat: now.timestamp(),
        exp: exp.timestamp(),
    };

    // create encoding key from private PEM
    let encoding_key = match EncodingKey::from_rsa_pem(&key.private_pem) {
        Ok(k) => k,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Cannot build encoding key: {}", e));
        }
    };

    // header with kid
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());

    match jsonwebtoken::encode(&header, &claims, &encoding_key) {
        Ok(token) => {
            HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .json(serde_json::json!({ "token": token, "kid": key.kid, "key_expiry": key.expiry }))
        }
        Err(err) => HttpResponse::InternalServerError().body(format!("Signing error: {}", err)),
    }
}
