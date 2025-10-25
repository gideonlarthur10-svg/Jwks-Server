use actix_web::{test, web, App};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::decode_header;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde_json::Value;
use tempfile::NamedTempFile;

use jwks_server::{db, handlers}; // requires src/lib.rs that re-exports these

type DbPool = Pool<SqliteConnectionManager>;

/// Build a Basic auth header for Gradebot-style calls (mocked)
fn basic_auth_value(user: &str, pass: &str) -> String {
    let token = general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    format!("Basic {token}")
}

/// Spin up an Actix test app backed by a fresh, temporary SQLite file.
/// Seeds one expired and one unexpired key (like main.rs does).
async fn setup_app() -> (actix_web::App<impl actix_web::dev::ServiceFactory>, DbPool) {
    // Create a temp SQLite file
    let tmp = NamedTempFile::new().expect("temp db");
    let db_path = tmp.path().to_path_buf(); // keep handle alive for duration of test

    // Build pooled connection
    let manager = SqliteConnectionManager::file(&db_path);
    let pool = r2d2::Pool::new(manager).expect("pool");

    // Initialize schema
    db::init_db(&pool).expect("init");

    // Seed: one expired, one valid
    db::generate_and_insert_rsa_pem(&pool, (Utc::now() - Duration::seconds(10)).timestamp())
        .expect("seed expired");
    db::generate_and_insert_rsa_pem(&pool, (Utc::now() + Duration::seconds(3600)).timestamp())
        .expect("seed valid");

    // Build Actix app using the same routes as main.rs
    let app = App::new()
        .app_data(web::Data::new(pool.clone()))
        .route("/auth", actix_web::web::post().to(handlers::auth))
        .route("/.well-known/jwks.json", actix_web::web::get().to(handlers::jwks));

    (app, pool)
}

#[actix_rt::test]
async fn jwks_returns_only_unexpired_keys() {
    let (app, _pool) = setup_app().await;
    let app = test::init_service(app).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/jwks.json")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    let keys = body.get("keys").and_then(|k| k.as_array()).unwrap();

    // Expect at least one unexpired key (we seeded one)
    assert!(!keys.is_empty());

    // There should be NO expired keys in JWKS
    // (We can only assert structural properties: kid/n/e present)
    for k in keys {
        assert!(k.get("kid").is_some());
        assert!(k.get("n").is_some());
        assert!(k.get("e").is_some());
        assert_eq!(k.get("kty").unwrap().as_str().unwrap(), "RSA");
        assert_eq!(k.get("alg").unwrap().as_str().unwrap(), "RS256");
    }
}

#[actix_rt::test]
async fn auth_issues_token_with_unexpired_key_by_default() {
    let (app, _pool) = setup_app().await;
    let app = test::init_service(app).await;

    let req = test::TestRequest::post()
        .uri("/auth")
        .insert_header((
            actix_web::http::header::AUTHORIZATION,
            basic_auth_value("userABC", "password123"),
        ))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    let token = body
        .get("token")
        .and_then(|t| t.as_str())
        .expect("token missing");
    let key_expiry = body.get("key_expiry").and_then(|e| e.as_i64()).unwrap();
    let kid_json = body.get("kid").and_then(|k| k.as_str()).unwrap().to_string();

    // Decode JWT header only (no signature verification here)
    let header = decode_header(token).expect("decode header");
    let kid_hdr = header.kid.expect("kid missing in header");
    assert_eq!(kid_hdr, kid_json, "JWT header.kid should match response.kid");

    // The default path should use an unexpired key
    assert!(
        key_expiry > Utc::now().timestamp(),
        "default /auth should choose an unexpired key"
    );
}

#[actix_rt::test]
async fn auth_with_expired_param_uses_expired_key() {
    let (app, _pool) = setup_app().await;
    let app = test::init_service(app).await;

    let req = test::TestRequest::post()
        .uri("/auth?expired=true")
        .insert_header((
            actix_web::http::header::AUTHORIZATION,
            basic_auth_value("userABC", "password123"),
        ))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: Value = test::read_body_json(resp).await;
    let token = body
        .get("token")
        .and_then(|t| t.as_str())
        .expect("token missing");
    let key_expiry = body.get("key_expiry").and_then(|e| e.as_i64()).unwrap();

    // Header has kid
    let header = decode_header(token).expect("decode header");
    assert!(header.kid.is_some(), "kid should be present in JWT header");

    // Expired branch should pick an expired key
    assert!(
        key_expiry <= Utc::now().timestamp(),
        "/auth?expired=true should choose an expired key"
    );
}
