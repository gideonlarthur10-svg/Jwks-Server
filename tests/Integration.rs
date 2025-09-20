use actix_web::{test, App};
use jwks_server::{state::KeyStore, handlers::{jwks, auth}};
use std::sync::Arc;
use serde_json::Value;
use jsonwebtoken::{decode_header};

#[actix_rt::test]
async fn test_jwks_and_auth() {
    let ks = KeyStore::new();
    // create an unexpired
    ks.generate_key(3600).unwrap();

    // create an expired key for the expired test by generating and then setting expiry to past:
    let expired_kid = ks.generate_key(1).unwrap();
    // force it to be expired by setting expiry in the past:
    {
        let mut keys = ks.keys.write().unwrap();
        if let Some(k) = keys.iter_mut().find(|k| k.kid == expired_kid) {
            k.expiry = chrono::Utc::now() - chrono::Duration::seconds(10);
        }
    }

    let shared = Arc::new(ks);

    let app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::from(shared.clone()))
            .route("/jwks", actix_web::web::get().to(jwks))
            .route("/auth", actix_web::web::post().to(auth))
    ).await;

    // JWKS
    let req = test::TestRequest::get().uri("/jwks").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body: Value = test::read_body_json(resp).await;
    assert!(body.get("keys").is_some());

    // auth (normal)
    let req = test::TestRequest::post().uri("/auth").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body: Value = test::read_body_json(resp).await;
    let token = body.get("token").unwrap().as_str().unwrap();
    let header = decode_header(token).unwrap();
    assert!(header.kid.is_some());

    // auth with expired param (should return token signed with expired kid)
    let req = test::TestRequest::post().uri("/auth?expired=1").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body2: Value = test::read_body_json(resp).await;
    let token2 = body2.get("token").unwrap().as_str().unwrap();
    let header2 = decode_header(token2).unwrap();
    // header2.kid should be present
    assert!(header2.kid.is_some());
}
