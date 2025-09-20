use actix_web::{web, App, HttpServer};
use std::sync::Arc;
mod handlers;
mod state;
mod utils;

use state::KeyStore;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Create a KeyStore with a couple of keys
    let ks = KeyStore::new();
    // generate two keys: one short-lived, one longer-lived for demo
    ks.generate_key(60).expect("gen");      // expires in 60s
    ks.generate_key(60 * 60 * 24).expect("gen"); // expires in 24h

    let shared = Arc::new(ks);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::from(shared.clone()))
            .route("/jwks", web::get().to(handlers::jwks))
            .route("/auth", web::post().to(handlers::auth))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
