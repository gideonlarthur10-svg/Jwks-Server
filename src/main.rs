 use actix_web::{web, App, HttpServer};
use chrono::{Duration, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

mod db;
mod utils;
mod handlers;

use db::{derive_aes_key_from_env, AesKey};

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool<SqliteConnectionManager>,
    pub aes: AesKey,
    // optional limiter (10 rps global)
    pub limiter: governor::RateLimiter<governor::state::InMemoryState, governor::state::NotKeyed, governor::clock::QuantaClock>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // DB pool
    let manager = SqliteConnectionManager::file("./totally_not_my_privateKeys.db");
    let pool = Pool::new(manager).expect("pool");

    // schema
    db::init_db(&pool).expect("init db");

    // AES key
    let aes = derive_aes_key_from_env().expect("NOT_MY_KEY missing");

    // seed keys
    if db::count_keys(&pool).expect("count") == 0 {
        db::generate_encrypt_and_insert(&pool, &aes, (Utc::now() - Duration::seconds(10)).timestamp()).expect("seed expired");
        db::generate_encrypt_and_insert(&pool, &aes, (Utc::now() + Duration::seconds(3600)).timestamp()).expect("seed valid");
    }

    // rate limiter: 10 req/s
    use governor::{Quota, clock::QuantaClock, state::InMemoryState, RateLimiter};
    let limiter = RateLimiter::direct_with_clock(Quota::per_second(nonzero_ext::nonzero!(10u32)), &QuantaClock::default());

    let state = AppState { pool: pool.clone(), aes, limiter };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/register", web::post().to(handlers::register))
            .route("/auth", web::post().to(handlers::auth))
            .route("/.well-known/jwks.json", web::get().to(handlers::jwks))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
