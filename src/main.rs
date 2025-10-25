use actix_web::{web, App, HttpServer};
use chrono::{Duration, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::path::Path;

mod handlers;
mod utils; // base64url helper
mod db;    // <- you’ll add this (see notes below)

const DB_PATH: &str = "./totally_not_my_privateKeys.db";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // 1) Create/open SQLite connection pool
    if !Path::new(DB_PATH).exists() {
        // letting SQLite create it; no-op here
    }
    let manager = SqliteConnectionManager::file(DB_PATH);
    let pool: Pool<SqliteConnectionManager> =
        Pool::new(manager).expect("failed to create sqlite pool");

    // 2) Init schema
    db::init_db(&pool).expect("init db failed");

    // 3) Seed keys if table empty:
    //    - one expired (now - 10s)
    //    - one valid   (now + 3600s)
    let now = Utc::now().timestamp();
    let count = db::count_keys(&pool).expect("count failed");
    if count == 0 {
        // expired
        db::generate_and_insert_rsa_pem(
            &pool,
            (Utc::now() - Duration::seconds(10)).timestamp(),
        )
        .expect("insert expired failed");

        // valid
        db::generate_and_insert_rsa_pem(
            &pool,
            (Utc::now() + Duration::seconds(3600)).timestamp(),
        )
        .expect("insert valid failed");
    }

    // 4) Run HTTP server (share pool via actix Data)
    let shared_pool = web::Data::new(pool);

    HttpServer::new(move || {
        App::new()
            .app_data(shared_pool.clone())
            // JWKS as per spec path
            .route("/.well-known/jwks.json", web::get().to(handlers::jwks))
            // Auth endpoint
            .route("/auth", web::post().to(handlers::auth))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
