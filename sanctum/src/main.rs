mod auth;
mod middleware;
mod util;
mod vault;

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use axum::Router;
use base64::{Engine, prelude::BASE64_STANDARD};
use opaque_ke::ServerSetup;
use rand::rngs::OsRng;
use sanctum_shared::DefaultCipherSuite;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct AppState {
    server_setup: ServerSetup<DefaultCipherSuite>,
    db: PgPool,
    redis: redis::aio::ConnectionManager,
    jwt_secret: String,
}
type AppStateRef = std::sync::Arc<AppState>;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    setup_logging();

    let server_setup = get_server_setup();
    let redis = get_redis().await;
    let db = get_db().await;

    let state = AppState {
        server_setup,
        db,
        redis,
        jwt_secret: std::env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
    };

    let api_v1 = Router::new()
        .nest("/auth", auth::routes())
        .merge(vault::routes());

    let app = Router::new()
        .nest("/api/v1", api_v1)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(state));

    tracing::info!("Starting server on http://0.0.0.0:3000");

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// FIXME: remove all the unwraps: when an error
// occurs, just generate a new ServerSetup
fn get_server_setup() -> ServerSetup<DefaultCipherSuite> {
    if std::fs::exists(Path::new(".state.safe")).unwrap() {
        let mut file = File::open(".state.safe").unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        let setup = ServerSetup::deserialize(&BASE64_STANDARD.decode(content).unwrap()).unwrap();
        setup
    } else {
        let setup = ServerSetup::new(&mut OsRng);
        let mut file = File::create(".state.safe").unwrap();
        let content = BASE64_STANDARD.encode(setup.serialize());
        file.write_all(&content.as_bytes()).unwrap();
        setup
    }
}

fn setup_logging() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tower_http=debug,axum::rejection=trace,sanctum=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();
}

async fn get_redis() -> redis::aio::ConnectionManager {
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let redis_client = redis::Client::open(redis_url).unwrap();
    redis::aio::ConnectionManager::new(redis_client)
        .await
        .unwrap()
}

async fn get_db() -> PgPool {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgPool::connect(&db_url).await.unwrap()
}
