use {
    axum::{Router, routing},
    axum_jwt::{Claims, Decoder, jsonwebtoken::DecodingKey},
    serde::Deserialize,
    std::io::Error,
    tokio::net::TcpListener,
};

#[derive(Deserialize)]
struct User {
    sub: String,
}

async fn hello(Claims(u): Claims<User>) -> String {
    format!("Hello, {}!", u.sub)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));

    let app = Router::new()
        .route("/", routing::get(hello))
        .with_state(decoder);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await
}
