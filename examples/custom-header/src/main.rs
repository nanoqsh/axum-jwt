use {
    axum::{Router, http::request::Parts, routing},
    axum_jwt::{Decoder, Extract, Token, jsonwebtoken::DecodingKey},
    serde::Deserialize,
    std::io::Result,
    tokio::net::TcpListener,
};

struct Custom;

impl Extract for Custom {
    fn extract(parts: &mut Parts) -> Option<&str> {
        parts.headers.get("X-Auth-Token")?.to_str().ok()
    }
}

#[derive(Deserialize)]
struct User {
    sub: String,
}

// Apply the custom token extractor.
async fn hello(Token { claims, .. }: Token<User, Custom>) -> String {
    format!("Hello, {}!", claims.sub)
}

#[tokio::main]
async fn main() -> Result<()> {
    let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));

    let app = Router::new()
        .route("/", routing::get(hello))
        // Note, you can also apply extractors to the middleware layer
        // .layer(axum_jwt::layer(decoder).with_extract(Custom))
        .with_state(decoder);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await
}
