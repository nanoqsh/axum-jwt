use {
    axum::{Router, routing},
    axum_jwt::{Decoder, jsonwebtoken::DecodingKey},
    serde::Deserialize,
    std::io::Result,
    tokio::net::TcpListener,
};

#[derive(Deserialize)]
struct User {
    roles: Vec<String>,
}

async fn hello() -> &'static str {
    "Hello, Admin!"
}

fn check_access(u: User) -> bool {
    u.roles.iter().any(|role| role == "admin")
}

#[tokio::main]
async fn main() -> Result<()> {
    let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));

    let app = Router::new()
        .route("/", routing::get(hello))
        // This layer will validate the token
        // and check the presence of the role
        .layer(axum_jwt::layer(decoder).with_filter(check_access));

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await
}
