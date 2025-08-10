use {
    axum::{Extension, Router, routing},
    axum_jwt::{Decoder, jsonwebtoken::DecodingKey},
    serde::Deserialize,
    std::io::Result,
    tokio::net::TcpListener,
};

// Note: you only need `Clone` if you want to use the `Extension` extractor.
#[derive(Clone, Deserialize)]
struct User {
    sub: String,
    roles: Vec<String>,
}

fn check_access(u: &User) -> bool {
    u.roles.iter().any(|role| role == "admin")
}

async fn hello() -> String {
    "Hello, Anonimus!".to_owned()
}

async fn hello_with_name(Extension(u): Extension<User>) -> String {
    format!("Hello, {}!", u.sub)
}

#[tokio::main]
async fn main() -> Result<()> {
    let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));

    let app = Router::new()
        .route("/hello", routing::get(hello))
        .route("/hello_with_name", routing::get(hello_with_name))
        // This layer will validate the token
        // and check the presence of the role
        .layer(
            axum_jwt::layer(decoder)
                .with_filter(check_access)
                .store_to_extension(),
        );

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await
}
