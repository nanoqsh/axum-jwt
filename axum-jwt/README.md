<div align="center">
    <h1>axum-jwt</h1>
    <p>
        JSON Web Token extractors and middleware for <a href="https://github.com/tokio-rs/axum">axum</a> framework
    </p>
    <p>
        <a href="https://crates.io/crates/axum-jwt"><img src="https://img.shields.io/crates/v/axum-jwt.svg"></img></a>
        <a href="https://docs.rs/axum-jwt"><img src="https://docs.rs/axum-jwt/badge.svg"></img></a>
    </p>
</div>

## About

The library provides [extractors](https://docs.rs/axum/latest/axum/extract/index.html) for performing JWT authentication. Under the hood, tokens are parsed using the [`jsonwebtoken`](https://docs.rs/jsonwebtoken/latest/jsonwebtoken) crate. For more details, see the [documentation](https://docs.rs/axum-jwt).

## Example

In this example, the request token is validated and the user ID is extracted:

```rust
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
```

In case of failed authentication, for example if the token is invalid or expired, a `401 Unauthorized` status code is returned.
