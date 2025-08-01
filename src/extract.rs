use {
    crate::decode::Decoder,
    axum_core::{
        extract::{FromRef, FromRequestParts},
        response::{IntoResponse, Response},
    },
    http::{StatusCode, request::Parts},
    jsonwebtoken::{Header, TokenData},
    serde::de::DeserializeOwned,
};

/// JWT [extractor](https://docs.rs/axum/latest/axum/extract/index.html) type.
#[derive(Clone, Debug)]
pub struct Token<T, X = AuthorizationExtract> {
    pub header: Header,
    pub claims: T,
    pub exrtact: X,
}

impl<S, T, X> FromRequestParts<S> for Token<T, X>
where
    Decoder: FromRef<S>,
    S: Sync,
    T: DeserializeOwned + Send,
    X: Extract,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = X::exrtact(parts).ok_or(Error::AuthorizationHeader)?;
        let decoder = Decoder::from_ref(state);
        let TokenData { header, claims } = decoder.decode(token).map_err(Error::Jwt)?;

        Ok(Token {
            header,
            claims,
            exrtact: X::default(),
        })
    }
}

/// JWT [extractor](https://docs.rs/axum/latest/axum/extract/index.html) type returning only claims.
#[derive(Clone, Copy, Debug)]
pub struct Claims<T>(pub T);

impl<S, T> FromRequestParts<S> for Claims<T>
where
    Decoder: FromRef<S>,
    S: Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Token { claims, .. }: Token<_, AuthorizationExtract> =
            Token::from_request_parts(parts, state).await?;

        Ok(Claims(claims))
    }
}

/// Trait for token extraction.
pub trait Extract: Default {
    fn exrtact(parts: &mut Parts) -> Option<&str>;
}

/// The token extraction from `Authorization` header.
#[derive(Clone, Debug, Default)]
pub struct AuthorizationExtract;

impl Extract for AuthorizationExtract {
    fn exrtact(parts: &mut Parts) -> Option<&str> {
        let auth = parts.headers.get("Authorization")?;
        let token = auth.as_bytes().strip_prefix(b"Bearer ")?;
        str::from_utf8(token).ok()
    }
}

/// Authorization error.
#[derive(Debug)]
pub enum Error {
    AuthorizationHeader,
    Jwt(jsonwebtoken::errors::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
