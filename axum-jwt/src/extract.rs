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

/// JWT [extractor] type.
///
/// [extractor]: https://docs.rs/axum/latest/axum/extract/index.html
///
/// # Examples
///
/// Extract the [header](Header) and claims from a token:
///
/// ```
/// use {
///     axum_jwt::Token,
///     serde::Deserialize,
/// };
///
/// #[derive(Deserialize)]
/// struct User {
///     sub: String,
/// }
///
/// async fn hello(Token { header, claims, .. }: Token<User>) -> String {
///     format!("decoded with {:?} algorithm: {}", header.alg, claims.sub)
/// }
/// ```
///
/// Note that to extract a token, the application [state] must contain
/// a [decoder](Decoder).
///
/// [state]: https://docs.rs/axum/latest/axum/struct.Router.html#method.with_state
///
/// ```
/// use {
///     axum::{Router, routing},
///     axum_jwt::{Decoder, jsonwebtoken::DecodingKey},
/// };
///
/// let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));
///
/// # async fn hello() {}
/// let app = Router::new()
///     .route("/", routing::get(hello))
///     .with_state(decoder);
/// # let _: Router = app;
/// ```
#[derive(Clone, Debug)]
pub struct Token<T, X = Bearer>
where
    T: DeserializeOwned,
    X: Extract,
{
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
        let token = X::exrtact(parts).ok_or(Error::Extract)?;
        let decoder = Decoder::from_ref(state);
        let TokenData { header, claims } = decoder.decode(token).map_err(Error::Jwt)?;

        Ok(Token {
            header,
            claims,
            exrtact: X::default(),
        })
    }
}

/// JWT [extractor] type returning only claims.
///
/// [extractor]: https://docs.rs/axum/latest/axum/extract/index.html
///
/// # Examples
///
/// Extract user claims:
///
/// ```
/// use {
///     axum_jwt::Claims,
///     serde::Deserialize,
/// };
///
/// #[derive(Deserialize)]
/// struct User {
///     sub: String,
/// }
///
/// async fn hello(Claims(u): Claims<User>) -> String {
///     format!("Hello, {}!", u.sub)
/// }
/// ```
///
/// Note that to extract a token, the application [state] must contain
/// a [decoder](Decoder).
///
/// [state]: https://docs.rs/axum/latest/axum/struct.Router.html#method.with_state
///
/// ```
/// use {
///     axum::{Router, routing},
///     axum_jwt::{Decoder, jsonwebtoken::DecodingKey},
/// };
///
/// let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));
///
/// # async fn hello() {}
/// let app = Router::new()
///     .route("/", routing::get(hello))
///     .with_state(decoder);
/// # let _: Router = app;
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Claims<T>(pub T)
where
    T: DeserializeOwned;

impl<S, T> FromRequestParts<S> for Claims<T>
where
    Decoder: FromRef<S>,
    S: Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Token { claims, .. }: Token<_> = Token::from_request_parts(parts, state).await?;
        Ok(Claims(claims))
    }
}

/// Trait for token extraction.
pub trait Extract: Default {
    fn exrtact(parts: &mut Parts) -> Option<&str>;
}

/// The token extraction from a header with `Bearer` authentication scheme.
#[derive(Clone, Debug, Default)]
pub struct Bearer;

impl Extract for Bearer {
    fn exrtact(parts: &mut Parts) -> Option<&str> {
        let auth = parts.headers.get("Authorization")?;
        let token = auth.as_bytes().strip_prefix(b"Bearer ")?;
        str::from_utf8(token).ok()
    }
}

/// Errors that can occur during authentication.
#[derive(Debug)]
pub enum Error {
    /// Failed to extract authentication data from the request.
    Extract,

    /// JWT error.
    Jwt(jsonwebtoken::errors::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
