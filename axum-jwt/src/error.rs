use {
    axum_core::response::{IntoResponse, Response},
    http::StatusCode,
    std::convert::Infallible,
};

/// Errors that can occur during authentication.
#[derive(Debug)]
pub enum Error<U = Infallible> {
    /// Failed to extract authentication data from the request.
    Extract,

    /// JWT error.
    Jwt(jsonwebtoken::errors::Error),

    /// Custom error.
    Custom(U),
}

impl<U> Error<U> {
    pub fn map<F, E>(self, f: F) -> Error<E>
    where
        F: FnOnce(U) -> E,
    {
        match self {
            Self::Extract => Error::Extract,
            Self::Jwt(e) => Error::Jwt(e),
            Self::Custom(u) => Error::Custom(f(u)),
        }
    }
}

impl<U> IntoResponse for Error<U>
where
    U: IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Error::Extract | Error::Jwt(_) => StatusCode::UNAUTHORIZED.into_response(),
            Error::Custom(u) => u.into_response(),
        }
    }
}
