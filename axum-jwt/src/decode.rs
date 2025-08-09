use {
    axum_core::extract::FromRef,
    jsonwebtoken::{DecodingKey, TokenData, Validation},
    serde::de::DeserializeOwned,
    std::{fmt, ops::Deref, sync::Arc},
};

/// A decoder for JSON Web Tokens (JWTs).
///
/// To extract a JWT value from a request header, this decoder must be provided
/// to the [router] using the [`with_state`] method.
///
/// [router]: https://docs.rs/axum/latest/axum/struct.Router.html
/// [`with_state`]: https://docs.rs/axum/latest/axum/struct.Router.html#method.with_state
///
/// # Examples
///
/// You can pass the decoder directly:
///
/// ```
/// use {
///     axum::{Router, routing},
///     axum_jwt::{Claims, Decoder, jsonwebtoken::DecodingKey},
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
///
/// let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));
///
/// let app = Router::new()
///     .route("/", routing::get(hello))
///     .with_state(decoder);
/// # let _: Router = app;
/// ```
///
/// If the application needs to store additional state, you can define a custom
/// type that contains the decoder. You'll also need the application state to
/// be cheap to clone, so it makes sense to wrap it in an [`Arc`]. In this
/// case, you can provide the decoder by implementing the [`AsRef`] trait for
/// your custom state.
///
/// ```
/// # use {
/// #     axum::{Router, routing},
/// #     axum_jwt::{Decoder, jsonwebtoken::DecodingKey},
/// #     std::sync::{Arc, Mutex},
/// # };
/// # struct User;
/// struct App {
///     decoder: Decoder,
///     users_online: Mutex<Vec<User>>,
/// }
///
/// impl AsRef<Decoder> for App {
///     fn as_ref(&self) -> &Decoder {
///         &self.decoder
///     }
/// }
///
/// let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));
///
/// # async fn hello() {}
/// let app = Router::new()
///     .route("/", routing::get(hello))
///     .with_state(Arc::new(App {
///         decoder,
///         users_online: Mutex::default(),
///     }));
/// # let _: Router = app;
/// ```
#[derive(Clone)]
pub struct Decoder(Arc<Inner>);

impl Decoder {
    /// Creates a decoder from the provided decoding key.
    pub fn from_key(key: DecodingKey) -> Self {
        Self(Arc::new(Inner {
            keys: vec![key],
            validation: Validation::default(),
        }))
    }

    /// Creates a decoder from the provided decoding key and validation.
    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        Self(Arc::new(Inner {
            keys: vec![key],
            validation,
        }))
    }

    /// Creates a decoder from the provided decoding keys and validation.
    ///
    /// If the given vector is empty, this constructor will return `None`.
    pub fn with_keys(keys: Vec<DecodingKey>, validation: Validation) -> Option<Self> {
        if keys.is_empty() {
            None
        } else {
            Some(Self(Arc::new(Inner { keys, validation })))
        }
    }

    /// Returns a slice of decoding keys.
    pub fn keys(&self) -> &[DecodingKey] {
        &self.0.keys
    }

    /// Returns a reference to the validation.
    pub fn validation(&self) -> &Validation {
        &self.0.validation
    }

    pub(crate) fn decode<T>(&self, token: &str) -> Result<TokenData<T>, jsonwebtoken::errors::Error>
    where
        T: DeserializeOwned,
    {
        let decoder = &*self.0;
        let mut err = None;
        for key in &decoder.keys {
            match jsonwebtoken::decode(token, key, &decoder.validation) {
                Ok(data) => return Ok(data),
                Err(e) => err = Some(e),
            }
        }

        Err(err.expect("take error"))
    }
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("keys", &"..")
            .field("validation", &self.0.validation)
            .finish()
    }
}

impl<P> FromRef<P> for Decoder
where
    P: Deref<Target: AsRef<Decoder>>,
{
    fn from_ref(p: &P) -> Self {
        p.as_ref().clone()
    }
}

struct Inner {
    keys: Vec<DecodingKey>,
    validation: Validation,
}
