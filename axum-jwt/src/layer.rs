//! Middleware types and traits.

use {
    crate::{
        decode::Decoder,
        error::Error,
        extract::{Bearer, Extract, Token},
    },
    axum_core::{
        extract::Request,
        response::{IntoResponse, Response},
    },
    http::{Extensions, StatusCode},
    jsonwebtoken::TokenData,
    serde::de::{DeserializeOwned, IgnoredAny},
    std::{
        any,
        convert::Infallible,
        fmt,
        marker::PhantomData,
        mem,
        pin::Pin,
        task::{self, Context, Poll},
    },
    tower_layer::Layer,
    tower_service::Service,
};

/// Layer type for creating middleware.
///
/// To configure the layer and create the middleware service, call
/// the [`layer`] function.
pub struct JwtLayer<I = IgnoredAny, H = Discard, X = Bearer> {
    decoder: Decoder,
    validate: H,
    store: fn(Token<I>, &mut Extensions),
    extract: PhantomData<X>,
}

impl<I, X> JwtLayer<I, Discard, X> {
    pub fn with_filter<H, N, O>(self, validate: H) -> JwtLayer<N, H, X>
    where
        H: FnMut(&Token<N>) -> O,
        N: DeserializeOwned,
        O: Output,
    {
        JwtLayer {
            decoder: self.decoder,
            validate,
            store: |_, _| {},
            extract: PhantomData,
        }
    }
}

impl<I, H, X> JwtLayer<I, H, X> {
    pub fn store_to_extension(mut self) -> Self
    where
        I: Clone + Send + Sync + 'static,
    {
        self.store = |claims, extensions| {
            extensions.insert(claims);
        };

        self
    }
}

impl<I, H> JwtLayer<I, H, Bearer> {
    pub fn with_extract<X>(self, extract: X) -> JwtLayer<I, H, X>
    where
        X: Extract,
    {
        _ = extract;
        JwtLayer {
            decoder: self.decoder,
            validate: self.validate,
            store: self.store,
            extract: PhantomData,
        }
    }
}

impl<I, H, X> Clone for JwtLayer<I, H, X>
where
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            decoder: self.decoder.clone(),
            validate: self.validate.clone(),
            store: self.store,
            extract: PhantomData,
        }
    }
}

impl<I, H, X> fmt::Debug for JwtLayer<I, H, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtLayer")
            .field("decoder", &self.decoder)
            .field("validate", &"..")
            .field("store", &"..")
            .field("extract", &any::type_name::<H>())
            .finish()
    }
}

impl<S, I, H, X> Layer<S> for JwtLayer<I, H, X>
where
    H: Clone,
{
    type Service = Jwt<S, I, H>;

    fn layer(&self, svc: S) -> Self::Service {
        Jwt {
            svc,
            decoder: self.decoder.clone(),
            validate: self.validate.clone(),
            store: self.store,
            extract: PhantomData,
        }
    }
}

/// Creates a [layer](JwtLayer) for middleware.
///
/// # Examples
///
/// ```
/// use {
///     axum::{Router, routing},
///     axum_jwt::{Decoder, jsonwebtoken::DecodingKey},
/// };
///
/// // This handler will be called only if the token is successfully validated.
/// async fn hello() -> String {
///     "Hello, Anonimus!".to_owned()
/// }
///
/// let decoder = Decoder::from_key(DecodingKey::from_secret(b"secret"));
///
/// let app = Router::new()
///     .route("/", routing::get(hello))
///     .layer(axum_jwt::layer(decoder));
/// # let _: Router = app;
/// ```
pub fn layer(decoder: Decoder) -> JwtLayer {
    JwtLayer {
        decoder,
        validate: Discard,
        store: |_, _| {},
        extract: PhantomData,
    }
}

/// Trait for additional token validation.
pub trait Validate<I> {
    type Output: Output;
    fn validate(&mut self, input: &Token<I>) -> Self::Output;
}

/// The output value of the [validation](Validate).
pub trait Output {
    fn output(self) -> Option<Response>;
}

impl<E> Output for Result<(), E>
where
    E: IntoResponse,
{
    fn output(self) -> Option<Response> {
        self.err().map(E::into_response)
    }
}

impl Output for bool {
    fn output(self) -> Option<Response> {
        if self {
            None
        } else {
            Some(StatusCode::UNAUTHORIZED.into_response())
        }
    }
}

/// Discards any token data and returns success.
#[derive(Clone)]
pub struct Discard;

impl<I> Validate<I> for Discard {
    type Output = bool;

    fn validate(&mut self, _: &Token<I>) -> Self::Output {
        true
    }
}

impl<F, I, O> Validate<I> for F
where
    F: FnMut(&Token<I>) -> O,
    I: DeserializeOwned,
    O: Output,
{
    type Output = O;

    fn validate(&mut self, input: &Token<I>) -> Self::Output {
        self(input)
    }
}

/// Axum [middleware] for token validation.
///
/// [middleware]: https://docs.rs/axum/latest/axum/middleware/index.html
pub struct Jwt<S, I, H = Discard, X = Bearer> {
    svc: S,
    decoder: Decoder,
    validate: H,
    store: fn(Token<I>, &mut Extensions),
    extract: PhantomData<X>,
}

impl<S, I, H, X> Clone for Jwt<S, I, H, X>
where
    S: Clone,
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            decoder: self.decoder.clone(),
            validate: self.validate.clone(),
            store: self.store,
            extract: PhantomData,
        }
    }
}

impl<S, I, H, X> fmt::Debug for Jwt<S, I, H, X>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwt")
            .field("svc", &self.svc)
            .field("decoder", &self.decoder)
            .field("validate", &"..")
            .field("store", &"..")
            .field("extract", &any::type_name::<X>())
            .finish()
    }
}

impl<S, I, H, X> Service<Request> for Jwt<S, I, H, X>
where
    S: Service<Request> + Clone,
    I: DeserializeOwned,
    H: Validate<I>,
    X: Extract,
    Result<S::Response, S::Error>: IntoResponse,
{
    type Response = Response;
    type Error = Infallible;
    type Future = JwtFuture<S>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let validate = |parts| -> Result<Token<I>, Error> {
            let token = X::extract(parts).ok_or(Error::Extract)?;
            let TokenData { header, claims }: TokenData<I> =
                self.decoder.decode(token).map_err(Error::Jwt)?;

            Ok(Token::new(header, claims))
        };

        let (mut parts, body) = req.into_parts();
        match validate(&mut parts) {
            Ok(token) => {
                if let Some(res) = self.validate.validate(&token).output() {
                    return JwtFuture::ready(res);
                }

                (self.store)(token, &mut parts.extensions);

                let req = Request::from_parts(parts, body);
                let clone = self.svc.clone();
                let svc = mem::replace(&mut self.svc, clone);
                JwtFuture::not_ready(svc, req)
            }
            Err(e) => JwtFuture::ready(e.into_response()),
        }
    }
}

pin_project_lite::pin_project! {
    /// Middleware future.
    pub struct JwtFuture<S>
    where
        S: Service<Request>,
    {
        #[pin]
        state: State<S, S::Future>,
    }
}

impl<S> JwtFuture<S>
where
    S: Service<Request>,
{
    fn not_ready(svc: S, req: Request) -> Self {
        Self {
            state: State::NotReady { svc, req },
        }
    }

    fn ready(res: Response) -> Self {
        Self {
            state: State::Ready { res },
        }
    }
}

impl<S> Future for JwtFuture<S>
where
    S: Service<Request>,
    Result<S::Response, S::Error>: IntoResponse,
{
    type Output = Result<Response, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.project().state;
        let res = loop {
            match state.as_mut().project() {
                StateProj::NotReady { svc, req } => {
                    if let Err(e) = task::ready!(svc.poll_ready(cx)) {
                        state.set(State::Done);
                        break Err(e).into_response();
                    }

                    let req = mem::take(req);
                    let fut = svc.call(req);
                    state.set(State::Called { fut });
                }
                StateProj::Called { fut } => {
                    let res = task::ready!(fut.poll(cx));
                    state.set(State::Done);
                    break res.into_response();
                }
                StateProj::Ready { res } => {
                    let res = mem::take(res);
                    state.set(State::Done);
                    break res;
                }
                StateProj::Done => panic!("polled after completion"),
            }
        };

        Poll::Ready(Ok(res))
    }
}

pin_project_lite::pin_project! {
    #[project = StateProj]
    enum State<S, F> {
        NotReady { svc: S, req: Request },
        Called {
            #[pin]
            fut: F,
        },
        Ready { res: Response },
        Done,
    }
}
