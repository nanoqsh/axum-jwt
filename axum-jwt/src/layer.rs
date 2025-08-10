//! Middleware types and traits.

use {
    crate::{
        decode::Decoder,
        error::Error,
        extract::{Bearer, Extract},
    },
    axum_core::{
        extract::Request,
        response::{IntoResponse, Response},
    },
    http::StatusCode,
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
pub struct JwtLayer<H = Discard, X = Bearer> {
    decoder: Decoder,
    validate: H,
    extract: PhantomData<X>,
}

impl<X> JwtLayer<Discard, X> {
    pub fn with_filter<F, I, O>(self, f: F) -> JwtLayer<Filter<F, I>, X>
    where
        F: FnMut(I) -> O,
        I: DeserializeOwned,
        O: Output,
    {
        JwtLayer {
            decoder: self.decoder,
            validate: Filter {
                f,
                input: PhantomData,
            },
            extract: PhantomData,
        }
    }
}

impl<H> JwtLayer<H, Bearer> {
    pub fn with_extract<X>(self, extract: X) -> JwtLayer<H, X>
    where
        X: Extract,
    {
        _ = extract;
        JwtLayer {
            decoder: self.decoder,
            validate: self.validate,
            extract: PhantomData,
        }
    }
}

impl<H, X> Clone for JwtLayer<H, X>
where
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            decoder: self.decoder.clone(),
            validate: self.validate.clone(),
            extract: PhantomData,
        }
    }
}

impl<H, X> fmt::Debug for JwtLayer<H, X>
where
    H: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtLayer")
            .field("decoder", &self.decoder)
            .field("validate", &self.validate)
            .field("extract", &any::type_name::<H>())
            .finish()
    }
}

impl<S, H> Layer<S> for JwtLayer<H>
where
    H: Clone,
{
    type Service = Jwt<S, H>;

    fn layer(&self, svc: S) -> Self::Service {
        Jwt {
            svc,
            decoder: self.decoder.clone(),
            validate: self.validate.clone(),
            extract: PhantomData,
        }
    }
}

/// Creates a layer for middleware.
pub fn layer(decoder: Decoder) -> JwtLayer {
    JwtLayer {
        decoder,
        validate: Discard,
        extract: PhantomData,
    }
}

/// Trait for additional token validation.
pub trait Validate {
    type Input: DeserializeOwned;
    type Output: Output;
    fn validate(&mut self, input: Self::Input) -> Self::Output;
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
#[derive(Clone, Debug)]
pub struct Discard;

impl Validate for Discard {
    type Input = IgnoredAny;
    type Output = bool;

    fn validate(&mut self, _: Self::Input) -> Self::Output {
        true
    }
}

/// Applies a validation function and returns its result.
pub struct Filter<F, A> {
    f: F,
    input: PhantomData<A>,
}

impl<F, A> Clone for Filter<F, A>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            input: PhantomData,
        }
    }
}

impl<F, A> fmt::Debug for Filter<F, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filter")
            .field("f", &"..")
            .field("input", &any::type_name::<A>())
            .finish()
    }
}

impl<F, I, O> Validate for Filter<F, I>
where
    F: FnMut(I) -> O,
    I: DeserializeOwned,
    O: Output,
{
    type Input = I;
    type Output = O;

    fn validate(&mut self, input: Self::Input) -> Self::Output {
        (self.f)(input)
    }
}

/// Axum [middleware] for token validation.
///
/// [middleware]: https://docs.rs/axum/latest/axum/middleware/index.html
pub struct Jwt<S, H = Discard, X = Bearer> {
    svc: S,
    decoder: Decoder,
    validate: H,
    extract: PhantomData<X>,
}

impl<S, H, X> Clone for Jwt<S, H, X>
where
    S: Clone,
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            decoder: self.decoder.clone(),
            validate: self.validate.clone(),
            extract: PhantomData,
        }
    }
}

impl<S, H, X> fmt::Debug for Jwt<S, H, X>
where
    S: fmt::Debug,
    H: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwt")
            .field("svc", &self.svc)
            .field("decoder", &self.decoder)
            .field("validate", &self.validate)
            .field("extract", &any::type_name::<X>())
            .finish()
    }
}

impl<S, H, X> Service<Request> for Jwt<S, H, X>
where
    S: Service<Request> + Clone,
    H: Validate,
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
        let validate = |parts| -> Result<H::Input, Error> {
            let token = X::extract(parts).ok_or(Error::Extract)?;
            let TokenData { claims, .. }: TokenData<H::Input> =
                self.decoder.decode(token).map_err(Error::Jwt)?;

            Ok(claims)
        };

        let (mut parts, body) = req.into_parts();
        match validate(&mut parts) {
            Ok(claims) => {
                if let Some(res) = self.validate.validate(claims).output() {
                    return JwtFuture::ready(res);
                }

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
