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

pub struct JwtLayer<H = Discard, X = Bearer> {
    decoder: Decoder,
    handle: H,
    extract: PhantomData<X>,
}

impl<X> JwtLayer<Discard, X> {
    pub fn filter<F, I, O>(self, f: F) -> JwtLayer<Filter<F, I>, X>
    where
        F: FnMut(I) -> O,
        I: DeserializeOwned,
        O: Output,
    {
        JwtLayer {
            decoder: self.decoder,
            handle: Filter {
                f,
                input: PhantomData,
            },
            extract: PhantomData,
        }
    }
}

impl<H> JwtLayer<H, Bearer> {
    pub fn extract_with<X>(self, extract: X) -> JwtLayer<H, X>
    where
        X: Extract,
    {
        _ = extract;
        JwtLayer {
            decoder: self.decoder,
            handle: self.handle,
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
            handle: self.handle.clone(),
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
            .field("handle", &self.handle)
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
            handle: self.handle.clone(),
            extract: PhantomData,
        }
    }
}

pub fn layer(decoder: Decoder) -> JwtLayer {
    JwtLayer {
        decoder,
        handle: Discard,
        extract: PhantomData,
    }
}

pub trait Handle {
    type Input: DeserializeOwned;
    type Output: Output;
    fn handle(&mut self, input: Self::Input) -> Self::Output;
}

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

#[derive(Clone, Debug)]
pub struct Discard;

impl Handle for Discard {
    type Input = IgnoredAny;
    type Output = bool;

    fn handle(&mut self, _: Self::Input) -> Self::Output {
        true
    }
}

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

impl<F, I, O> Handle for Filter<F, I>
where
    F: FnMut(I) -> O,
    I: DeserializeOwned,
    O: Output,
{
    type Input = I;
    type Output = O;

    fn handle(&mut self, input: Self::Input) -> Self::Output {
        (self.f)(input)
    }
}

pub struct Jwt<S, H = Discard, X = Bearer> {
    svc: S,
    decoder: Decoder,
    handle: H,
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
            handle: self.handle.clone(),
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
            .field("handle", &self.handle)
            .field("extract", &any::type_name::<X>())
            .finish()
    }
}

impl<S, H, X> Service<Request> for Jwt<S, H, X>
where
    S: Service<Request> + Clone,
    H: Handle,
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
                if let Some(res) = self.handle.handle(claims).output() {
                    return JwtFuture::Ready { res };
                }

                let req = Request::from_parts(parts, body);
                let clone = self.svc.clone();
                let svc = mem::replace(&mut self.svc, clone);
                JwtFuture::NotReady { svc, req }
            }
            Err(e) => JwtFuture::Ready {
                res: e.into_response(),
            },
        }
    }
}

pin_project_lite::pin_project! {
    #[project = JwtFutureProj]
    pub enum JwtFuture<S>
    where
        S: Service<Request>,
    {
        NotReady { svc: S, req: Request },
        Called {
            #[pin]
            fut: S::Future,
        },
        Ready { res: Response },
        Done,
    }
}

impl<S> Future for JwtFuture<S>
where
    S: Service<Request>,
    Result<S::Response, S::Error>: IntoResponse,
{
    type Output = Result<Response, Infallible>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let res = loop {
            match self.as_mut().project() {
                JwtFutureProj::NotReady { svc, req } => {
                    if let Err(e) = task::ready!(svc.poll_ready(cx)) {
                        self.set(Self::Done);
                        break Err(e).into_response();
                    }

                    let req = mem::take(req);
                    let fut = svc.call(req);
                    self.set(Self::Called { fut });
                }
                JwtFutureProj::Called { fut } => {
                    let res = task::ready!(fut.poll(cx));
                    self.set(Self::Done);
                    break res.into_response();
                }
                JwtFutureProj::Ready { res } => {
                    let res = mem::take(res);
                    self.set(Self::Done);
                    break res;
                }
                JwtFutureProj::Done => panic!("polled after completion"),
            }
        };

        Poll::Ready(Ok(res))
    }
}
