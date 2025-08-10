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
        convert::Infallible,
        marker::PhantomData,
        mem,
        pin::Pin,
        task::{self, Context, Poll},
    },
    tower_layer::Layer,
    tower_service::Service,
};

#[derive(Clone, Debug)]
pub struct JwtLayer<H = Discard> {
    decoder: Decoder,
    handle: H,
}

impl JwtLayer {
    pub fn filter<F, I, O>(self, f: F) -> JwtLayer<Filter<F, I>>
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
        }
    }
}

impl<S, H> Layer<S> for JwtLayer<H>
where
    H: Clone,
{
    type Service = Jwt<S, H>;

    fn layer(&self, svc: S) -> Self::Service {
        Jwt {
            decoder: self.decoder.clone(),
            handle: self.handle.clone(),
            svc,
        }
    }
}

pub fn layer(decoder: Decoder) -> JwtLayer {
    JwtLayer {
        decoder,
        handle: Discard,
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

#[derive(Clone)]
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

#[derive(Clone, Debug)]
pub struct Jwt<S, H = Discard> {
    decoder: Decoder,
    handle: H,
    svc: S,
}

impl<S, H> Service<Request> for Jwt<S, H>
where
    S: Service<Request> + Clone,
    H: Handle,
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
            let token = Bearer::exrtact(parts).ok_or(Error::Extract)?;
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
