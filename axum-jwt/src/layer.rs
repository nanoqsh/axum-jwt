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
    jsonwebtoken::TokenData,
    serde::de::IgnoredAny,
    std::{
        convert::Infallible,
        mem,
        pin::Pin,
        task::{self, Context, Poll},
    },
    tower_layer::Layer,
    tower_service::Service,
};

pub fn layer<S>(decoder: Decoder) -> impl Layer<S, Service = Middleware<S>> + Clone {
    #[derive(Clone)]
    struct Jwt(Decoder);

    impl<S> Layer<S> for Jwt {
        type Service = Middleware<S>;

        fn layer(&self, svc: S) -> Self::Service {
            Middleware {
                decoder: self.0.clone(),
                svc,
            }
        }
    }

    Jwt(decoder)
}

#[derive(Clone)]
pub struct Middleware<S> {
    decoder: Decoder,
    svc: S,
}

impl<S> Service<Request> for Middleware<S>
where
    S: Service<Request> + Clone + Unpin,
    Result<S::Response, S::Error>: IntoResponse,
{
    type Response = Response;
    type Error = Infallible;
    type Future = MiddlewareFuture<S>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let validate = |parts| -> Result<(), Error> {
            let token = Bearer::exrtact(parts).ok_or(Error::Extract)?;
            let TokenData {
                claims: IgnoredAny, ..
            } = self.decoder.decode(token).map_err(Error::Jwt)?;

            Ok(())
        };

        let (mut parts, body) = req.into_parts();
        match validate(&mut parts) {
            Ok(()) => {
                let req = Request::from_parts(parts, body);
                let clone = self.svc.clone();
                let svc = mem::replace(&mut self.svc, clone);
                MiddlewareFuture::NotReady { svc, req }
            }
            Err(e) => MiddlewareFuture::Ready(e.into_response()),
        }
    }
}

pub enum MiddlewareFuture<S>
where
    S: Service<Request>,
{
    NotReady { svc: S, req: Request },
    Called { fut: Pin<Box<S::Future>> },
    Ready(Response),
    Done,
}

impl<S> Future for MiddlewareFuture<S>
where
    S: Service<Request> + Unpin,
    Result<S::Response, S::Error>: IntoResponse,
{
    type Output = Result<Response, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        let res = loop {
            match me {
                Self::NotReady { svc, req } => {
                    if let Err(e) = task::ready!(svc.poll_ready(cx)) {
                        *me = Self::Done;
                        break Err(e).into_response();
                    }

                    let req = mem::take(req);
                    let fut = svc.call(req);
                    *me = Self::Called { fut: Box::pin(fut) };
                }
                Self::Called { fut } => {
                    let res = task::ready!(fut.as_mut().poll(cx));
                    *me = Self::Done;
                    break res.into_response();
                }
                Self::Ready(res) => {
                    let res = mem::take(res);
                    *me = Self::Done;
                    break res;
                }
                Self::Done => unreachable!(),
            }
        };

        Poll::Ready(Ok(res))
    }
}
