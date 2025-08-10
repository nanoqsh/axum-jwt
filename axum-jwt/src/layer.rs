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

#[derive(Clone)]
pub struct JwtLayer(Decoder);

impl<S> Layer<S> for JwtLayer {
    type Service = Jwt<S>;

    fn layer(&self, svc: S) -> Self::Service {
        Jwt {
            decoder: self.0.clone(),
            svc,
        }
    }
}

pub fn layer(decoder: Decoder) -> JwtLayer {
    JwtLayer(decoder)
}

#[derive(Clone)]
pub struct Jwt<S> {
    decoder: Decoder,
    svc: S,
}

impl<S> Service<Request> for Jwt<S>
where
    S: Service<Request> + Clone,
    Result<S::Response, S::Error>: IntoResponse,
{
    type Response = Response;
    type Error = Infallible;
    type Future = JwtFuture<S>;

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
                JwtFutureProj::Done => unreachable!(),
            }
        };

        Poll::Ready(Ok(res))
    }
}
