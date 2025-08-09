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
        task::{Context, Poll},
    },
    tower::{Layer, Service, ServiceExt, util::Oneshot},
};

pub fn layer<S>(decoder: Decoder) -> impl Layer<S, Service = Middleware<S>> + Clone {
    #[derive(Clone)]
    struct Jwt(Decoder);

    impl<S> Layer<S> for Jwt {
        type Service = Middleware<S>;

        fn layer(&self, inner: S) -> Self::Service {
            Middleware {
                decoder: self.0.clone(),
                inner,
            }
        }
    }

    Jwt(decoder)
}

#[derive(Clone)]
pub struct Middleware<S> {
    decoder: Decoder,
    inner: S,
}

impl<S> Service<Request> for Middleware<S>
where
    S: Service<Request> + Clone,
    Result<S::Response, S::Error>: IntoResponse,
{
    type Response = Response;
    type Error = Infallible;
    type Future = MiddlewareFuture<Oneshot<S, Request>>;

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
                let clone = self.inner.clone();
                let inner = mem::replace(&mut self.inner, clone);
                let fut = inner.oneshot(req);
                MiddlewareFuture::Oneshot(Box::pin(fut))
            }
            Err(e) => MiddlewareFuture::Ready(e.into_response()),
        }
    }
}

pub enum MiddlewareFuture<F> {
    Oneshot(Pin<Box<F>>),
    Ready(Response),
    End,
}

impl<F> Future for MiddlewareFuture<F>
where
    F: Future<Output: IntoResponse>,
{
    type Output = Result<Response, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        match mem::replace(me, Self::End) {
            Self::Oneshot(mut fut) => match Pin::new(&mut fut).poll(cx) {
                Poll::Ready(res) => Poll::Ready(Ok(res.into_response())),
                Poll::Pending => {
                    *me = Self::Oneshot(fut);
                    Poll::Pending
                }
            },
            Self::Ready(res) => Poll::Ready(Ok(res)),
            Self::End => unreachable!(),
        }
    }
}
