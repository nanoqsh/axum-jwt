use {
    crate::{
        decode::Decoder,
        error::Error,
        extract::{Bearer, Extract},
    },
    axum_core::extract::Request,
    jsonwebtoken::TokenData,
    serde::de::IgnoredAny,
    std::{
        pin::Pin,
        task::{Context, Poll},
    },
    tower_service::Service,
};

pub struct Middleware<S> {
    decoder: Decoder,
    inner: S,
}

impl<S> Service<Request> for Middleware<S>
where
    S: Service<Request, Future: 'static>,
{
    type Response = S::Response;
    type Error = Error<S::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::Custom)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let validate = |parts| {
            let token = Bearer::exrtact(parts).ok_or(Error::Extract)?;
            let TokenData {
                claims: IgnoredAny, ..
            } = self.decoder.decode(token).map_err(Error::Jwt)?;

            Ok(())
        };

        let (mut parts, body) = req.into_parts();
        let res: Result<_, Error> = validate(&mut parts).map(|()| {
            let req = Request::from_parts(parts, body);
            self.inner.call(req)
        });

        Box::pin(async {
            match res {
                Ok(fut) => fut.await.map_err(Error::Custom),
                Err(e) => Err(e.map(|never| match never {})),
            }
        })
    }
}
