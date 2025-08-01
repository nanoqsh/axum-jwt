use {
    jsonwebtoken::{DecodingKey, TokenData, Validation},
    serde::de::DeserializeOwned,
    std::{fmt, sync::Arc},
};

/// The JWT decoder.
#[derive(Clone)]
pub struct Decoder(Arc<Inner>);

impl Decoder {
    pub fn from_key(key: DecodingKey) -> Self {
        Self(Arc::new(Inner {
            keys: vec![key],
            validation: Validation::default(),
        }))
    }

    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        Self(Arc::new(Inner {
            keys: vec![key],
            validation,
        }))
    }

    pub fn with_keys(keys: Vec<DecodingKey>, validation: Validation) -> Option<Self> {
        if keys.is_empty() {
            None
        } else {
            Some(Self(Arc::new(Inner { keys, validation })))
        }
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

struct Inner {
    keys: Vec<DecodingKey>,
    validation: Validation,
}
