#![cfg_attr(all(doc, not(doctest)), doc = include_str!("../README.md"))]

mod decode;
mod error;
mod extract;
pub mod layer;

pub use {
    crate::{
        decode::Decoder,
        error::Error,
        extract::{Bearer, Claims, Extract, Token},
        layer::layer,
    },
    jsonwebtoken,
};
