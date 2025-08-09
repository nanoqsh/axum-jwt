#![cfg_attr(all(doc, not(doctest)), doc = include_str!("../README.md"))]

mod decode;
mod extract;

pub use {
    crate::{
        decode::Decoder,
        extract::{Bearer, Claims, Error, Extract, Token},
    },
    jsonwebtoken,
};
