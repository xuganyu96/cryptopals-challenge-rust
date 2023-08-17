//! Convenience functions for hex and base64 encoding
use crate::common;
use base64;
use base64::{engine::general_purpose, Engine as _};
use hex;

pub fn encode_hex(bytes: &[u8]) -> String {
    return hex::encode(bytes);
}

pub fn decode_hex(hexstr: &str) -> common::Result<Vec<u8>> {
    let bytes = hex::decode(hexstr)?;
    return Ok(bytes);
}

pub fn encode_base64(bytes: &[u8]) -> String {
    return general_purpose::STANDARD.encode(bytes);
}

pub fn decode_base64(base64str: &str) -> common::Result<Vec<u8>> {
    let bytes = general_purpose::STANDARD.decode(base64str)?;
    return Ok(bytes);
}
