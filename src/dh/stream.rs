//! A toy implementation of a network protocol in which the two parties first negoriate a common
//! secret using the Diffie-Hellman key exchange, then use AES128-CBC to communicate confidentially
//!
//! Denote the two peers by Alice and Bob. Suppose that Alice initiates the channel:
use std::net::TcpStream;
use std::io::{Read, Write};

fn handshake() {
    let stream = TcpStream::connect("127.0.0.1:8080").unwrap();

}
