//! Server
use std::net::TcpListener;
use std::io::Read;
use crypto_bigint::{U2048, NonZero};

fn main() {
    let port = 8888;
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).unwrap();
    println!("Listening on port {port}....");
    let (mut stream, addr) = listener.accept().unwrap();
    println!("{stream:?}, {addr:?}");


    let mut buf: [u8; 256] = [0; 256];
    let _x = stream.read(&mut buf).unwrap();
    let p: NonZero<U2048> = NonZero::from_be_bytes(buf).unwrap();
    println!("prime is {p}");
}
