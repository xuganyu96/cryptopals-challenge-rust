//! Client
use std::net::TcpStream;
use crypto_bigint::Encoding;
use cryptopals::dh::{DHParams, KeyPair};
use std::io::Write;

fn main() {
    let port = 8888;
    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect(&addr).unwrap();
    println!("Opened connection to {stream:?}");

    let params: DHParams<32> = DHParams::pgen(2048);
    let keypair: KeyPair<32> = KeyPair::keygen(&params, 256);
    println!("{keypair:?}");

    let x = stream.write(&keypair.get_params().get_prime().to_be_bytes()).unwrap();
    println!("{x} bytes written");
}
