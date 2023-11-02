use crate::dh::{DHParams, KeyPair, PublicKey, SECRET_KEY_SIZE};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

/// Similar to TcpStream, but with the added steps of negotiating secret key using Diffie-Hellman
/// (2048 bits) and encrypting the communicated bytes using AES128-CBC
pub struct DHStream {}

impl DHStream {
    /// Connect to a server, negotiate the parameters, initialize the cipher. If all these steps
    /// are successful, then return Ok(Self), which is ready to be written to and read from
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Self, Box<dyn Error>> {
        let mut stream = TcpStream::connect(addr)?;
        let params = DHParams::pgen();
        let client_keypair = KeyPair::keygen(&params, SECRET_KEY_SIZE);

        stream.write(&client_keypair.get_pk().to_be_bytes())?;

        let mut server_pkbytes = [0u8; PublicKey::BYTES];
        stream.read_exact(&mut server_pkbytes)?;
        let server_pk = PublicKey::from_be_bytes(server_pkbytes);
        let shared_secret = client_keypair.get_shared_secret(&server_pk)?;
        println!("Shared secret {shared_secret:?}");

        // TODO: derive cipher suite and getting ready for I/O
        return Ok(Self {});
    }

    /// Bind to an address and listen for incoming parameter negotiation. Upon receiving a public
    /// key, generate the server pk and transmit it back to the client. If the handshake is
    /// successful, then initialize the cipher
    pub fn bind(addr: impl ToSocketAddrs) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind(addr)?;
        let (mut stream, _addr) = listener.accept()?;
        let mut client_pkbytes = [0u8; PublicKey::BYTES];
        stream.read_exact(&mut client_pkbytes)?;

        let client_pk = PublicKey::from_be_bytes(client_pkbytes);
        let server_keypair = KeyPair::keygen(&client_pk.get_params(), SECRET_KEY_SIZE);
        let shared_secret = server_keypair.get_shared_secret(&client_pk).unwrap();
        stream.write(&server_keypair.get_pk().to_be_bytes())?;
        println!("Shared secret {shared_secret:?}");

        // TODO: derive cipher suite and getting ready for I/O
        return Ok(Self {});
    }
}

pub fn client_main(host: &str, port: u16) {
    let addr = format!("{host}:{port}");
    DHStream::connect(&addr).unwrap();
}

pub fn server_main(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    DHStream::bind(&addr).unwrap();
}
