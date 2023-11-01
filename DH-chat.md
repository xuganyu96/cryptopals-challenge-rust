Let's write a (horribly insecure) network protocol that uses Diffie-Hellman key exchange to establish a shared secret, then uses AES128 exchange messages. Although after a secure connection is established there is no distinction between the two peer, we denote the one who initiates the connection the client and the other side the server.

There needs to be a procedure for establishing the connection, I propose to go as follows:

1. Server starts listening
1. Client opens TCP stream to the server
1. Client generates parameters and key pairs, then sends over the parameters and the public key
1. Server receives parameters and client's public key, generate its own key pair, and sends over server's public key
1. Client and server each computes the shared secret, derives the AES-128 key, then start communicating

Using `crypto-bigint` it is fairly straightforward to implement the [math](./src/dh.rs). It remains to implement the handshake protocol

```rust
struct DHChatStream {
    keypair: KeyPair,
    stream: TcpStream,
}

impl DHChatStream {
    /// Used by the client to initiate a DHChat connection. If a connection
    /// is established, return Ok(); else return the appropriate error
    fn initiate_handshake(tcpstream: TcpStream) -> Result<Self, ...> {
        let params = ...;
        let keypairs = ...;
        
        tcpstream.write(&keypairs.serialize());
        let peer_pk = KeyPair::deserialize(tcpstream.read());
        let secret = keypair.get_shared_secret(&peer_pk);

        // Instantiate the AES cipher

        return Ok(Self { ... });
    }
}

fn client() {
    let stream = TcpStream::connect("address").unwrap();
    let stream = DHChatStream::new(stream);
}
```