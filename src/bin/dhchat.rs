//! DH Chat
use std::net::{TcpStream, TcpListener};
use std::io::{Write, Read};
use clap::{Parser, Subcommand};
use cryptopals::dh::{MODULUS_SIZE, SECRET_KEY_SIZE, DHParams, KeyPair, PublicKey};

const DEFAULT_PORT: u16 = 8888;

#[derive(Debug, Parser)]
struct Args {

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Client {
        /// The host to connect to; defaults to "127.0.0.1"
        #[arg(long)]
        host: Option<String>,

        /// The port to run DH-Chat on; defaults to 8888
        #[arg(short, long)]
        port: Option<u16>,
    },
    Server {
        /// The port to listen-in on
        #[arg(short, long)]
        port: Option<u16>,
    },
}

fn client_main(host: &str, port: u16) {
    let params = DHParams::pgen(MODULUS_SIZE);
    let keypair = KeyPair::keygen(&params, SECRET_KEY_SIZE);
    println!("Generated key pair");

    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).unwrap();
    println!("Connected to {stream:?}");

    if let Ok(x) = stream.write(&keypair.get_pk().to_be_bytes()) {
        println!("{x} bytes written");
    }

    let mut server_pkbytes = [0u8; PublicKey::BYTES];
    stream.read_exact(&mut server_pkbytes).unwrap();
    let server_pk = PublicKey::from_be_bytes(server_pkbytes);
    let shared_secret = keypair.get_shared_secret(&server_pk);

    dbg!(shared_secret);
}

fn server_main(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).unwrap();
    let (mut stream, addr) = listener.accept().unwrap();
    println!("Listening in on {addr}");

    let mut pkbytes = [0u8; PublicKey::BYTES];
    if let Ok(_) = stream.read_exact(&mut pkbytes) {
        println!("{} bytes received", PublicKey::BYTES);
    }

    let client_pk = PublicKey::from_be_bytes(pkbytes);
    let server_keypair = KeyPair::keygen(&client_pk.get_params(), SECRET_KEY_SIZE);
    let shared_secret = server_keypair.get_shared_secret(&client_pk);
    dbg!(shared_secret);

    stream.write(&server_keypair.get_pk().to_be_bytes()).unwrap();
}

fn main() {
    let args = Args::parse();
    match args.command {
        Commands::Client{ host, port } => {
            let host = host.unwrap_or("127.0.0.1".to_string());
            let port = port.unwrap_or(DEFAULT_PORT);
            client_main(&host, port)
        },
        Commands::Server{ port } => {
            let port = port.unwrap_or(DEFAULT_PORT);
            server_main(port);
        }
    }
}
