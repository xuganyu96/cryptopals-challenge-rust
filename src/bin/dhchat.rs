//! DH Chat
use clap::{Parser, Subcommand};
use cryptopals::dh::stream;

const DEFAULT_PORT: u16 = 8888;

/// An E2E encrypted chat
#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Connect to a running instance of a server
    Client {
        /// The host to connect to; defaults to "127.0.0.1"
        #[arg(long)]
        host: Option<String>,

        /// The port to run DH-Chat on; defaults to 8888
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Start an instance of the server
    Server {
        /// The port to listen-in on
        #[arg(short, long)]
        port: Option<u16>,
    },
}

fn main() {
    let args = Args::parse();
    match args.command {
        Commands::Client { host, port } => {
            let host = host.unwrap_or("127.0.0.1".to_string());
            let port = port.unwrap_or(DEFAULT_PORT);
            stream::client_main(&host, port)
        }
        Commands::Server { port } => {
            let port = port.unwrap_or(DEFAULT_PORT);
            stream::server_main(port);
        }
    }
}
