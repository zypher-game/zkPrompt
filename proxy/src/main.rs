use anyhow::Result;
use clap::Parser;
use hickory_resolver::TokioAsyncResolver;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
};

async fn forward(mut from: ReadHalf<TcpStream>, mut to: WriteHalf<TcpStream>) -> Result<()> {
    loop {
        let mut data = vec![];
        let mut buffer = [0u8; 8192]; // read 8k buffer

        // TODO read more than 8k
        let n = from.read(&mut buffer).await?;
        if n == 0 {
            continue;
        }
        data.extend(&buffer[..n]);

        println!("read buffer: {}", data.len());

        // check the data is tls data
        if is_tls_handshake_packet(&data) {
            println!("TLS packet");
        } else {
            println!("Data packet{:?}", data);
            // TODO commitment for the prompt data
        }

        to.write_all(&data).await?;
    }

    // Ok(())
}

/// TLS Handshake signal 0x16
fn is_tls_handshake_packet(packet: &[u8]) -> bool {
    match packet[0] {
        0x14 | 0x15 | 0x16 => true,
        _ => false,
    }
}

async fn handle_client(client_stream: TcpStream, addr: SocketAddr) -> Result<()> {
    let target_stream = TcpStream::connect(addr).await?;

    let (client_reader, mut client_writer) = tokio::io::split(client_stream);
    let (mut target_reader, target_writer) = tokio::io::split(target_stream);

    // handle request transfer
    tokio::spawn(forward(client_reader, target_writer));

    // not handle response transfer
    tokio::io::copy(&mut target_reader, &mut client_writer).await?;

    Ok(())
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Command {
    /// Service port
    #[arg(short, long, env = "PORT", default_value = "9100")]
    port: u16,

    /// Forward host service, e.g. api.openai.com
    #[arg(short, long, env = "FORWARD")]
    forward: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let args = Command::parse();

    let self_addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let listener = TcpListener::bind(self_addr).await.unwrap();
    let res = TokioAsyncResolver::tokio_from_system_conf()
        .unwrap()
        .lookup_ip(&args.forward)
        .await
        .unwrap();
    let server_ip = res.iter().next().expect("no addresses returned!");
    let server_addr = SocketAddr::new(server_ip, 443); // use tls default port

    println!("Listening on 0.0.0.0:{}", args.port);
    println!("Forwarding to {} -> {}", args.forward, server_addr);

    loop {
        let (client_stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = handle_client(client_stream, server_addr).await;
        });
    }
}
