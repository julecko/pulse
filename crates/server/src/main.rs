mod connection;

use std::io;

use tokio::net::TcpListener;

const DEFAULT_BIND: &str = "127.0.0.1:9000";

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let bind = std::env::var("PULSE_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let listener = TcpListener::bind(&bind).await?;
    println!("pulse server listening on {bind}");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(async move {
                    if let Err(err) = connection::handle(stream, peer).await {
                        eprintln!("connection error ({peer}): {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }
}
