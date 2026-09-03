mod connection;

use std::io;
use std::net::TcpListener;
use std::thread;

const DEFAULT_BIND: &str = "127.0.0.1:9000";

fn main() -> io::Result<()> {
    let bind = std::env::var("PULSE_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let listener = TcpListener::bind(&bind)?;
    println!("pulse server listening on {bind}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(err) = connection::handle(stream) {
                        eprintln!("connection error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }
    Ok(())
}
