use std::io;
use std::net::TcpStream;

use protocol::Report;

pub fn send(server: &str, report: &Report) -> io::Result<()> {
    let mut stream = TcpStream::connect(server)?;
    protocol::write_report(&mut stream, report).map_err(io::Error::other)
}
