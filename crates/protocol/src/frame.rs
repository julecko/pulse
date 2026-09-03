//! Framing: length-prefixed MessagePack over a raw byte stream (e.g. TCP).
//!
//! Layout: `[u32 big-endian body length][body bytes]`.
//!
//! The sync [`read_report`] / [`write_report`] work on any [`std::io`] stream.
//! With the `async` feature, [`read_report_async`] / [`write_report_async`]
//! provide the same framing over a tokio [`AsyncRead`]/[`AsyncWrite`].

use std::io::{self, Read, Write};

use crate::{MAX_FRAME_LEN, Report};

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("frame of {0} bytes exceeds MAX_FRAME_LEN ({MAX_FRAME_LEN})")]
    FrameTooLarge(u32),
}

/// MessagePack-encode a report's body (no length prefix). This is the exact
/// payload [`encode`] frames; stored verbatim as the `body` blob by the server.
pub fn encode_body(report: &Report) -> Result<Vec<u8>, ProtocolError> {
    Ok(rmp_serde::to_vec_named(report)?)
}

/// Decode a body produced by [`encode_body`] (or the framed body from [`encode`]).
pub fn decode_body(bytes: &[u8]) -> Result<Report, ProtocolError> {
    Ok(rmp_serde::from_slice(bytes)?)
}

pub fn encode(report: &Report) -> Result<Vec<u8>, ProtocolError> {
    let body = encode_body(report)?;
    if body.len() as u64 > MAX_FRAME_LEN as u64 {
        return Err(ProtocolError::FrameTooLarge(body.len() as u32));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    Ok(buf)
}

pub fn write_report<W: Write>(w: &mut W, report: &Report) -> Result<(), ProtocolError> {
    w.write_all(&encode(report)?)?;
    Ok(())
}

pub fn read_report<R: Read>(r: &mut R) -> Result<Option<Report>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    if !read_exact_or_eof(r, &mut len_buf)? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(rmp_serde::from_slice(&body)?))
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            // A TLS peer that hangs up without a close_notify, exactly at a
            // frame boundary, is a clean disconnect for our purposes.
            Err(e) if filled == 0 && e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[cfg(feature = "async")]
pub async fn write_report_async<W>(w: &mut W, report: &Report) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    w.write_all(&encode(report)?).await?;
    Ok(())
}

#[cfg(feature = "async")]
pub async fn read_report_async<R>(r: &mut R) -> Result<Option<Report>, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    if !async_read_exact_or_eof(r, &mut len_buf).await? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    tokio::io::AsyncReadExt::read_exact(r, &mut body).await?;
    Ok(Some(rmp_serde::from_slice(&body)?))
}

#[cfg(feature = "async")]
async fn async_read_exact_or_eof<R>(r: &mut R, buf: &mut [u8]) -> io::Result<bool>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]).await {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            // A TLS peer that hangs up without a close_notify, exactly at a
            // frame boundary, is a clean disconnect for our purposes.
            Err(e) if filled == 0 && e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use crate::{HostInfo, MemoryInfo, Metrics, Report};

    use super::*;

    #[test]
    fn round_trips_through_a_frame() {
        let report = Report::new(
            HostInfo {
                hostname: "box".into(),
                ..Default::default()
            },
            Metrics {
                memory: Some(MemoryInfo {
                    total_bytes: 16,
                    used_bytes: 8,
                    free_bytes: 8,
                    swap_total_bytes: 0,
                    swap_used_bytes: 0,
                }),
                ..Default::default()
            },
        );

        let bytes = encode(&report).unwrap();
        let mut cursor = io::Cursor::new(bytes);
        let decoded = read_report(&mut cursor).unwrap().unwrap();

        assert_eq!(decoded.host.hostname, "box");
        assert_eq!(decoded.metrics.memory.unwrap().total_bytes, 16);
        assert!(decoded.metrics.cpu.is_none());
    }

    #[test]
    fn clean_eof_yields_none() {
        let mut empty = io::Cursor::new(Vec::new());
        assert!(read_report(&mut empty).unwrap().is_none());
    }
}
