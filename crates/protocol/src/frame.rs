//! Framing: length-prefixed MessagePack over a raw byte stream (e.g. TCP).
//!
//! Layout: `[u32 big-endian body length][body bytes]`.

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

/// Serialize `report` into a single length-prefixed frame.
pub fn encode(report: &Report) -> Result<Vec<u8>, ProtocolError> {
    let body = rmp_serde::to_vec_named(report)?;
    if body.len() as u64 > MAX_FRAME_LEN as u64 {
        return Err(ProtocolError::FrameTooLarge(body.len() as u32));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    Ok(buf)
}

/// Write one framed `report` to `w`.
pub fn write_report<W: Write>(w: &mut W, report: &Report) -> Result<(), ProtocolError> {
    w.write_all(&encode(report)?)?;
    Ok(())
}

/// Read exactly one framed report from `r`.
///
/// Returns `Ok(None)` on a clean EOF at a frame boundary (peer hung up between
/// messages); any other short read is an error.
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

/// Fill `buf` from `r`. Returns `Ok(false)` if EOF hits before the first byte,
/// `Ok(true)` once `buf` is full, and an error on EOF partway through.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 if filled == 0 => return Ok(false),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => filled += n,
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
