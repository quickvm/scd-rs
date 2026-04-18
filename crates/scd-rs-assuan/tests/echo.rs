//! End-to-end `ECHO` round-trip against a real Unix socket.
//!
//! Serves as the Phase 2 exit criterion: an `AssuanServer` bound to a socket
//! in a tempdir, a real tokio `UnixStream` client, and a handler that emits
//! its argument back as a `D` line.

use std::future::Future;

use scd_rs_assuan::{AssuanServer, CommandHandler, Connection, HandlerError};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

struct EchoHandler;

impl CommandHandler for EchoHandler {
    fn handle(
        &self,
        conn: &mut Connection,
        verb: &str,
        args: &str,
    ) -> impl Future<Output = Result<(), HandlerError>> + Send {
        let verb = verb.to_string();
        let args = args.to_string();
        async move {
            match verb.as_str() {
                "ECHO" => {
                    conn.write_data(args.as_bytes())
                        .await
                        .map_err(|e| HandlerError::new(100, e.to_string()))?;
                    Ok(())
                }
                // MANYBYTES <n>: emit `n` bytes of 'x' so we can test server-side
                // chunking without blowing the client-side command line limit.
                "MANYBYTES" => {
                    let n: usize = args
                        .parse()
                        .map_err(|_| HandlerError::new(100, "expected integer"))?;
                    let payload = vec![b'x'; n];
                    conn.write_data(&payload)
                        .await
                        .map_err(|e| HandlerError::new(100, e.to_string()))?;
                    Ok(())
                }
                _ => Err(HandlerError::new(100, format!("unknown verb {verb}"))),
            }
        }
    }
}

#[tokio::test]
async fn echo_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("assuan.sock");

    let server = AssuanServer::bind(&path, EchoHandler).unwrap();
    let server_task = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    // Give the accept loop a tick to start.
    tokio::task::yield_now().await;

    let stream = UnixStream::connect(&path).await.expect("connect");
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

    let greeting = lines.next_line().await.unwrap().unwrap();
    assert!(greeting.starts_with("OK"));

    write.write_all(b"ECHO hello\n").await.unwrap();
    write.flush().await.unwrap();

    let data = lines.next_line().await.unwrap().unwrap();
    assert_eq!(data, "D hello");
    let ok = lines.next_line().await.unwrap().unwrap();
    assert_eq!(ok, "OK");

    write.write_all(b"BYE\n").await.unwrap();
    write.flush().await.unwrap();
    let bye = lines.next_line().await.unwrap().unwrap();
    assert!(bye.starts_with("OK"));

    server_task.abort();
}

#[tokio::test]
async fn echo_unknown_verb_returns_err() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("assuan.sock");

    let server = AssuanServer::bind(&path, EchoHandler).unwrap();
    let server_task = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    tokio::task::yield_now().await;

    let stream = UnixStream::connect(&path).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

    let _greeting = lines.next_line().await.unwrap().unwrap();

    write.write_all(b"NOPE foo\n").await.unwrap();
    write.flush().await.unwrap();

    let err = lines.next_line().await.unwrap().unwrap();
    assert!(err.starts_with("ERR 100"), "got: {err}");

    server_task.abort();
}

#[tokio::test]
async fn data_line_chunking_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("assuan.sock");

    let server = AssuanServer::bind(&path, EchoHandler).unwrap();
    let server_task = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    tokio::task::yield_now().await;

    let stream = UnixStream::connect(&path).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let _greeting = lines.next_line().await.unwrap().unwrap();

    // 2500 bytes of output → server must split across ≥3 D lines.
    let expected = 2500;
    write
        .write_all(format!("MANYBYTES {expected}\n").as_bytes())
        .await
        .unwrap();
    write.flush().await.unwrap();

    let mut decoded = Vec::new();
    let mut data_lines = 0;
    loop {
        let line = lines.next_line().await.unwrap().unwrap();
        if line == "OK" {
            break;
        }
        assert!(line.starts_with("D "), "unexpected line: {line}");
        data_lines += 1;
        decoded.extend_from_slice(&line.as_bytes()[2..]);
    }
    assert_eq!(decoded.len(), expected);
    assert!(decoded.iter().all(|&b| b == b'x'));
    assert!(data_lines >= 3, "expected ≥3 D lines, got {data_lines}");

    server_task.abort();
}
