//! Assuan server: `UnixListener` accept loop, per-connection dispatch.
//!
//! `AssuanServer` binds a Unix socket and accepts client connections
//! indefinitely. Each connection becomes an independent tokio task that
//! drives a `CommandHandler` for the lifetime of the session.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::framing::encode_data_lines;
use crate::protocol::{parse_client_line, ClientLine, ProtocolError};

/// Error a `CommandHandler` can return to have the server emit `ERR`.
#[derive(Debug, Error)]
#[error("Assuan error {code}: {message}")]
pub struct HandlerError {
    pub code: u32,
    pub message: String,
}

impl HandlerError {
    #[must_use]
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("bind path already exists: {}", .0.display())]
    PathInUse(PathBuf),
}

/// Trait implemented by downstream crates to dispatch Assuan commands.
///
/// Each connection owns an instance of `Self::Session` initialized via
/// `Default`. The handler mutates that through `handle`. On `RESTART`, the
/// server calls `reset_session` to clear per-flow state without closing the
/// transport.
pub trait CommandHandler: Send + Sync + 'static {
    type Session: Default + Send + 'static;

    fn handle(
        &self,
        session: &mut Self::Session,
        conn: &mut Connection,
        verb: &str,
        args: &str,
    ) -> impl Future<Output = Result<(), HandlerError>> + Send;

    /// Reset per-session state, typically in response to `RESTART`.
    fn reset_session(&self, session: &mut Self::Session) {
        *session = Self::Session::default();
    }
}

/// One live Assuan session. Handlers receive a mutable reference to this
/// and use the `write_*` methods to emit status, data, and completion lines.
pub struct Connection {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl Connection {
    fn new(stream: UnixStream) -> Self {
        let (read, write) = stream.into_split();
        Self {
            reader: BufReader::new(read),
            writer: write,
        }
    }

    /// Read one line and parse it. `Ok(None)` signals EOF (peer closed).
    pub async fn read_line(&mut self) -> Result<Option<ClientLine>, ServerError> {
        let mut buf = Vec::with_capacity(256);
        let n = self.reader.read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(parse_client_line(&buf)?))
    }

    /// Emit `OK` with an optional trailing comment.
    pub async fn write_ok(&mut self, comment: Option<&str>) -> Result<(), ServerError> {
        match comment {
            Some(c) => self.write_line(format!("OK {c}\n").as_bytes()).await,
            None => self.write_line(b"OK\n").await,
        }
    }

    /// Emit `ERR <code> <message>`.
    pub async fn write_err(&mut self, err: &HandlerError) -> Result<(), ServerError> {
        self.write_line(format!("ERR {} {}\n", err.code, err.message).as_bytes())
            .await
    }

    /// Emit a status line: `S <keyword> <data>` (data is sent verbatim).
    pub async fn write_status(&mut self, keyword: &str, data: &str) -> Result<(), ServerError> {
        if data.is_empty() {
            self.write_line(format!("S {keyword}\n").as_bytes()).await
        } else {
            self.write_line(format!("S {keyword} {data}\n").as_bytes())
                .await
        }
    }

    /// Emit one or more `D` lines carrying `bytes`, chunked per the Assuan
    /// line-length cap.
    pub async fn write_data(&mut self, bytes: &[u8]) -> Result<(), ServerError> {
        for mut line in encode_data_lines(bytes) {
            line.push(b'\n');
            self.writer.write_all(&line).await?;
        }
        self.writer.flush().await?;
        Ok(())
    }

    async fn write_line(&mut self, bytes: &[u8]) -> Result<(), ServerError> {
        self.writer.write_all(bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Borrow the raw writer (used by tests; not part of the stable surface).
    #[doc(hidden)]
    pub fn writer(&mut self) -> &mut (dyn AsyncWrite + Unpin + Send) {
        &mut self.writer
    }
}

/// An Assuan server bound to a Unix socket and driven by a single handler.
pub struct AssuanServer<H> {
    listener: UnixListener,
    handler: Arc<H>,
    socket_path: PathBuf,
}

impl<H: CommandHandler> AssuanServer<H> {
    /// Bind to `path`, creating the socket and failing if it already exists.
    /// The socket file is removed on `Drop`.
    pub fn bind(path: impl AsRef<Path>, handler: H) -> Result<Self, ServerError> {
        let socket_path = path.as_ref().to_path_buf();
        if socket_path.exists() {
            return Err(ServerError::PathInUse(socket_path));
        }
        let listener = UnixListener::bind(&socket_path)?;
        Ok(Self {
            listener,
            handler: Arc::new(handler),
            socket_path,
        })
    }

    /// Accept connections forever, spawning a task per connection.
    pub async fn serve(self) -> Result<(), ServerError> {
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let handler = Arc::clone(&self.handler);
            tokio::spawn(async move {
                if let Err(e) = drive_session(stream, handler).await {
                    tracing::warn!(error = %e, "session ended with error");
                }
            });
        }
    }
}

impl<H> Drop for AssuanServer<H> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn drive_session<H: CommandHandler>(
    stream: UnixStream,
    handler: Arc<H>,
) -> Result<(), ServerError> {
    let mut conn = Connection::new(stream);
    let mut session = H::Session::default();

    // Assuan servers send an initial OK on connect, per the spec.
    conn.write_ok(Some("scd-rs ready")).await?;

    loop {
        let Some(line) = conn.read_line().await? else {
            return Ok(());
        };

        match line {
            ClientLine::Bye => {
                conn.write_ok(Some("closing connection")).await?;
                return Ok(());
            }
            ClientLine::Command { verb, args: _ } if verb == "RESTART" => {
                handler.reset_session(&mut session);
                conn.write_ok(None).await?;
            }
            ClientLine::Command { verb, args } => {
                match handler.handle(&mut session, &mut conn, &verb, &args).await {
                    Ok(()) => conn.write_ok(None).await?,
                    Err(e) => conn.write_err(&e).await?,
                }
            }
            ClientLine::Data(_) | ClientLine::End | ClientLine::Cancel => {
                // These only make sense inside an INQUIRE round-trip, which
                // is driven by the handler itself (see Connection::inquire).
                tracing::debug!("ignoring out-of-sequence client line");
            }
        }
    }
}
