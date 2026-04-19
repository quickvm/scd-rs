//! Assuan server: `UnixListener` accept loop, per-connection dispatch.
//!
//! `AssuanServer` binds a Unix socket and accepts client connections
//! indefinitely. Each connection becomes an independent tokio task that
//! drives a `CommandHandler` for the lifetime of the session.

use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::framing::encode_data_lines;
use crate::protocol::{parse_client_line, ClientLine, ProtocolError};

/// Shared handle to an open trace file. Cloned across all Connections that
/// should tee into the same sink; the Mutex serializes concurrent writers.
pub type TraceSink = Arc<Mutex<std::fs::File>>;

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
    #[error("peer sent CAN during INQUIRE")]
    InquireCancelled,
    #[error("peer sent unexpected line during INQUIRE: {0:?}")]
    InquireUnexpected(ClientLine),
    #[error("peer closed during INQUIRE")]
    InquireEof,
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

type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// One live Assuan session. Handlers receive a mutable reference to this
/// and use the `write_*` methods to emit status, data, and completion lines.
pub struct Connection {
    reader: BufReader<BoxedReader>,
    writer: BoxedWriter,
    trace: Option<TraceSink>,
    /// When true, `trace_io` emits `[[Confidential data not shown]]` in
    /// place of the actual wire bytes. Scoped to a single `inquire()` call
    /// whose keyword names a secret (PIN, passphrase).
    trace_confidential: bool,
}

impl Connection {
    fn from_unix_stream(stream: UnixStream) -> Self {
        let (read, write) = stream.into_split();
        Self::new(Box::new(read), Box::new(write))
    }

    #[must_use]
    pub fn new(reader: BoxedReader, writer: BoxedWriter) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            trace: None,
            trace_confidential: false,
        }
    }

    /// Wrap the current process's stdin/stdout. Used for scdaemon-compat
    /// server mode where `gpg-agent` spawns us and talks over pipes.
    #[must_use]
    pub fn from_stdio() -> Self {
        Self::new(
            Box::new(tokio::io::stdin()),
            Box::new(tokio::io::stdout()),
        )
    }

    /// Tee every line read from and written to this connection into `sink`.
    /// Each line is prefixed with `<- ` (client→server) or `-> ` (server→
    /// client) and a trailing newline; matches the direction convention
    /// stock scdaemon's `debug ipc` log uses.
    pub fn set_trace(&mut self, sink: TraceSink) {
        self.trace = Some(sink);
    }

    fn trace_io(&self, prefix: &[u8], bytes: &[u8]) {
        let Some(sink) = &self.trace else {
            return;
        };
        let Ok(mut f) = sink.lock() else {
            return;
        };
        let _ = f.write_all(prefix);
        if self.trace_confidential {
            let _ = f.write_all(b"[[Confidential data not shown]]\n");
        } else {
            let stripped = bytes.strip_suffix(b"\n").unwrap_or(bytes);
            let _ = f.write_all(stripped);
            let _ = f.write_all(b"\n");
        }
    }

    /// Read one line and parse it. `Ok(None)` signals EOF (peer closed).
    pub async fn read_line(&mut self) -> Result<Option<ClientLine>, ServerError> {
        let mut buf = Vec::with_capacity(256);
        let n = self.reader.read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        self.trace_io(b"<- ", &buf);
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
            self.trace_io(b"-> ", &line);
        }
        self.writer.flush().await?;
        Ok(())
    }

    /// Send `INQUIRE <keyword>[ <args>]` and collect the peer's `D` lines
    /// into a single byte buffer, terminated by `END`. Returns the decoded
    /// payload.
    ///
    /// The caller is responsible for zeroising the returned bytes if they
    /// contain secret material (e.g. a PIN).
    pub async fn inquire(
        &mut self,
        keyword: &str,
        args: &str,
    ) -> Result<Vec<u8>, ServerError> {
        // NEEDPIN/PASSPHRASE/PIN prompts carry the card's serial and holder
        // in the prompt, and the client's D/END response carries the PIN
        // itself. Redact in the trace file for the duration of the inquire
        // round so the captured transcript matches stock scdaemon's
        // `[[Confidential data not shown]]` behavior.
        let is_confidential = matches!(keyword, "NEEDPIN" | "PASSPHRASE" | "PIN");
        if is_confidential {
            self.trace_confidential = true;
        }
        let result = self.inquire_inner(keyword, args).await;
        self.trace_confidential = false;
        result
    }

    async fn inquire_inner(
        &mut self,
        keyword: &str,
        args: &str,
    ) -> Result<Vec<u8>, ServerError> {
        if args.is_empty() {
            self.write_line(format!("INQUIRE {keyword}\n").as_bytes()).await?;
        } else {
            self.write_line(format!("INQUIRE {keyword} {args}\n").as_bytes())
                .await?;
        }
        let mut payload = Vec::new();
        let mut data_lines = 0u32;
        loop {
            let Some(line) = self.read_line().await? else {
                return Err(ServerError::InquireEof);
            };
            match line {
                ClientLine::Data(bytes) => {
                    data_lines += 1;
                    tracing::info!(
                        data_line = data_lines,
                        len = bytes.len(),
                        "inquire: received D line",
                    );
                    payload.extend(bytes);
                }
                ClientLine::End => {
                    tracing::info!(
                        total_lines = data_lines,
                        total_bytes = payload.len(),
                        "inquire: END received",
                    );
                    return Ok(payload);
                }
                ClientLine::Cancel => return Err(ServerError::InquireCancelled),
                other => return Err(ServerError::InquireUnexpected(other)),
            }
        }
    }

    async fn write_line(&mut self, bytes: &[u8]) -> Result<(), ServerError> {
        self.writer.write_all(bytes).await?;
        self.writer.flush().await?;
        self.trace_io(b"-> ", bytes);
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
    trace: Option<TraceSink>,
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
            trace: None,
        })
    }

    /// Tee every accepted connection's wire traffic into `sink`.
    #[must_use]
    pub fn with_trace(mut self, sink: TraceSink) -> Self {
        self.trace = Some(sink);
        self
    }

    /// Accept connections forever, spawning a task per connection.
    pub async fn serve(self) -> Result<(), ServerError> {
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let handler = Arc::clone(&self.handler);
            let trace = self.trace.clone();
            tokio::spawn(async move {
                let mut conn = Connection::from_unix_stream(stream);
                if let Some(sink) = trace {
                    conn.set_trace(sink);
                }
                if let Err(e) = drive_session(conn, handler).await {
                    tracing::warn!(error = %e, "session ended with error");
                }
            });
        }
    }
}

/// Drive one Assuan session over stdin/stdout, then return. Used for
/// scdaemon-compat server mode where `gpg-agent` invokes us as a child
/// process via `assuan_pipe_connect`.
pub async fn serve_stdio<H: CommandHandler>(handler: H) -> Result<(), ServerError> {
    serve_stdio_with_trace(handler, None).await
}

/// As `serve_stdio`, but with optional wire-level tracing.
pub async fn serve_stdio_with_trace<H: CommandHandler>(
    handler: H,
    trace: Option<TraceSink>,
) -> Result<(), ServerError> {
    let mut conn = Connection::from_stdio();
    if let Some(sink) = trace {
        conn.set_trace(sink);
    }
    drive_session(conn, Arc::new(handler)).await
}

impl<H> Drop for AssuanServer<H> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn drive_session<H: CommandHandler>(
    mut conn: Connection,
    handler: Arc<H>,
) -> Result<(), ServerError> {
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
                    Err(e) => {
                        tracing::warn!(code = e.code, message = %e.message, "handler returned ERR");
                        conn.write_err(&e).await?;
                    }
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
