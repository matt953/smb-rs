use crate::config::IoTimeouts;
use crate::error::*;
use crate::{SmbTransport, SmbTransportRead, SmbTransportWrite};

#[cfg(feature = "async")]
use futures_core::future::BoxFuture;
use maybe_async::*;
use std::net::SocketAddr;
use std::time::Duration;

#[cfg(feature = "async")]
use futures_util::FutureExt;
#[cfg(not(feature = "async"))]
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};
#[cfg(feature = "async")]
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, tcp},
    select,
};

use binrw::prelude::*;

#[cfg(feature = "async")]
type TcpRead = tcp::OwnedReadHalf;
#[cfg(feature = "async")]
type TcpWrite = tcp::OwnedWriteHalf;

#[cfg(not(feature = "async"))]
type TcpRead = TcpStream;
#[cfg(not(feature = "async"))]
type TcpWrite = TcpStream;
pub struct TcpTransport {
    reader: Option<TcpRead>,
    writer: Option<TcpWrite>,
    timeout: Duration,
    io_timeouts: IoTimeouts,
}

impl TcpTransport {
    pub const DEFAULT_PORT: u16 = 445;

    /// A TCP transport with the legacy I/O timeouts ([`IoTimeouts::default`]):
    /// 30 s for any single receive or send, idle waits included.
    pub fn new(timeout: Duration) -> TcpTransport {
        Self::with_io_timeouts(timeout, IoTimeouts::default())
    }

    /// A TCP transport with explicit I/O timeouts.
    /// `timeout` is the connect timeout; `io_timeouts` bounds each receive and send.
    pub fn with_io_timeouts(timeout: Duration, io_timeouts: IoTimeouts) -> TcpTransport {
        TcpTransport {
            reader: None,
            writer: None,
            timeout,
            io_timeouts,
        }
    }

    /// Connects to a NetBios server in the specified endpoint with a timeout.
    /// This is the threaded version of [connect](NetBiosClient::connect) -
    /// using the [std::net::TcpStream] as the underlying socket provider.
    #[cfg(not(feature = "async"))]
    fn connect_timeout(&mut self, endpoint: &SocketAddr) -> Result<TcpStream> {
        if self.timeout == Duration::ZERO {
            log::debug!("Connecting to {endpoint}.");
            return TcpStream::connect(endpoint).map_err(Into::into);
        }

        log::debug!("Connecting to {endpoint} with timeout {:?}.", self.timeout);
        TcpStream::connect_timeout(endpoint, self.timeout).map_err(|e| match e.kind() {
            io::ErrorKind::TimedOut => {
                log::error!("Connection timed out after {:?}", self.timeout);
                TransportError::Timeout(self.timeout)
            }
            _ => {
                log::error!("Failed to connect to {endpoint}: {e}");
                e.into()
            }
        })
    }

    /// Connects to a NetBios server in the specified endpoint with a timeout.
    /// This is the async version of [connect](NetBiosClient::connect) -
    /// using the [tokio::net::TcpStream] as the underlying socket provider.
    #[cfg(feature = "async")]
    async fn connect_timeout(&mut self, endpoint: &SocketAddr) -> Result<TcpStream> {
        let socket = if self.timeout == Duration::ZERO {
            log::debug!("Connecting to {endpoint}.",);
            TcpStream::connect(&endpoint).await?
        } else {
            log::debug!("Connecting to {endpoint} with timeout {:?}.", self.timeout);
            let socket = select! {
                res = TcpStream::connect(&endpoint) => res?,
                _ = tokio::time::sleep(self.timeout) => return Err(
                    TransportError::Timeout(self.timeout)
                ),
            };
            socket
        };

        // Configure socket for high-throughput SMB traffic
        socket.set_nodelay(true)?; // Disable Nagle's algorithm for lower latency
        log::debug!("Socket configured: nodelay=true");

        Ok(socket)
    }

    /// Async implementation of split socket to read and write halves.
    #[cfg(feature = "async")]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let (r, w) = socket.into_split();
        (r, w)
    }

    /// Sync implementation of split socket to read and write halves.
    #[cfg(not(feature = "async"))]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let rsocket = socket.try_clone().unwrap();
        let wsocket = socket;

        (rsocket, wsocket)
    }

    /// For synchronous implementations, gets the read timeout for the connection.
    #[cfg(not(feature = "async"))]
    pub fn read_timeout(&self) -> Result<Option<std::time::Duration>> {
        self.reader
            .as_ref()
            .ok_or(TransportError::NotConnected)?
            .read_timeout()
            .map_err(|e| e.into())
    }

    /// Maps a TCP error to a crate error.
    /// Connection aborts and unexpected EOFs are mapped to [Error::NotConnected].
    #[inline]
    fn map_tcp_error(e: io::Error) -> TransportError {
        if e.kind() == io::ErrorKind::ConnectionAborted || e.kind() == io::ErrorKind::UnexpectedEof
        {
            log::error!("Got IO error: {e} -- Connection Error, notify NotConnected!");
            return TransportError::NotConnected;
        }
        if e.kind() == io::ErrorKind::WouldBlock {
            log::trace!("Got IO error: {e} -- with ErrorKind::WouldBlock.");
        } else {
            log::error!("Got IO error: {e} -- Mapping to IO error.",);
        }
        e.into()
    }

    /// Receives exactly `out_buf.len()` bytes.
    ///
    /// The receive loop waits here between messages too, so `idle_read` bounds
    /// idle waits. `IoTimeouts::idle_read == None` waits forever, leaving
    /// dead-peer detection to per-request timeouts and keep-alives.
    #[cfg(feature = "async")]
    #[inline]
    async fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<()> {
        let reader = self.reader.as_mut().ok_or(TransportError::NotConnected)?;
        let result = match self.io_timeouts.idle_read {
            Some(t) if !t.is_zero() => tokio::time::timeout(t, reader.read_exact(out_buf))
                .await
                .map_err(|_| TransportError::Timeout(t))?,
            _ => reader.read_exact(out_buf).await,
        };
        result.map(|_| ()).map_err(Self::map_tcp_error)
    }

    /// Sync builds: the worker sets the socket's own read timeout.
    #[cfg(not(feature = "async"))]
    #[inline]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<()> {
        let reader = self.reader.as_mut().ok_or(TransportError::NotConnected)?;
        reader.read_exact(out_buf).map_err(Self::map_tcp_error)
    }

    #[cfg(feature = "async")]
    #[inline]
    async fn send_raw(&mut self, message: &[u8]) -> Result<()> {
        let writer = self.writer.as_mut().ok_or(TransportError::NotConnected)?;
        let result = match self.io_timeouts.send {
            Some(t) if !t.is_zero() => tokio::time::timeout(t, writer.write_all(message))
                .await
                .map_err(|_| TransportError::Timeout(t))?,
            _ => writer.write_all(message).await,
        };
        result.map_err(Self::map_tcp_error)
    }

    #[cfg(not(feature = "async"))]
    #[inline]
    fn send_raw(&mut self, message: &[u8]) -> Result<()> {
        let writer = self.writer.as_mut().ok_or(TransportError::NotConnected)?;
        if let Some(t) = self.io_timeouts.send.filter(|t| !t.is_zero()) {
            writer.set_write_timeout(Some(t))?;
        }
        writer.write_all(message).map_err(Self::map_tcp_error)
    }

    #[maybe_async::maybe_async]
    #[inline]
    async fn do_connect(&mut self, _server_name: &str, server_address: SocketAddr) -> Result<()> {
        let socket = self.connect_timeout(&server_address).await?;
        let (r, w) = Self::split_socket(socket);
        self.reader = Some(r);
        self.writer = Some(w);
        Ok(())
    }
}

impl SmbTransport for TcpTransport {
    #[cfg(feature = "async")]
    fn connect<'a>(
        &'a mut self,
        server_name: &'a str,
        server_address: SocketAddr,
    ) -> BoxFuture<'a, Result<()>> {
        self.do_connect(server_name, server_address).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn connect(&mut self, server_name: &str, server_address: SocketAddr) -> Result<()> {
        self.do_connect(server_name, server_address)
    }

    fn split(self: Box<Self>) -> Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        Ok((
            Box::new(Self {
                reader: self.reader,
                writer: None,
                timeout: self.timeout,
                io_timeouts: self.io_timeouts,
            }),
            Box::new(Self {
                reader: None,
                writer: self.writer,
                timeout: self.timeout,
                io_timeouts: self.io_timeouts,
            }),
        ))
    }

    fn default_port(&self) -> u16 {
        Self::DEFAULT_PORT
    }

    fn remote_address(&self) -> Result<SocketAddr> {
        self.reader
            .as_ref()
            .ok_or(TransportError::NotConnected)?
            .peer_addr()
            .map_err(Into::into)
    }
}

impl SmbTransportWrite for TcpTransport {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.send_raw(buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> Result<()> {
        self.send_raw(buf)
    }
}

impl SmbTransportRead for TcpTransport {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, Result<()>> {
        self.receive_exact(out_buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<()> {
        self.receive_exact(out_buf)
    }

    #[cfg(not(feature = "async"))]
    fn set_read_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        self.reader
            .as_ref()
            .ok_or(TransportError::NotConnected)?
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.into())
    }
}
