#[cfg(feature = "quic")]
pub use crate::quic::config::*;
#[cfg(feature = "rdma")]
pub use crate::rdma::config::*;

/// Specifies the transport protocol to be used for the connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum TransportConfig {
    /// Use TCP transport protocol.
    #[default]
    Tcp,

    #[cfg(feature = "netbios-transport")]
    /// Use NetBIOS over TCP transport protocol.
    NetBios,

    #[cfg(feature = "quic")]
    /// Use SMB over QUIC transport protocol.
    /// Note that this is only supported in dialects 3.1.1 and above.
    Quic(QuicConfig),

    #[cfg(feature = "rdma")]
    Rdma(RdmaConfig),
}

/// Bounds on single transport I/O operations, once connected.
///
/// `idle_read` also bounds the wait for the *next* message from the server,
/// so a value tears down a connection that is merely idle (no request in
/// flight, no change-notify answer yet). `None` (or zero) waits forever and
/// leaves dead-peer detection to per-request timeouts and keep-alives
/// (`ConnectionConfig::keepalive_interval` in the `smb` crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoTimeouts {
    /// Longest wait for bytes from the server, idle waits included.
    pub idle_read: Option<std::time::Duration>,
    /// Longest wait for one send to complete.
    pub send: Option<std::time::Duration>,
}

impl IoTimeouts {
    /// The fork's original fixed behaviour: 30 s for every receive and send.
    pub const LEGACY: IoTimeouts = IoTimeouts {
        idle_read: Some(std::time::Duration::from_secs(30)),
        send: Some(std::time::Duration::from_secs(30)),
    };

    /// No idle teardown: receives wait forever, sends are bounded by `send`.
    pub const fn no_idle_timeout(send: std::time::Duration) -> IoTimeouts {
        IoTimeouts {
            idle_read: None,
            send: Some(send),
        }
    }
}

impl Default for IoTimeouts {
    /// [`IoTimeouts::LEGACY`], so existing callers keep their behaviour.
    fn default() -> Self {
        Self::LEGACY
    }
}
