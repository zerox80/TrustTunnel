use std::io;
use async_trait::async_trait;
use crate::log_utils;


/// An abstract interface for a datagram receiver implementation
#[async_trait]
pub(crate) trait Source: Send {
    type Output;

    fn id(&self) -> log_utils::IdChain<u64>;

    /// Listen for an incoming datagram
    async fn read(&mut self) -> io::Result<Self::Output>;
}

pub(crate) enum SendStatus {
    /// A sink sent the full chunk successfully
    Sent,
    /// A sink did not send anything as it is not able to send the full chunk at the moment
    /// (for example, due to flow control limits)
    Dropped,
}

/// An abstract interface for a datagram transmitter implementation
#[async_trait]
pub(crate) trait Sink: Send {
    type Input;

    /// Send a data chunk to the peer.
    ///
    /// # Return
    ///
    /// See [`SendStatus`]
    async fn write(&mut self, data: Self::Input) -> io::Result<SendStatus>;
}


/// An abstract interface for a two-way datagram channel implementation
#[async_trait]
pub(crate) trait DuplexPipe: Send {
    /// Exchange datagrams until some error happened or the channel is closed
    async fn exchange(&mut self) -> io::Result<()>;
}
