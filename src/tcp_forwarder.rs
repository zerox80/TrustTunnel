use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use crate::forwarder::TcpConnector;
use crate::net_utils::TcpDestination;
use crate::{log_id, log_utils, pipe};
use crate::settings::Settings;


pub(crate) struct TcpForwarder {
    core_settings: Arc<Settings>,
}

struct Connector {
    destination: TcpDestination,
    ipv6_available: bool,
    id: log_utils::IdChain<u64>,
}

struct StreamRx {
    rx: OwnedReadHalf,
    id: log_utils::IdChain<u64>,
}

struct StreamTx {
    tx: OwnedWriteHalf,
    id: log_utils::IdChain<u64>,
}

impl TcpForwarder {
    pub fn new(
        core_settings: Arc<Settings>,
    ) -> Self {
        Self {
            core_settings,
        }
    }

    pub fn connect_tcp(
        &self, id: log_utils::IdChain<u64>, destination: TcpDestination,
    ) -> io::Result<Box<dyn TcpConnector>> {
        Ok(Box::new(Connector {
            destination,
            ipv6_available: self.core_settings.ipv6_available,
            id,
        }))
    }

    pub fn pipe_from_stream(
        stream: TcpStream, id: log_utils::IdChain<u64>
    ) -> (Box<dyn pipe::Source>, Box<dyn pipe::Sink>) {
        let (rx, tx) = stream.into_split();
        (
            Box::new(StreamRx {
                rx,
                id: id.clone(),
            }),
            Box::new(StreamTx {
                tx,
                id,
            }),
        )
    }
}

#[async_trait]
impl TcpConnector for Connector {
    async fn connect(self: Box<Self>) -> io::Result<(Box<dyn pipe::Source>, Box<dyn pipe::Sink>)> {
        let peer = match self.destination {
            TcpDestination::Address(peer) => peer,
            TcpDestination::HostName(peer) => {
                log_id!(trace, self.id, "Resolving peer: {:?}", peer);

                let resolved = tokio::net::lookup_host(format!("{}:{}", peer.0, peer.1)).await
                    .and_then(|mut addrs|
                        addrs.find(|a| self.ipv6_available || a.is_ipv4()).ok_or_else(
                            || io::Error::new(ErrorKind::Other, "Acceptable address not found")
                        ))?;
                log_id!(trace, self.id, "Peer successfully resolved: {}", resolved);
                resolved
            }
        };

        log_id!(trace, self.id, "Connecting to peer: {}", peer);
        let stream = TcpStream::connect(peer).await
            .and_then(|s| { s.set_nodelay(true)?; Ok(s) })?;
        Ok(TcpForwarder::pipe_from_stream(stream, self.id))
    }
}

#[async_trait]
impl pipe::Source for StreamRx {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    async fn read(&mut self) -> io::Result<pipe::Data> {
        loop {
            match self.rx.readable().await {
                Ok(_) => break,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }

        const READ_CHUNK_SIZE: usize = 64 * 1024;
        let mut buffer = Vec::with_capacity(READ_CHUNK_SIZE);

        const READ_BUDGET: usize = 16;
        for _ in 0..READ_BUDGET {
            match self.rx.try_read_buf(&mut buffer) {
                Ok(0) => return Ok(pipe::Data::Eof),
                Ok(_) => if buffer.capacity() == buffer.len() {
                    break;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(pipe::Data::Chunk(Bytes::from(buffer)))
    }

    fn consume(&mut self, _size: usize) -> io::Result<()> {
        // do nothing
        Ok(())
    }
}

#[async_trait]
impl pipe::Sink for StreamTx {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn write(&mut self, mut data: Bytes) -> io::Result<Bytes> {
        while !data.is_empty() {
            match self.tx.try_write(data.as_ref()) {
                Ok(n) => data.advance(n),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(data)
    }

    fn eof(&mut self) -> io::Result<()> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.tx.shutdown().await
            })
        })
    }

    async fn wait_writable(&mut self) -> io::Result<()> {
        self.tx.writable().await
    }
}
