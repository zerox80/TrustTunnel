use std::collections::{HashMap, HashSet};
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use bytes::{Buf, Bytes, BytesMut};
use http::header::InvalidHeaderName;
use lazy_static::lazy_static;
use quiche::h3;
use quiche::h3::NameValue;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;
use crate::{log_id, log_utils, net_utils, utils};
use crate::http_codec::{RequestHeaders, ResponseHeaders};
use crate::settings::{ListenProtocolSettings, Settings, TlsHostInfo};


const TOKEN_PREFIX_SIZE: usize = 16;
const MUX_ID_FMT: &str = "QMUX={}";
const SOCKET_ID_FMT: &str = "QSOCK={}";
const QUIC_CONNECTION_CLOSE_CODE: u64 = 0x42;

type QuicConnection = Pin<Box<quiche::Connection>>;


pub(crate) struct QuicMultiplexer {
    core_settings: Arc<Settings>,
    socket: Arc<UdpSocket>,
    /// Receives messages from [`QuicSocket.mux_tx`]
    socket_rx: mpsc::Receiver<SocketMessage>,
    /// See [`QuicSocket.mux_tx`]
    mux_tx: Arc<std::sync::Mutex<mpsc::Sender<SocketMessage>>>,
    connections: HashMap<quiche::ConnectionId<'static>, Connection>,
    deadlines: HashMap<quiche::ConnectionId<'static>, Instant>,
    closest_deadline: Option<Instant>,
    token_prefix: [u8; TOKEN_PREFIX_SIZE],
    id: log_utils::IdChain<u64>,
    next_socket_id: Arc<AtomicU64>,
}

pub(crate) struct QuicSocket {
    /// Receives messages from [`EstablishedConnection.socket_tx`]
    conn_rx: tokio::sync::Mutex<mpsc::Receiver<MultiplexerMessage>>,
    /// Sends messages to [`QuicMultiplexer.socket_rx`]
    mux_tx: Arc<std::sync::Mutex<mpsc::Sender<SocketMessage>>>,
    peer: SocketAddr,
    udp_socket: Arc<UdpSocket>,
    quic_conn: Arc<std::sync::Mutex<QuicConnection>>,
    h3_conn: Arc<std::sync::Mutex<h3::Connection>>,
    waiting_writable_streams: std::sync::Mutex<HashSet<u64>>,
    id: log_utils::IdChain<u64>,
}

pub(crate) enum QuicSocketEvent {
    Request(/* stream id */ u64, Box<RequestHeaders>),
    Readable(/* stream id */ u64),
    Writable(Vec</* stream id */ u64>),
    Close(/* stream id */ u64),
}


/// Messages sent by [`QuicMultiplexer`] to [`QuicSocket`]s
enum MultiplexerMessage {
    PollH3,
    Close,
}

/// Messages sent by [`QuicSocket`]s to [`QuicMultiplexer`]
enum SocketMessage {
    Close(quiche::ConnectionId<'static>),
}

struct HandshakingConnection {
    quic_conn: Arc<std::sync::Mutex<QuicConnection>>,
}

struct EstablishedConnection {
    /// Sends messages to [`QuicSocket.conn_rx`]
    socket_tx: mpsc::Sender<MultiplexerMessage>,
    quic_conn: Arc<std::sync::Mutex<QuicConnection>>,
}

enum Connection {
    Handshake(HandshakingConnection),
    Established(EstablishedConnection),
}

enum UnknownPacketStatus {
    Process,
    Skip,
}

enum HandshakeStatus {
    InProgress(Arc<std::sync::Mutex<QuicConnection>>),
    Complete,
}

enum ServerNameCheckStatus<'a> {
    Ok,
    RetryAs(&'a TlsHostInfo),
}


impl QuicMultiplexer {
    pub fn new(
        core_settings: Arc<Settings>,
        socket: UdpSocket,
        next_socket_id: Arc<AtomicU64>,
    ) -> Self {
        let queue_cap = core_settings.listen_protocols.iter()
            .find_map(|x| match x {
                ListenProtocolSettings::Quic(x) => Some(x.message_queue_capacity),
                _ => None,
            })
            .unwrap();

        let (tx, rx) = mpsc::channel(queue_cap);

        Self {
            core_settings,
            socket: Arc::new(socket),
            socket_rx: rx,
            mux_tx: Arc::new(std::sync::Mutex::new(tx)),
            connections: Default::default(),
            deadlines: Default::default(),
            closest_deadline: None,
            token_prefix: ring::rand::generate(&ring::rand::SystemRandom::new()).unwrap().expose(),
            id: log_utils::IdChain::from(log_utils::IdItem::new(MUX_ID_FMT, 0)),
            next_socket_id,
        }
    }

    pub async fn listen(&mut self) -> io::Result<QuicSocket> {
        enum Event {
            UdpRead,
            UdpSend(SocketMessage),
        }

        loop {
            let event = {
                let wait_timeout = tokio::time::sleep_until(
                    self.closest_deadline.unwrap_or_else(Instant::now)
                );
                tokio::pin!(wait_timeout);

                let wait_udp_send = self.socket_rx.recv();
                tokio::pin!(wait_udp_send);

                let wait_udp_read = self.socket.readable();
                tokio::pin!(wait_udp_read);

                tokio::select! {
                    r = wait_udp_read => match r {
                        Ok(_) => Some(Event::UdpRead),
                        Err(e) => return Err(e),
                    },
                    r = wait_udp_send => match r {
                        Some(m) => Some(Event::UdpSend(m)),
                        None => return Err(io::Error::new(ErrorKind::Other, "Message receiving channel closed unexpectedly")),
                    },
                    _ = &mut wait_timeout, if self.closest_deadline.map_or(false, |x| x > Instant::now()) => None,
                }
            };

            self.process_timeouts();

            match event {
                None => (),
                Some(Event::UdpSend(m)) => self.on_socket_message(m)?,
                Some(Event::UdpRead) => if let Some(s) = self.read_udp_socket()? {
                    return Ok(s);
                }
            }

            self.process_pending_socket_messages()?;
            self.remove_closed_connections();
        }
    }

    fn read_udp_socket(&mut self) -> io::Result<Option<QuicSocket>> {
        const READ_BUDGET: usize = 16;

        let mut buffer = [0; net_utils::MAX_DATAGRAM_SIZE];
        for _ in 0..READ_BUDGET {
            match self.socket.try_recv_from(&mut buffer) {
                Ok((n, peer)) => match self.on_udp_packet(&peer, &mut buffer[..n]) {
                    Some(s) => return Ok(Some(s)),
                    None => continue,
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(None)
    }

    fn on_udp_packet(&mut self, peer: &SocketAddr, packet: &mut [u8]) -> Option<QuicSocket> {
        let header = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
            Ok(h) => {
                log_id!(trace, self.id, "Received QUIC packet: {:?}", h);
                h
            }
            Err(e) => {
                log_id!(debug, self.id, "Parsing UDP packet header failed: {}", e);
                return None;
            }
        };

        let result = match self.connections.get(&header.dcid) {
            None => match self.on_unknown_quic_packet(peer, &header) {
                Ok(UnknownPacketStatus::Process) => self.on_new_connection(peer, &header, packet),
                Ok(UnknownPacketStatus::Skip) => return None,
                Err(e) => {
                    log_id!(debug, self.id, "Failed to process QUIC packet: header={:?}, error={}", header, e);
                    return None;
                }
            }
            Some(Connection::Handshake(conn)) =>
                match conn.proceed_handshake(peer, packet, &self.id) {
                    Ok(HandshakeStatus::InProgress(conn)) => Ok((None, conn)),
                    Ok(HandshakeStatus::Complete) => {
                        self.deadlines.remove(&header.dcid);
                        let conn = self.connections.remove(&header.dcid)
                            .map(|x| match x {
                                Connection::Handshake(x) => x,
                                Connection::Established(_) => unreachable!(),
                            }).unwrap();
                        self.finalize_established_connection(&header.dcid, conn, peer)
                            .map(|(sock, conn)| (Some(sock), conn))
                    }
                    Err(e) => Err(e),
                }
            Some(Connection::Established(conn)) =>
                self.proceed_established_connection(conn, peer, packet)
                    .map(|conn| (None, conn)),
        };

        let (mut result, quic_conn) = match result {
            Ok((sock, conn)) => (Ok(sock), Some(conn.clone())),
            Err(e) => {
                log_id!(debug, self.id, "Failed to process QUIC packet: header={:?}, error={}", header, e);
                match self.connections.get(&header.dcid) {
                    None => (Err(e), None),
                    Some(Connection::Handshake(c)) => (Err(e), Some(c.quic_conn.clone())),
                    Some(Connection::Established(c)) => (Err(e), Some(c.quic_conn.clone())),
                }
            }
        };

        if let Some(quic_conn) = quic_conn {
            let mut quic_conn = quic_conn.lock().unwrap();

            if let Err(e) = &result {
                let _ = quic_conn.close(false, QUIC_CONNECTION_CLOSE_CODE, e.to_string().as_bytes());
            }

            if let Some(timeout) = quic_conn.timeout() {
                self.update_connection_deadline(header.dcid.clone(), timeout);
            }

            let flush_result = flush_pending_data(&mut quic_conn, &self.socket, peer, &self.id)
                .map(|_| None);
            if let Err(e) = &flush_result {
                log_id!(debug, self.id, "Failed to flush QUIC connection: {}", e);
                if result.is_ok() {
                    result = flush_result;
                }
            }
        }

        result.ok().flatten()
    }

    fn check_server_name(&self, sni: Option<&str>) -> io::Result<ServerNameCheckStatus> {
        let settings = &self.core_settings;

        // For now, SNI-based authorization is not supported for QUIC
        match sni {
            Some(x) if x == settings.tunnel_tls_host_info.hostname => Ok(ServerNameCheckStatus::Ok),
            Some(x) if settings.service_messenger_tls_host_info.as_ref().map_or(
                false, |info| info.hostname == x
            ) =>
                Ok(ServerNameCheckStatus::RetryAs(
                    settings.service_messenger_tls_host_info.as_ref().unwrap(),
                )),
            x => return Err(io::Error::new(
                ErrorKind::Other, format!("Unexpected server name in TLS handshake: {:?}", x)
            )),
        }
    }

    fn on_unknown_quic_packet<'a>(&self, peer: &SocketAddr, header: &quiche::Header<'a>)
        -> io::Result<UnknownPacketStatus>
    {
        if !matches!(header.ty, quiche::Type::Initial) {
            return Err(io::Error::new(ErrorKind::Other, format!("Unexpected packet type: {:?}", header)));
        }

        if !quiche::version_is_supported(header.version) {
            log_id!(trace, self.id, "Doing version negotiation: {:?}", header);
            let mut out = [0; net_utils::MAX_DATAGRAM_SIZE];
            let n = quiche::negotiate_version(&header.scid, &header.dcid, &mut out)
                .map_err(|e|
                    io::Error::new(ErrorKind::Other, format!("Version negotiation failed: {}", e))
                )?;
            return self.socket.try_send_to(&out[..n], *peer).map(|_| UnknownPacketStatus::Skip);
        }

        let quic_token = header.token.as_ref()
            .ok_or_else(||
                io::Error::new(ErrorKind::Other, "Invalid packet: initial packet must contain token")
            )?;

        lazy_static! {
            static ref CONN_ID_SEED: ring::hmac::Key = {
                let rng = ring::rand::SystemRandom::new();
                ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap()
            };
        }

        let conn_id = ring::hmac::sign(&CONN_ID_SEED, &header.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];

        let scid = quiche::ConnectionId::from_ref(conn_id);

        if quic_token.is_empty() {
            log_id!(trace, self.id, "Doing stateless retry: {:?}", header);
            let mut out = [0; net_utils::MAX_DATAGRAM_SIZE];
            let n = quiche::retry(
                &header.scid, &header.dcid, &scid,
                &mint_token(header, &self.token_prefix, peer), header.version, &mut out
            )
                .map_err(|e|
                    io::Error::new(ErrorKind::Other, format!("Retry failed: {}", e))
                )?;
            return self.socket.try_send_to(&out[..n], *peer).map(|_| UnknownPacketStatus::Skip);
        }

        if scid.len() != header.dcid.len() {
            return Err(io::Error::new(ErrorKind::Other,
                                      "Invalid packet: unexpected destination connection ID"));
        }

        Ok(UnknownPacketStatus::Process)
    }

    fn accept_quic_connection<'a>(
        &self,
        tls_host_info: &TlsHostInfo,
        scid: &quiche::ConnectionId<'a>,
        odcid: Option<&quiche::ConnectionId<'a>>,
        peer: &SocketAddr,
        packet: &mut [u8],
    ) -> io::Result<QuicConnection> {
        let mut quic_config = make_quic_conn_config(
            &self.core_settings,
            &tls_host_info.cert_chain_path,
            &tls_host_info.private_key_path,
        )
            .map_err(|e| io::Error::new(
                ErrorKind::Other, format!("Failed to create QUIC configuration: {}", e)
            ))?;
        let mut quic_conn = quiche::accept(scid, odcid, *peer, &mut quic_config)
            .map_err(|e| io::Error::new(
                ErrorKind::Other, format!("Failed to accept QUIC connection: {}", e)
            ))?;

        quic_recv(&mut quic_conn, packet, &quiche::RecvInfo { from: *peer }, &self.id)?;

        Ok(quic_conn)
    }

    fn finalize_established_connection<'a>(
        &mut self,
        conn_id: &quiche::ConnectionId<'a>,
        conn: HandshakingConnection,
        peer: &SocketAddr,
    ) -> io::Result<(QuicSocket, Arc<std::sync::Mutex<QuicConnection>>)> {
        let quic_conn = conn.quic_conn;

        let h3_conn = {
            let mut quic_conn = quic_conn.lock().unwrap();
            let h3_config = h3::Config::new().unwrap();
            let h3_conn = h3::Connection::with_transport(&mut quic_conn, &h3_config)
                .map_err(|e| io::Error::new(
                    ErrorKind::Other, format!("Failed to open HTTP3 session: {}", e)
                ))?;

            flush_pending_data(&mut quic_conn, &self.socket, peer, &self.id)?;
            Arc::new(std::sync::Mutex::new(h3_conn))
        };

        let (tx, rx) = mpsc::channel(1);
        self.connections.insert(conn_id.clone().into_owned(), Connection::Established(EstablishedConnection {
            socket_tx: tx,
            quic_conn: quic_conn.clone(),
        }));

        Ok((
            QuicSocket {
                conn_rx: tokio::sync::Mutex::new(rx),
                mux_tx: self.mux_tx.clone(),
                peer: *peer,
                udp_socket: self.socket.clone(),
                quic_conn: quic_conn.clone(),
                h3_conn,
                waiting_writable_streams: Default::default(),
                id: self.id.extended(log_utils::IdItem::new(
                    SOCKET_ID_FMT, self.next_socket_id.fetch_add(1, Ordering::Relaxed)
                )),
           },
           quic_conn,
       ))
    }

    fn on_new_connection<'a>(
        &mut self, peer: &SocketAddr, header: &quiche::Header<'a>, packet: &mut [u8]
    ) -> io::Result<(Option<QuicSocket>, Arc<std::sync::Mutex<QuicConnection>>)> {
        let odcid = validate_token(&self.token_prefix, peer, header.token.as_ref().unwrap())
            .ok_or_else(||
                io::Error::new(ErrorKind::Other, "Invalid packet: unexpected token")
            )?;

        log_id!(debug, self.id, "New connection: dcid={} scid={}",
            utils::hex_dump(&header.dcid), utils::hex_dump(&header.scid));

        let quic_conn = {
            // Quiche modifies buffer in-place while processing packets, so copy the packet
            // in case we should retry as another host
            let mut retry_buffer = packet.to_vec();

            // Reuse the source connection ID we sent in the Retry packet, instead of changing it again
            let quic_conn = self.accept_quic_connection(
                &self.core_settings.tunnel_tls_host_info, &header.dcid, Some(&odcid), peer, packet,
            )?;

            match self.check_server_name(quic_conn.server_name())? {
                ServerNameCheckStatus::Ok => quic_conn,
                ServerNameCheckStatus::RetryAs(tls_host_info) => self.accept_quic_connection(
                    tls_host_info, &header.dcid, Some(&odcid), peer, &mut retry_buffer,
                )?,
            }
        };

        let is_established = quic_conn.is_established() || quic_conn.is_in_early_data();
        let quic_conn = Arc::new(std::sync::Mutex::new(quic_conn));
        let conn = HandshakingConnection {
            quic_conn: quic_conn.clone(),
        };

        if is_established {
            return self.finalize_established_connection(&header.dcid, conn, peer)
                .map(|(sock, conn)| (Some(sock), conn));
        }

        self.connections.insert(header.dcid.clone().into_owned(), Connection::Handshake(conn));
        Ok((None, quic_conn))
    }

    fn proceed_established_connection(
        &self, conn: &EstablishedConnection, peer: &SocketAddr, packet: &mut [u8]
    ) -> io::Result<Arc<std::sync::Mutex<QuicConnection>>> {
        quic_recv(&mut conn.quic_conn.lock().unwrap(), packet, &quiche::RecvInfo{ from: *peer }, &self.id)?;
        match conn.socket_tx.try_send(MultiplexerMessage::PollH3) {
            // `Full` is not considered as an error in this case, as the connection does not need
            // multiple `poll` messages in the queue
            Ok(_) | Err(mpsc::error::TrySendError::Full(_)) => Ok(conn.quic_conn.clone()),
            Err(mpsc::error::TrySendError::Closed(_)) =>
                Err(io::Error::new(ErrorKind::Other, "Channel closed")),
        }
    }

    fn update_connection_deadline(&mut self, conn_id: quiche::ConnectionId<'static>, duration: Duration) {
        let deadline = Instant::now() + duration;
        self.deadlines.insert(conn_id, deadline);
        if self.closest_deadline.map_or(true, |x| x > deadline) {
            self.closest_deadline = Some(deadline);
        }
    }

    fn process_timeouts(&mut self) {
        let now = Instant::now();

        let timedout: Vec<_> = self.deadlines.iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(conn_id, _)| conn_id.clone())
            .collect();

        for conn_id in timedout {
            self.deadlines.remove(&conn_id);

            match self.connections.get_mut(&conn_id) {
                None => log_id!(debug, self.id, "Expired connection not found: {:?}", conn_id),
                Some(Connection::Handshake(conn)) => conn.quic_conn.lock().unwrap().on_timeout(),
                Some(Connection::Established(conn)) => conn.quic_conn.lock().unwrap().on_timeout(),
            }
        }
    }

    fn on_socket_message(&mut self, message: SocketMessage) -> io::Result<()> {
        match message {
            SocketMessage::Close(conn_id) => {
                self.connections.remove(&conn_id);
                Ok(())
            }
        }
    }

    fn process_pending_socket_messages(&mut self) -> io::Result<()> {
        loop {
            match self.socket_rx.try_recv() {
                Ok(m) => self.on_socket_message(m)?,
                Err(mpsc::error::TryRecvError::Empty) => return Ok(()),
                Err(mpsc::error::TryRecvError::Disconnected) => return Err(io::Error::new(
                    ErrorKind::Other, "Message receive channel closed unexpectedly"
                )),
            }
        }
    }

    fn remove_closed_connections(&mut self) {
        let closed: Vec<_> = self.connections.iter()
            .filter(|(_, conn)| match conn {
                Connection::Handshake(c) => c.quic_conn.lock().unwrap().is_closed(),
                Connection::Established(c) => c.quic_conn.lock().unwrap().is_closed(),
            })
            .map(|(id, _)| id.clone())
            .collect();

        for conn_id in closed {
            self.deadlines.remove(&conn_id);
            if let Some(Connection::Established(c)) = self.connections.remove(&conn_id) {
                let _ = c.socket_tx.try_send(MultiplexerMessage::Close);
            }
        }
    }
}

impl QuicSocket {
    pub fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    pub fn send_response(&self, stream_id: u64, response: ResponseHeaders, fin: bool) -> io::Result<()> {
        let response: Vec<_> =
            std::iter::once(h3::HeaderRef::new(
                ":status".as_bytes(), response.status.as_str().as_bytes()
            ))
                .chain(response.headers.iter()
                    .map(|(n, v)| h3::HeaderRef::new(n.as_ref(), v.as_ref())))
                .collect();

        self.h3_conn.lock().unwrap().send_response(
            &mut self.quic_conn.lock().unwrap(), stream_id, response.as_slice(), fin
        ).map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;

        self.flush_pending_data()
    }

    pub fn read(&self, stream_id: u64) -> io::Result<Option<Bytes>> {
        const READ_CHUNK_SIZE: usize = 64 * 1024;
        let mut bytes = BytesMut::with_capacity(READ_CHUNK_SIZE);
        bytes.resize(READ_CHUNK_SIZE, 0);

        let chunk = match self.h3_conn.lock().unwrap().recv_body(
            &mut self.quic_conn.lock().unwrap(), stream_id, bytes.as_mut()
        ) {
            Ok(n) => {
                bytes.truncate(n);
                Some(bytes.freeze())
            }
            Err(quiche::h3::Error::Done) => None,
            Err(e) => return Err(io::Error::new(ErrorKind::Other,e.to_string())),
        };

        self.flush_pending_data()?;
        Ok(chunk)
    }

    pub fn write(&self, stream_id: u64, mut data: Bytes) -> io::Result<Bytes> {
        match self.h3_conn.lock().unwrap().send_body(
            &mut self.quic_conn.lock().unwrap(), stream_id, data.as_ref(), false
        ) {
            Ok(n) => data.advance(n),
            Err(h3::Error::Done) => (),
            Err(e) => return Err(io::Error::new(ErrorKind::Other, e.to_string())),
        }

        self.flush_pending_data().map(|_| data)
    }

    pub fn stream_capacity(&self, stream_id: u64) -> io::Result<usize> {
        self.quic_conn.lock().unwrap()
            .stream_capacity(stream_id)
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))
    }

    pub fn stream_finished(&self, stream_id: u64) -> bool {
        self.quic_conn.lock().unwrap().stream_finished(stream_id)
    }

    pub fn notify_stream_waiting_writable(&self, stream_id: u64) {
        self.waiting_writable_streams.lock().unwrap().insert(stream_id);
    }

    pub fn shutdown_stream(&self, stream_id: u64, direction: quiche::Shutdown) {
        let _ = self.quic_conn.lock().unwrap().stream_shutdown(stream_id, direction, 0);
    }

    pub fn close_stream(&self, stream_id: u64) {
        self.shutdown_stream(stream_id, quiche::Shutdown::Read);
        self.shutdown_stream(stream_id, quiche::Shutdown::Write);
    }

    pub async fn listen(&self) -> io::Result<QuicSocketEvent> {
        loop {
            let event = loop {
                match self.process_pending_h3_events()? {
                    None => {
                        let writable_streams: Vec<_> = {
                            let quic_conn = self.quic_conn.lock().unwrap();
                            let mut waiting_streams = self.waiting_writable_streams.lock().unwrap();
                            let writable_streams: Vec<_> = waiting_streams.iter()
                                .filter(|id| quic_conn.stream_capacity(**id)
                                    .map_or(true, |x| x >= net_utils::MIN_USABLE_QUIC_STREAM_CAPACITY))
                                .copied()
                                .collect();
                            waiting_streams.retain(|id| !writable_streams.contains(id));
                            writable_streams
                        };

                        if !writable_streams.is_empty() {
                            break Some(QuicSocketEvent::Writable(writable_streams));
                        }
                    }
                    Some(event) => break Some(event),
                }

                match self.conn_rx.lock().await
                    .recv().await
                    .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
                {
                    MultiplexerMessage::PollH3 => (),
                    MultiplexerMessage::Close => break None,
                }
            };

            let quic_conn = self.quic_conn.lock().unwrap();
            if quic_conn.is_closed() {
                let _ = self.mux_tx.lock().unwrap()
                    .send(SocketMessage::Close(quic_conn.source_id().into_owned()));
                return Err(io::Error::from(ErrorKind::UnexpectedEof));
            }

            match event {
                None => (),
                Some(ev) => return Ok(ev),
            }
        }
    }

    fn flush_pending_data(&self) -> io::Result<()> {
        flush_pending_data(&mut self.quic_conn.lock().unwrap(), &self.udp_socket, &self.peer, &self.id)
    }

    fn poll_h3_connection(&self) -> h3::Result<(u64, h3::Event)> {
        self.h3_conn.lock().unwrap().poll(&mut self.quic_conn.lock().unwrap())
    }

    fn process_pending_h3_events(&self) -> io::Result<Option<QuicSocketEvent>> {
        match self.poll_h3_connection() {
            Ok((stream_id, h3::Event::Headers { list, .. })) =>
                match self.on_request(stream_id, list) {
                    Ok(x) => Ok(Some(x)),
                    Err(e) => {
                        let _ = self.send_response(
                            stream_id,
                            http::Response::builder()
                                .status(http::StatusCode::BAD_REQUEST)
                                .body(())
                                .unwrap()
                                .into_parts().0,
                            true,
                        );
                        Err(e)
                    }
                },
            Ok((stream_id, h3::Event::Data)) =>
                Ok(Some(QuicSocketEvent::Readable(stream_id))),
            Ok((stream_id, h3::Event::Finished)) =>
                Ok(Some(QuicSocketEvent::Close(stream_id))),
            Ok((stream_id, h3::Event::Reset(err))) => {
                log_id!(trace, self.id, "Stream reset by client: id={}, err={}", stream_id, err);
                Ok(Some(QuicSocketEvent::Close(stream_id)))
            }
            Ok((_flow_id, h3::Event::Datagram)) => Err(io::Error::new(
                ErrorKind::Other, "Received unexpected datagram frame"
            )),
            Ok((_goaway_id, h3::Event::GoAway)) => Err(io::Error::new(
                ErrorKind::UnexpectedEof, "Received GOAWAY"
            )),
            Err(h3::Error::Done) => Ok(None),
            Err(e) => Err(io::Error::new(ErrorKind::Other, e.to_string())),
        }
    }

    fn on_request(&self, stream_id: u64, headers: Vec<h3::Header>) -> io::Result<QuicSocketEvent> {
        let mut request_builder = http::request::Request::builder()
            .version(http::Version::HTTP_3);

        for h in headers {
            request_builder = match h.name() {
                b":method" => request_builder.method(h.value()),
                b":authority" => request_builder.uri(
                    http::uri::Uri::builder()
                        .scheme("https")
                        .authority(h.value())
                        .path_and_query("")
                        .build()
                        .map_err(|e| io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Unexpected URI: error={}, authority=0x{}", e, utils::hex_dump(h.value()))
                        ))?
                ),
                x => match http::header::HeaderName::from_lowercase(x) {
                    Ok(name) => request_builder.header(name, h.value()),
                    Err(InvalidHeaderName { .. }) => return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("Unexpected header name: 0x{}", utils::hex_dump(h.name()))
                    )),
                }
            };
        }

        request_builder.body(())
            .map(|r| QuicSocketEvent::Request(stream_id, Box::new(r.into_parts().0)))
            .map_err(|e| io::Error::new(ErrorKind::Other, format!("Invalid request: {}", e)))
    }
}

impl HandshakingConnection {
    fn proceed_handshake<'a>(
        &self,
        peer: &SocketAddr,
        packet: &mut [u8],
        log_id: &log_utils::IdChain<u64>,
    ) -> io::Result<HandshakeStatus> {
        let mut quic_conn = self.quic_conn.lock().unwrap();
        quic_recv(&mut quic_conn, packet, &quiche::RecvInfo { from: *peer }, log_id)?;

        if quic_conn.is_closed() {
            return Err(io::Error::new(
                ErrorKind::Other, format!("[{}] Connection closed", quic_conn.trace_id())
            ));
        }

        if quic_conn.is_draining() {
            return Ok(HandshakeStatus::InProgress(self.quic_conn.clone()));
        }

        if !quic_conn.is_established() && !quic_conn.is_in_early_data() {
            return Ok(HandshakeStatus::InProgress(self.quic_conn.clone()));
        }

        Ok(HandshakeStatus::Complete)
    }
}

fn flush_pending_data(
    quic_conn: &mut quiche::Connection, udp_socket: &UdpSocket, peer: &SocketAddr, id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    let mut out = [0; net_utils::MAX_DATAGRAM_SIZE];
    loop {
        match quic_conn.send(&mut out) {
            Ok((n, _)) => udp_socket_send_to(udp_socket, &out[..n], peer, id)?,
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(io::Error::new(ErrorKind::Other, e.to_string())),
        }
    }

    Ok(())
}

fn udp_socket_send_to(
    socket: &UdpSocket, data: &[u8], peer: &SocketAddr, id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    match socket.try_send_to(data, *peer) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS) => {
            log_id!(debug, id, "Dropping {} bytes due to socket would block: peer={}", data.len(), peer);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn quic_recv(
    conn: &mut quiche::Connection, packet: &mut [u8], info: &quiche::RecvInfo, id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    match conn.recv(packet, *info) {
        Ok(n) => {
            if n != packet.len() {
                log_id!(debug, id, "Dropping {} bytes unaccepted during handshake: {}",
                    packet.len() - n, conn.trace_id());
            }
            Ok(())
        }
        Err(e) => Err(io::Error::new(
            ErrorKind::Other, format!("QUIC receive failure: {}", e)
        )),
    }
}

fn make_quic_conn_config(
    core_settings: &Settings, cert_chain_file: &str, priv_key_file: &str,
) -> io::Result<quiche::Config> {
    let quic_settings = core_settings.listen_protocols.iter()
        .find_map(|x| if let ListenProtocolSettings::Quic(x) = x { Some(x) } else { None })
        .unwrap();

    let mut cfg = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    cfg.load_cert_chain_from_pem_file(cert_chain_file).unwrap();
    cfg.load_priv_key_from_pem_file(priv_key_file).unwrap();
    cfg.set_application_protos(h3::APPLICATION_PROTOCOL).unwrap();
    cfg.set_max_idle_timeout(core_settings.client_listener_timeout.as_millis() as u64);
    cfg.set_max_recv_udp_payload_size(quic_settings.recv_udp_payload_size);
    cfg.set_max_send_udp_payload_size(quic_settings.send_udp_payload_size);
    cfg.set_initial_max_data(quic_settings.initial_max_data);
    cfg.set_initial_max_stream_data_bidi_local(quic_settings.max_stream_data_bidi_local);
    cfg.set_initial_max_stream_data_bidi_remote(quic_settings.max_stream_data_bidi_remote);
    cfg.set_initial_max_stream_data_uni(quic_settings.max_stream_data_uni);
    cfg.set_initial_max_streams_bidi(quic_settings.max_streams_bidi);
    cfg.set_initial_max_streams_uni(quic_settings.max_streams_uni);
    cfg.set_max_connection_window(quic_settings.max_connection_window);
    cfg.set_max_stream_window(quic_settings.max_stream_window);
    cfg.set_disable_active_migration(quic_settings.disable_active_migration);
    if quic_settings.enable_early_data {
        cfg.enable_early_data();
    }
    Ok(cfg)
}

fn socket_addr_to_vec(addr: &SocketAddr) -> Vec<u8> {
    match addr.ip() {
        std::net::IpAddr::V4(a) => a.octets().iter().cloned()
            .chain(addr.port().to_be_bytes().iter().cloned())
            .collect(),
        std::net::IpAddr::V6(a) => a.octets().iter().cloned()
            .chain(addr.port().to_be_bytes().iter().cloned())
            .collect(),
    }
}

fn mint_token(header: &quiche::Header, prefix: &[u8; TOKEN_PREFIX_SIZE], peer: &SocketAddr) -> Vec<u8> {
    prefix.iter().cloned()
        .chain(socket_addr_to_vec(peer).iter().cloned())
        .chain(header.dcid.iter().cloned())
        .collect()
}

fn validate_token<'a>(prefix: &[u8; TOKEN_PREFIX_SIZE], peer: &SocketAddr, token: &'a [u8])
    -> Option<quiche::ConnectionId<'a>>
{
    token.strip_prefix(prefix)
        .and_then(|token| token.strip_prefix(socket_addr_to_vec(peer).as_slice()))
        .map(quiche::ConnectionId::from_ref)
}
