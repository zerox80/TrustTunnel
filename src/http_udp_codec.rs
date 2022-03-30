use std::net::SocketAddr;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::{downstream, forwarder, http_datagram_codec, log_id, log_utils, net_utils};


/// Outgoing UDP packet format (sent from us to client)
///
/// +----------+----------------+-------------+---------------------+------------------+---------+
/// |  Length  | Source address | Source port | Destination address | Destination port | Payload |
/// | 4 bytes  |  16 bytes      | 2 bytes     |  16 bytes           | 2 bytes          | N bytes |
/// +----------+----------------+-------------+---------------------+------------------+---------+
///
/// Incoming UDP packet format (sent from client to us)
///
/// +----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+
/// |  Length  | Source address | Source port | Destination address | Destination port | App name len (L) | App name | Payload |
/// | 4 bytes  |  16 bytes      | 2 bytes     |  16 bytes           | 2 bytes          | 1 byte           | L bytes  | N bytes |
/// +----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+


const UDPPKT_LENGTH_SIZE: usize = 4;
const UDPPKT_ADDR_SIZE: usize = 16;
const UDPPKT_PORT_SIZE: usize = 2;
const UDPPKT_APPLEN_SIZE: usize = 1;

const UDPPKT_IN_FIXED_HEADER_SIZE: usize = UDPPKT_LENGTH_SIZE + 2 * (UDPPKT_ADDR_SIZE + UDPPKT_PORT_SIZE) + UDPPKT_APPLEN_SIZE;
const UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE: usize = UDPPKT_IN_FIXED_HEADER_SIZE - UDPPKT_LENGTH_SIZE;
const UDPPKT_OUT_FIXED_HEADER_SIZE: usize = UDPPKT_LENGTH_SIZE + 2 * (UDPPKT_ADDR_SIZE + UDPPKT_PORT_SIZE);
const UDPPKT_OUT_FIXED_HEADER_NO_LENGTH_SIZE: usize = UDPPKT_OUT_FIXED_HEADER_SIZE - UDPPKT_LENGTH_SIZE;

const MAX_UDP_IN_PAYLOAD_SIZE: usize = net_utils::MAX_DATAGRAM_SIZE - UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE;


pub(crate) struct Decoder {
    state: RecvState,
    total_length: usize,
    buffer: BytesMut,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    app_name: Option<String>,
    id: log_utils::IdChain<u64>,
}

#[derive(Default)]
pub(crate) struct Encoder {}

impl Decoder {
    pub fn new(
        id: log_utils::IdChain<u64>,
    ) -> Self {
        Self {
            state: Default::default(),
            total_length: 0,
            buffer: Default::default(),
            source: None,
            destination: None,
            app_name: None,
            id,
        }
    }

    fn decode_chunk_once(&mut self, mut data: Bytes) -> (Option<downstream::UdpDatagram>, Bytes) {
        match self.state {
            RecvState::Length => (None, self.process_client_length(data)),
            RecvState::FixedHeader => (None, self.process_client_fixed_header(data)),
            RecvState::AppName(length) => (None, self.process_client_app_name(length, data)),
            RecvState::Payload(length) => self.process_client_payload(length, data),
            RecvState::Dropping(remaining_length) => {
                let to_drop = remaining_length.min(data.len());

                if remaining_length <= to_drop {
                    self.state = RecvState::Length
                } else {
                    self.state = RecvState::Dropping(remaining_length - to_drop)
                }

                (None, data.split_to(to_drop))
            }
        }
    }

    fn process_client_length(&mut self, data: Bytes) -> Bytes {
        let (mut raw_length, tail) =
            match self.buffered_read(data, UDPPKT_LENGTH_SIZE) {
                Some(x) => x,
                None => return Bytes::new(),
            };

        self.total_length = raw_length.get_u32() as usize;
        if self.total_length >= UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE {
            self.state = RecvState::FixedHeader;
        } else {
            log_id!(debug, self.id, "UDP packet length ({}) is less than fixed header size - dropping it",
                self.total_length);
            self.state = RecvState::Dropping(self.total_length);
        }

        tail
    }

    fn process_client_fixed_header(&mut self, data: Bytes) -> Bytes {
        let (mut header, tail) =
            match self.buffered_read(data, UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE) {
                Some(x) => x,
                None => return Bytes::new(),
            };

        self.source = Some(SocketAddr::new(
            net_utils::get_fixed_size_ip(&mut header), header.get_u16()
        ));
        self.destination = Some(SocketAddr::new(
            net_utils::get_fixed_size_ip(&mut header), header.get_u16()
        ));
        let app_name_length = header.get_u8() as usize;
        if self.total_length > MAX_UDP_IN_PAYLOAD_SIZE - app_name_length {
            log_id!(debug, self.id, "Too large UDP packet length ({}) - dropping it", self.total_length);
            self.state = RecvState::Dropping(
                self.total_length - UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE
            );
        } else if self.total_length >= UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE + app_name_length {
            self.state = RecvState::AppName(app_name_length);
        } else {
            log_id!(debug, self.id, "UDP packet length ({}) is less than header size - dropping it",
                self.total_length);
            self.state = RecvState::Dropping(
                self.total_length - UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE
            );
        }

        tail
    }

    fn process_client_app_name(&mut self, length: usize, data: Bytes) -> Bytes {
        let (name, tail) =
            match self.buffered_read(data, length) {
                Some(x) => x,
                None => return Bytes::new(),
            };

        let payload_length = self.total_length - UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE - length;
        match std::str::from_utf8(name.as_ref()) {
            Ok(name) => {
                self.app_name = Some(name.to_string());
                self.state = RecvState::Payload(payload_length);
            }
            Err(e) => {
                log_id!(debug, self.id, "Failed to convert app name: {}, dropping the rest of the packet",
                    e.to_string());
                self.state = RecvState::Dropping(payload_length);
            }
        }

        tail
    }

    fn process_client_payload(
        &mut self, length: usize, mut data: Bytes
    ) -> (Option<downstream::UdpDatagram>, Bytes) {
        let (to_send, tail) =
            if self.buffer.is_empty() && data.len() >= length {
                (data.split_to(length), data)
            } else {
                let to_drain = data.len().min(length - self.buffer.len());
                self.buffer.extend_from_slice(data.split_to(to_drain).as_ref());
                if self.buffer.len() < length {
                    return (None, data);
                }

                (std::mem::take(&mut self.buffer).freeze(), data)
            };

        self.state = RecvState::Length;
        (
            Some(downstream::UdpDatagram {
                meta: downstream::UdpDatagramMeta {
                    source: self.source.unwrap(),
                    destination: self.destination.unwrap(),
                    app_name: self.app_name.take(),
                },
                payload: to_send,
            }),
            tail
        )
    }

    fn buffered_read(&mut self, mut input: Bytes, cap: usize) -> Option<(Bytes, Bytes)> {
        assert!(self.buffer.len() < cap || cap == 0, "buffer={} cap={}", self.buffer.len(), cap);

        let to_drain = input.len().min(cap - self.buffer.len());
        self.buffer.extend_from_slice(input.split_to(to_drain).as_ref());

        if self.buffer.len() < cap {
            assert!(input.is_empty());
            return None;
        }

        Some((std::mem::take(&mut self.buffer).freeze(), input))
    }
}

impl http_datagram_codec::Decoder for Decoder {
    type Datagram = downstream::UdpDatagram;

    fn decode_chunk(&mut self, mut data: Bytes) -> http_datagram_codec::DecodeResult<Self::Datagram> {
        while !data.is_empty() {
            match self.decode_chunk_once(data) {
                (Some(d), tail) => return http_datagram_codec::DecodeResult::Complete(d, tail),
                (None, tail) => data = tail,
            }
        }

        assert!(data.is_empty(), "Expected to be fully processed, but {} bytes left unprocessed", data.len());
        http_datagram_codec::DecodeResult::WantMore
    }
}

impl http_datagram_codec::Encoder for Encoder {
    type Datagram = forwarder::UdpDatagram;

    fn encode_packet(&self, datagram: &Self::Datagram) -> Option<Bytes> {
        let total_length = UDPPKT_OUT_FIXED_HEADER_NO_LENGTH_SIZE + datagram.payload.len();
        let mut encoded = BytesMut::with_capacity(total_length);

        encoded.put_u32(total_length as u32);
        net_utils::put_fixed_size_ip(&mut encoded, &datagram.meta.source.ip());
        encoded.put_u16(datagram.meta.source.port());
        net_utils::put_fixed_size_ip(&mut encoded, &datagram.meta.destination.ip());
        encoded.put_u16(datagram.meta.destination.port());

        encoded.extend_from_slice(&datagram.payload);

        Some(encoded.freeze())
    }
}

#[derive(Debug)]
enum RecvState {
    /// Waiting for the `Length` field
    Length,
    /// Waiting for the header (without app name) completion
    FixedHeader,
    /// Waiting for the `App name` field
    AppName(usize),
    /// Waiting for the payload completion
    Payload(usize),
    /// Dropping the packet for some reason
    Dropping(usize),
}

impl Default for RecvState {
    fn default() -> Self { RecvState::Length }
}
