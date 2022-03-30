use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use lazy_static::lazy_static;
use std::net::UdpSocket;
use bytes::{BufMut, Bytes, BytesMut};


pub(crate) const MAX_DATAGRAM_SIZE: usize = 64 * 1024;
pub(crate) const PLAIN_DNS_PORT_NUMBER: u16 = 53;
pub(crate) const PLAIN_HTTP_PORT_NUMBER: u16 = 80;

pub(crate) const IPV4_WIRE_LENGTH: usize = 4;
pub(crate) const IPV6_WIRE_LENGTH: usize = 16;
const FIXED_LENGTH_IP_WIRE_LENGTH: usize = IPV6_WIRE_LENGTH;
const IPV4_PADDING_WIRE_LENGTH: usize = FIXED_LENGTH_IP_WIRE_LENGTH - IPV4_WIRE_LENGTH;

pub(crate) const HTTP1_ALPN: &str = "http/1.1";
pub(crate) const HTTP2_ALPN: &str = "h2";
pub(crate) const HTTP3_ALPN: &str = "h3";

pub(crate) const QUIC_DATA_FRAME_ID_WIRE_LENGTH: usize = varint_len(0);
/// The minimum value of a stream capacity which allows to send a data chunk.
/// Consists of 1 byte for frame ID, 1 byte for the shortest frame length, and
/// 1 byte for the chunk itself.
pub(crate) const MIN_USABLE_QUIC_STREAM_CAPACITY: usize = QUIC_DATA_FRAME_ID_WIRE_LENGTH + 1 + 1;

lazy_static! {
    pub(crate) static ref IPV4_BIND_ADDRESS: SocketAddr = SocketAddr::from_str("0.0.0.0:0").unwrap();
    pub(crate) static ref IPV6_BIND_ADDRESS: SocketAddr = SocketAddr::from_str("[::]:0").unwrap();
}

pub(crate) type HostnamePort = (String, u16);

#[derive(Debug)]
pub(crate) enum TcpDestination {
    Address(SocketAddr),
    HostName(HostnamePort),
}

pub(crate) fn make_udp_socket(is_v4: bool) -> std::io::Result<UdpSocket> {
    if is_v4 {
        UdpSocket::bind(*IPV4_BIND_ADDRESS)
    } else {
        UdpSocket::bind(*IPV6_BIND_ADDRESS)
    }
}

/// https://www.rfc-editor.org/rfc/rfc9000.html#section-16
pub(crate) const fn varint_len(x: usize) -> usize {
    if x <= 63 {
        1
    } else if x <= 16_383 {
        2
    } else if x <= 1_073_741_823 {
        4
    } else if x <= 4_611_686_018_427_387_903 {
        8
    } else {
        unreachable!()
    }
}

pub(crate) fn get_fixed_size_ip(bytes: &mut Bytes) -> IpAddr {
    let ip = bytes.split_to(IPV6_WIRE_LENGTH);
    if ip[..IPV4_PADDING_WIRE_LENGTH].iter().all(|x| *x == 0) {
        let address: [u8; IPV4_WIRE_LENGTH] = ip[IPV4_PADDING_WIRE_LENGTH..].try_into().unwrap();
        IpAddr::from(address)
    } else {
        let address: [u8; FIXED_LENGTH_IP_WIRE_LENGTH] = ip[..].try_into().unwrap();
        IpAddr::from(address)
    }
}

pub(crate) fn put_fixed_size_ip(bytes: &mut BytesMut, ip: &IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            bytes.put_slice(&[0; IPV4_PADDING_WIRE_LENGTH]);
            bytes.put_slice(&ip.octets());
        },
        IpAddr::V6(ip) => bytes.put_slice(&ip.octets()),
    }
}
