use std::fmt::Formatter;
use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use serde::Deserialize;
use crate::authentication::{Authenticator, DummyAuthenticator};
use crate::authentication::file_based::FileBasedAuthenticator;
use crate::authentication::radius::RadiusAuthenticator;


pub type Result<T> = std::result::Result<T, BuilderError>;
pub type Socks5Result<T> = std::result::Result<T, Socks5Error>;

#[derive(Deserialize)]
pub struct Settings {
    /// The number of worker threads.
    /// By default it is set to the number of CPUs on the machine.
    #[serde(default = "Settings::default_threads_number")]
    pub(crate) threads_number: usize,
    /// The address to listen on
    #[serde(default = "Settings::default_listen_address")]
    pub(crate) listen_address: SocketAddr,
    /// The TLS host info for traffic tunneling
    pub(crate) tunnel_tls_host_info: TlsHostInfo,
    /// The TLS host info of service messenger
    pub(crate) service_messenger_tls_host_info: Option<TlsHostInfo>,
    /// IPv6 availability
    #[serde(default = "Settings::default_ipv6_available")]
    pub(crate) ipv6_available: bool,
    /// Time out of a TLS handshake
    #[serde(default = "Settings::default_tls_handshake_timeout")]
    #[serde(rename(deserialize = "tls_handshake_timeout_secs"))]
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub(crate) tls_handshake_timeout: Duration,
    /// Time out of a client listener
    #[serde(default = "Settings::default_client_listener_timeout")]
    #[serde(rename(deserialize = "client_listener_timeout_secs"))]
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub(crate) client_listener_timeout: Duration,
    /// Time out of tunneled TCP connections
    #[serde(default = "Settings::default_tcp_connections_timeout")]
    #[serde(rename(deserialize = "tcp_connections_timeout_secs"))]
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub(crate) tcp_connections_timeout: Duration,
    /// Time out of tunneled UDP "connections"
    #[serde(default = "Settings::default_udp_connections_timeout")]
    #[serde(rename(deserialize = "udp_connections_timeout_secs"))]
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub(crate) udp_connections_timeout: Duration,
    /// The forwarder codec settings
    #[serde(default)]
    pub(crate) forward_protocol: ForwardProtocolSettings,
    /// The list of listener codec settings
    #[serde(deserialize_with = "deserialize_protocols")]
    pub(crate) listen_protocols: Vec<ListenProtocolSettings>,
    /// The client authenticator
    #[serde(default = "Settings::default_authenticator")]
    #[serde(deserialize_with = "deserialize_authenticator")]
    pub(crate) authenticator: Arc<dyn Authenticator>,
    /// The ICMP forwarding settings.
    /// Setting up this feature requires superuser rights on some systems.
    pub(crate) icmp: Option<IcmpSettings>,
}

#[derive(Default, Deserialize)]
pub struct TlsHostInfo {
    /// Used as a key for selecting a certificate chain in TLS handshake
    pub hostname: String,
    /// Path to a file containing the certificate chain
    #[serde(deserialize_with = "deserialize_file_path")]
    pub cert_chain_path: String,
    /// Path to a file containing the private key.
    /// May be equal to `cert_chain_path` if it contains both of them.
    #[serde(deserialize_with = "deserialize_file_path")]
    pub private_key_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProtocolSettings {
    /// A direct forwarder routes a connection directly to its target host
    Direct(DirectForwarderSettings),
    /// A SOCKS5 forwarder routes a connection though a SOCKS5 proxy
    Socks5(Socks5ForwarderSettings),
}

#[derive(Deserialize)]
pub struct DirectForwarderSettings {}

#[derive(Deserialize)]
pub struct Socks5ForwarderSettings {
    /// The address of a proxy
    pub(crate) address: SocketAddr,
}

pub struct Socks5ForwarderSettingsBuilder {
    settings: Socks5ForwarderSettings,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenProtocolSettings {
    Http1(Http1Settings),
    Http2(Http2Settings),
    Quic(QuicSettings),
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatorSettings {
    File(FileBasedAuthenticatorSettings),
    Radius(RadiusAuthenticatorSettings)
}

#[derive(Deserialize)]
pub struct FileBasedAuthenticatorSettings {
    /// A path to the file containing the authentication info
    #[serde(deserialize_with = "deserialize_file_path")]
    pub(crate) path: String,
}

#[derive(Deserialize)]
pub struct RadiusAuthenticatorSettings {
    /// The RADIUS server address
    pub(crate) server_address: SocketAddr,
    /// Timeout of the authentication procedure
    #[serde(default = "RadiusAuthenticatorSettings::default_timeout")]
    #[serde(rename(deserialize = "timeout_secs"))]
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub(crate) timeout: Duration,
    /// The password shared between the client and the RADIUS server
    pub(crate) secret: String,
    /// The authentication cache capacity
    #[serde(default = "RadiusAuthenticatorSettings::default_cache_size")]
    pub(crate) cache_size: usize,
    /// The authentication cache entry TTL
    #[serde(default = "RadiusAuthenticatorSettings::default_cache_ttl")]
    #[serde(rename(deserialize = "cache_ttl_secs"))]
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub(crate) cache_ttl: Duration,
}

#[derive(Deserialize)]
pub struct IcmpSettings {
    /// The name of an interface to bind the ICMP socket to
    pub(crate) interface_name: String,
    /// Time out of tunneled ICMP requests
    #[serde(default = "IcmpSettings::default_request_timeout")]
    #[serde(rename(deserialize = "urequest_timeout_secs"))]
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub(crate) request_timeout: Duration,
    /// The capacity of the ICMP multiplexer received messages queue.
    /// Decreasing it may cause packet dropping in case the multiplexer cannot keep up the pace.
    /// Increasing it may lead to high memory consumption.
    /// Each client has its own queue.
    #[serde(default = "IcmpSettings::default_message_queue_capacity")]
    pub(crate) recv_message_queue_capacity: usize,
}

#[derive(Deserialize)]
pub struct Http1Settings {}

#[derive(Deserialize)]
pub struct Http2Settings {
    /// The initial window size (in octets) for connection-level flow control for received data
    #[serde(default = "Http2Settings::default_initial_connection_window_size")]
    pub(crate) initial_connection_window_size: u32,
    /// The initial window size (in octets) for stream-level flow control for received data
    #[serde(default = "Http2Settings::default_initial_stream_window_size")]
    pub(crate) initial_stream_window_size: u32,
    /// The number of streams that the sender permits the receiver to create
    #[serde(default = "Http2Settings::default_max_concurrent_streams")]
    pub(crate) max_concurrent_streams: u32,
    /// The size (in octets) of the largest HTTP/2 frame payload that we are able to accept
    #[serde(default = "Http2Settings::default_max_frame_size")]
    pub(crate) max_frame_size: u32,
    /// The max size of received header frames
    #[serde(default = "Http2Settings::default_header_table_size")]
    pub(crate) header_table_size: u32,
}

#[derive(Deserialize)]
pub struct QuicSettings {
    /// The size of UDP payloads that the endpoint is willing to receive. UDP datagrams with
    /// payloads larger than this limit are not likely to be processed.
    #[serde(default = "QuicSettings::default_recv_udp_payload_size")]
    pub(crate) recv_udp_payload_size: usize,
    /// The size of UDP payloads that the endpoint is willing to send
    #[serde(default = "QuicSettings::default_send_udp_payload_size")]
    pub(crate) send_udp_payload_size: usize,
    /// The initial value for the maximum amount of data that can be sent on the connection
    #[serde(default = "QuicSettings::default_initial_max_data")]
    pub(crate) initial_max_data: u64,
    /// The initial flow control limit for locally initiated bidirectional streams
    #[serde(default = "QuicSettings::default_max_stream_data_bidi_local")]
    pub(crate) max_stream_data_bidi_local: u64,
    /// The initial flow control limit for peer-initiated bidirectional streams
    #[serde(default = "QuicSettings::default_max_stream_data_bidi_remote")]
    pub(crate) max_stream_data_bidi_remote: u64,
    /// The initial flow control limit for unidirectional streams
    #[serde(default = "QuicSettings::default_max_stream_data_uni")]
    pub(crate) max_stream_data_uni: u64,
    /// The initial maximum number of bidirectional streams the endpoint that receives this
    /// transport parameter is permitted to initiate
    #[serde(default = "QuicSettings::default_max_streams_bidi")]
    pub(crate) max_streams_bidi: u64,
    /// The initial maximum number of unidirectional streams the endpoint that receives this
    /// transport parameter is permitted to initiate
    #[serde(default = "QuicSettings::default_max_streams_uni")]
    pub(crate) max_streams_uni: u64,
    /// The maximum size of the connection window
    #[serde(default = "QuicSettings::default_max_connection_window")]
    pub(crate) max_connection_window: u64,
    /// The maximum size of the stream window
    #[serde(default = "QuicSettings::default_max_stream_window")]
    pub(crate) max_stream_window: u64,
    /// Disable active connection migration on the address being used during the handshake
    #[serde(default = "QuicSettings::default_disable_active_migration")]
    pub(crate) disable_active_migration: bool,
    /// Enable sending or receiving early data
    #[serde(default = "QuicSettings::default_enable_early_data")]
    pub(crate) enable_early_data: bool,
    /// The capacity of the QUIC multiplexer message queue.
    /// Decreasing it may cause packet dropping in case the multiplexer cannot keep up the pace.
    /// Increasing it may lead to high memory consumption.
    // @todo: separate values for incoming and outgoing?
    #[serde(default = "QuicSettings::default_message_queue_capacity")]
    pub(crate) message_queue_capacity: usize,
}

pub struct SettingsBuilder {
    settings: Settings,
    tunnel_tls_host_info_set: bool,
    authenticator: Option<Box<dyn Authenticator>>,
}

pub struct Http1SettingsBuilder {
    settings: Http1Settings,
}

pub struct Http2SettingsBuilder {
    settings: Http2Settings,
}

pub struct QuicSettingsBuilder {
    settings: QuicSettings,
}

pub struct RadiusAuthenticatorSettingsBuilder {
    settings: RadiusAuthenticatorSettings,
}

pub struct IcmpSettingsBuilder {
    settings: IcmpSettings,
}

#[derive(Debug)]
pub enum BuilderError {
    /// Invalid [`Settings.listen_address`]
    ListenAddress(String),
    /// Invalid [`Settings.tunnel_tls_host_info`]
    TunnelTlsHostInfo(String),
    /// Invalid [`Settings.service_messenger_tls_host_info`]
    ServiceMessengerTlsHostInfo(String),
    /// [`Settings.listen_protocols`] are not set
    ListenProtocols,
    /// Invalid authentication info
    AuthInfo(String),
}

#[derive(Debug)]
pub enum Socks5Error {
    /// Invalid [`Socks5ForwarderSettings.address`]
    Address(String),
}

impl Settings {
    pub fn builder() -> SettingsBuilder {
        SettingsBuilder::new()
    }

    fn default_threads_number() -> usize {
        num_cpus::get()
    }

    fn default_listen_address() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443))
    }

    fn default_ipv6_available() -> bool {
        true
    }

    fn default_authenticator() -> Arc<dyn Authenticator> {
        Arc::new(DummyAuthenticator {})
    }

    fn default_tls_handshake_timeout() -> Duration {
        Duration::from_secs(10)
    }

    fn default_client_listener_timeout() -> Duration {
        Duration::from_secs(10 * 60)
    }

    fn default_tcp_connections_timeout() -> Duration {
        Duration::from_secs(30)
    }

    fn default_udp_connections_timeout() -> Duration {
        Duration::from_secs(30)
    }
}

impl Socks5ForwarderSettings {
    pub fn builder() -> Socks5ForwarderSettingsBuilder {
        Socks5ForwarderSettingsBuilder::new()
    }
}

impl Http1Settings {
    pub fn builder() -> Http1SettingsBuilder {
        Http1SettingsBuilder::new()
    }
}

impl Http2Settings {
    pub fn builder() -> Http2SettingsBuilder {
        Http2SettingsBuilder::new()
    }

    fn default_initial_connection_window_size() -> u32 {
        8 * 1024 * 1024
    }

    fn default_initial_stream_window_size() -> u32 {
        128 * 1024 // Chrome constant
    }

    fn default_max_concurrent_streams() -> u32 {
        1000 // Chrome constant
    }

    fn default_max_frame_size() -> u32 {
        1 << 14 // Firefox constant
    }

    fn default_header_table_size() -> u32 {
        65536
    }
}

impl QuicSettings {
    pub fn builder() -> QuicSettingsBuilder {
        QuicSettingsBuilder::new()
    }

    fn default_recv_udp_payload_size() -> usize {
        1350
    }

    fn default_send_udp_payload_size() -> usize {
        1350
    }

    fn default_initial_max_data() -> u64 {
        100 * 1024 * 1024
    }

    fn default_max_stream_data_bidi_local() -> u64 {
        1024 * 1024
    }

    fn default_max_stream_data_bidi_remote() -> u64 {
        1024 * 1024
    }

    fn default_max_stream_data_uni() -> u64 {
        1024 * 1024
    }

    fn default_max_streams_bidi() -> u64 {
        4 * 1024
    }

    fn default_max_streams_uni() -> u64 {
        4 * 1024
    }

    fn default_max_connection_window() -> u64 {
        24 * 1024 * 1024
    }

    fn default_max_stream_window() -> u64 {
        16 * 1024 * 1024
    }

    fn default_disable_active_migration() -> bool {
        true
    }

    fn default_enable_early_data() -> bool {
        true
    }

    fn default_message_queue_capacity() -> usize {
        4 * 1024
    }
}

impl RadiusAuthenticatorSettings {
    pub fn builder() -> RadiusAuthenticatorSettingsBuilder {
        RadiusAuthenticatorSettingsBuilder::new()
    }

    fn default_timeout() -> Duration {
        Duration::from_secs(3)
    }

    fn default_cache_size() -> usize {
        1024
    }

    fn default_cache_ttl() -> Duration {
        Duration::from_secs(10)
    }
}

impl IcmpSettings {
    pub fn builder() -> IcmpSettingsBuilder {
        IcmpSettingsBuilder::new()
    }

    fn default_request_timeout() -> Duration {
        Duration::from_secs(3)
    }

    fn default_message_queue_capacity() -> usize {
        256
    }
}

impl SettingsBuilder {
    fn new() -> Self {
        Self {
            settings: Settings {
                threads_number: Settings::default_threads_number(),
                listen_address: Settings::default_listen_address(),
                tunnel_tls_host_info: Default::default(),
                service_messenger_tls_host_info: None,
                ipv6_available: Settings::default_ipv6_available(),
                tls_handshake_timeout: Settings::default_tls_handshake_timeout(),
                client_listener_timeout: Settings::default_client_listener_timeout(),
                tcp_connections_timeout: Settings::default_tcp_connections_timeout(),
                udp_connections_timeout: Settings::default_udp_connections_timeout(),
                forward_protocol: Default::default(),
                listen_protocols: vec![],
                authenticator: Settings::default_authenticator(),
                icmp: None,
            },
            tunnel_tls_host_info_set: false,
            authenticator: None,
        }
    }

    /// Finalize [`Settings`]
    pub fn build(mut self) -> Result<Settings> {
        if self.settings.listen_address.ip().is_unspecified() && self.settings.listen_address.port() == 0 {
            return Err(BuilderError::ListenAddress("Not set".to_string()));
        }

        if !self.tunnel_tls_host_info_set {
            return Err(BuilderError::TunnelTlsHostInfo("Not set".to_string()));
        }
        validate_file_path(&self.settings.tunnel_tls_host_info.cert_chain_path)
            .map_err(|e| BuilderError::TunnelTlsHostInfo(format!("Invalid cert chain path: {}", e)))?;
        validate_file_path(&self.settings.tunnel_tls_host_info.private_key_path)
            .map_err(|e| BuilderError::TunnelTlsHostInfo(format!("Invalid key path: {}", e)))?;

        if let Some(x) = &self.settings.service_messenger_tls_host_info {
            validate_file_path(&x.cert_chain_path)
                .map_err(|e| BuilderError::ServiceMessengerTlsHostInfo(format!("Invalid cert chain path: {}", e)))?;
            validate_file_path(&x.private_key_path)
                .map_err(|e| BuilderError::ServiceMessengerTlsHostInfo(format!("Invalid key path: {}", e)))?;
        }

        if self.settings.listen_protocols.is_empty() {
            return Err(BuilderError::ListenProtocols);
        }

        self.settings.authenticator = Arc::from(
            self.authenticator.ok_or_else(|| BuilderError::AuthInfo("Not set".to_string()))?
        );

        Ok(self.settings)
    }

    /// Set the number of worker threads
    pub fn threads_number(mut self, v: usize) -> Self {
        self.settings.threads_number = v;
        self
    }

    /// Set the address to listen on
    pub fn listen_address<A: ToSocketAddrs>(mut self, addr: A) -> io::Result<Self> {
        self.settings.listen_address = addr.to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "Parsed address to empty list"))?;
        Ok(self)
    }

    /// Set the TLS host info for traffic tunneling
    pub fn tunnel_tls_host_info(mut self, info: TlsHostInfo) -> Self {
        self.settings.tunnel_tls_host_info = info;
        self.tunnel_tls_host_info_set = true;
        self
    }

    /// Set the TLS host info of service messenger
    pub fn service_messenger_tls_host_info(mut self, info: TlsHostInfo) -> Self {
        self.settings.service_messenger_tls_host_info = Some(info);
        self
    }

    /// Set IPv6 availability
    pub fn ipv6_available(mut self, v: bool) -> Self {
        self.settings.ipv6_available = v;
        self
    }

    /// Set time out of TLS handshake
    pub fn tls_handshake_timeout(mut self, v: Duration) -> Self {
        self.settings.tls_handshake_timeout = v;
        self
    }

    /// Set time out of client listener
    pub fn client_listener_timeout(mut self, v: Duration) -> Self {
        self.settings.client_listener_timeout = v;
        self
    }

    /// Set time out of tunneled TCP connections
    pub fn tcp_connections_timeout(mut self, v: Duration) -> Self {
        self.settings.tcp_connections_timeout = v;
        self
    }

    /// Set time out of tunneled UDP "connections"
    pub fn udp_connections_timeout(mut self, v: Duration) -> Self {
        self.settings.udp_connections_timeout = v;
        self
    }

    /// Set the forwarder codec settings
    pub fn forwarder_settings(mut self, settings: ForwardProtocolSettings) -> Self {
        self.settings.forward_protocol = settings;
        self
    }

    /// Add the listener codec settings
    pub fn add_listen_protocol(mut self, settings: ListenProtocolSettings) -> Self {
        self.settings.listen_protocols.push(settings);
        self
    }

    /// Set the client authenticator
    pub fn authenticator(mut self, x: Box<dyn Authenticator>) -> Self {
        self.authenticator = Some(x);
        self
    }

    /// Set the ICMP forwarder settings
    pub fn icmp(mut self, x: IcmpSettings) -> Self {
        self.settings.icmp = Some(x);
        self
    }
}

impl Socks5ForwarderSettingsBuilder {
    fn new() -> Self {
        Self {
            settings: Socks5ForwarderSettings {
                address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            },
        }
    }

    /// Finalize [`Socks5ForwarderSettings`]
    pub fn build(self) -> Socks5Result<Socks5ForwarderSettings> {
        if self.settings.address.ip().is_unspecified() {
            return Err(Socks5Error::Address("Not set".to_string()));
        }

        Ok(self.settings)
    }

    /// Set the SOCKS proxy address
    pub fn server_address<A: ToSocketAddrs>(mut self, v: A) -> io::Result<Self> {
        self.settings.address = v.to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "Parsed address to empty list"))?;
        Ok(self)
    }
}

impl Http1SettingsBuilder {
    fn new() -> Self {
        Self {
            settings: Http1Settings {},
        }
    }

    /// Finalize [`Http1Settings`]
    pub fn build(self) -> Http1Settings {
        self.settings
    }
}

impl Http2SettingsBuilder {
    fn new() -> Self {
        Self {
            settings: Http2Settings {
                initial_connection_window_size: Http2Settings::default_initial_connection_window_size(),
                initial_stream_window_size: Http2Settings::default_initial_stream_window_size(),
                max_concurrent_streams: Http2Settings::default_max_concurrent_streams(),
                max_frame_size: Http2Settings::default_max_frame_size(),
                header_table_size: Http2Settings::default_header_table_size(),
            },
        }
    }

    /// Finalize [`Http2Settings`]
    pub fn build(self) -> Http2Settings {
        self.settings
    }

    /// Set the initial window size (in octets) for connection-level flow control for received data
    pub fn initial_connection_window_size(mut self, v: u32) -> Self {
        self.settings.initial_connection_window_size = v;
        self
    }

    /// Set the initial window size (in octets) for stream-level flow control for received data
    pub fn initial_stream_window_size(mut self, v: u32) -> Self {
        self.settings.initial_stream_window_size = v;
        self
    }

    /// Set the maximum number of concurrent streams
    pub fn max_concurrent_streams(mut self, v: u32) -> Self {
        self.settings.max_concurrent_streams = v;
        self
    }

    /// Set the size (in octets) of the largest HTTP/2 frame payload that we are able to accept
    pub fn max_frame_size(mut self, v: u32) -> Self {
        self.settings.max_frame_size = v;
        self
    }

    /// Set the max size of received header frames
    pub fn header_table_size(mut self, v: u32) -> Self {
        self.settings.header_table_size = v;
        self
    }
}

impl QuicSettingsBuilder {
    fn new() -> Self {
        Self {
            settings: QuicSettings {
                recv_udp_payload_size: QuicSettings::default_recv_udp_payload_size(),
                send_udp_payload_size: QuicSettings::default_send_udp_payload_size(),
                initial_max_data: QuicSettings::default_initial_max_data(),
                max_stream_data_bidi_local: QuicSettings::default_max_stream_data_bidi_local(),
                max_stream_data_bidi_remote: QuicSettings::default_max_stream_data_bidi_remote(),
                max_stream_data_uni: QuicSettings::default_max_stream_data_uni(),
                max_streams_bidi: QuicSettings::default_max_streams_bidi(),
                max_streams_uni: QuicSettings::default_max_streams_uni(),
                max_connection_window: QuicSettings::default_max_connection_window(),
                max_stream_window: QuicSettings::default_max_stream_window(),
                disable_active_migration: QuicSettings::default_disable_active_migration(),
                enable_early_data: QuicSettings::default_enable_early_data(),
                message_queue_capacity: QuicSettings::default_message_queue_capacity(),
            }
        }
    }

    /// Finalize [`QuicSettings`]
    pub fn build(self) -> QuicSettings {
        self.settings
    }

    /// Set the `max_udp_payload_size transport` parameter
    pub fn recv_udp_payload_size(mut self, v: usize) -> Self {
        self.settings.recv_udp_payload_size = v;
        self
    }

    /// Set the maximum outgoing UDP payload size
    pub fn send_udp_payload_size(mut self, v: usize) -> Self {
        self.settings.send_udp_payload_size = v;
        self
    }

    /// Set the `initial_max_data` transport parameter
    pub fn initial_max_data(mut self, v: u64) -> Self {
        self.settings.initial_max_data = v;
        self
    }

    /// Set the `initial_max_stream_data_bidi_local` transport parameter
    pub fn max_stream_data_bidi_local(mut self, v: u64) -> Self {
        self.settings.max_stream_data_bidi_local = v;
        self
    }

    /// Set the `initial_max_stream_data_bidi_remote` transport parameter
    pub fn max_stream_data_bidi_remote(mut self, v: u64) -> Self {
        self.settings.max_stream_data_bidi_remote = v;
        self
    }

    /// Set the `initial_max_stream_data_uni` transport parameter
    pub fn max_stream_data_uni(mut self, v: u64) -> Self {
        self.settings.max_stream_data_uni = v;
        self
    }

    /// Set the `initial_max_streams_bidi` transport parameter
    pub fn max_streams_bidi(mut self, v: u64) -> Self {
        self.settings.max_streams_bidi = v;
        self
    }

    /// Set the `initial_max_streams_uni` transport parameter
    pub fn max_streams_uni(mut self, v: u64) -> Self {
        self.settings.max_streams_uni = v;
        self
    }

    /// Set the maximum size of the connection window
    pub fn max_connection_window(mut self, v: u64) -> Self {
        self.settings.max_connection_window = v;
        self
    }

    /// Set the maximum size of the stream window
    pub fn max_stream_window(mut self, v: u64) -> Self {
        self.settings.max_stream_window = v;
        self
    }

    /// Set the `disable_active_migration` transport parameter
    pub fn disable_active_migration(mut self, v: bool) -> Self {
        self.settings.disable_active_migration = v;
        self
    }

    /// Enable receiving early data
    pub fn enable_early_data(mut self, v: bool) -> Self {
        self.settings.enable_early_data = v;
        self
    }

    /// Set the capacity of the QUIC multiplexer message queue
    pub fn message_queue_capacity(mut self, v: usize) -> Self {
        self.settings.message_queue_capacity = v;
        self
    }
}

impl RadiusAuthenticatorSettingsBuilder {
    fn new() -> Self {
        Self {
            settings: RadiusAuthenticatorSettings {
                server_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                timeout: RadiusAuthenticatorSettings::default_timeout(),
                secret: Default::default(),
                cache_size: RadiusAuthenticatorSettings::default_cache_size(),
                cache_ttl: RadiusAuthenticatorSettings::default_cache_ttl(),
            },
        }
    }

    /// Finalize [`RadiusAuthenticatorSettings`]
    pub fn build(self) -> RadiusAuthenticatorSettings {
        self.settings
    }

    /// Set the RADIUS server address
    pub fn server_address<A: ToSocketAddrs>(mut self, v: A) -> io::Result<Self> {
        self.settings.server_address = v.to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "Parsed address to empty list"))?;
        Ok(self)
    }

    /// Set timeout of the authentication procedure
    pub fn timeout(mut self, v: Duration) -> Self {
        self.settings.timeout = v;
        self
    }

    /// Set the password shared between the client and the RADIUS server
    pub fn secret(mut self, v: String) -> Self {
        self.settings.secret = v;
        self
    }

    /// Set the authentication cache capacity
    pub fn cache_size(mut self, v: usize) -> Self {
        self.settings.cache_size = v;
        self
    }

    /// Set the authentication cache entry TTL
    pub fn cache_ttl(mut self, v: Duration) -> Self {
        self.settings.cache_ttl = v;
        self
    }
}

impl IcmpSettingsBuilder {
    fn new() -> Self {
        Self {
            settings: IcmpSettings {
                interface_name: Default::default(),
                request_timeout: IcmpSettings::default_request_timeout(),
                recv_message_queue_capacity: IcmpSettings::default_message_queue_capacity(),
            },
        }
    }

    /// Set the interface name to bind the socket to
    pub fn interface_name<S: ToString>(mut self, v: S) -> Self {
        self.settings.interface_name = v.to_string();
        self
    }

    /// Set the ICMP request timeout
    pub fn request_timeout(mut self, v: Duration) -> Self {
        self.settings.request_timeout = v;
        self
    }

    /// Set the capacity of the ICMP multiplexer received messages queue
    pub fn recv_message_queue_capacity(mut self, v: usize) -> Self {
        self.settings.recv_message_queue_capacity = v;
        self
    }

    /// Finalize [`IcmpSettings`]
    pub fn build(self) -> Result<IcmpSettings> {
        Ok(self.settings)
    }
}

impl Default for ForwardProtocolSettings {
    fn default() -> Self {
        ForwardProtocolSettings::Direct(DirectForwarderSettings {})
    }
}

fn validate_file_path(path: &str) -> io::Result<()> {
    // @fixme: replace with `Path::try_exists` when it becomes stable
    match std::fs::metadata(Path::new(path))? {
        m if m.is_file() => Ok(()),
        _ => Err(io::Error::new(ErrorKind::Other, "Not a file"))
    }
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
    where
        D: serde::de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "an unsigned integer")
        }

        fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E> where E: serde::de::Error {
            Ok(v)
        }
    }

    let path = deserializer.deserialize_u64(Visitor)?;
    Ok(Duration::from_secs(path))
}

fn deserialize_protocols<'de, D>(deserializer: D) -> std::result::Result<Vec<ListenProtocolSettings>, D::Error>
    where
        D: serde::de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<ListenProtocolSettings>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "a non-empty list of protocol settings")
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
        {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(x) = seq.next_element()? {
                out.push(x);
            }

            if !out.is_empty() {
                Ok(out)
            } else {
                Err(serde::de::Error::invalid_length(0, &Visitor {}))
            }
        }
    }

    deserializer.deserialize_seq(Visitor)
}

fn deserialize_file_path<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
    where
        D: serde::de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = String;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "a path to an existent accessible file")
        }

        fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E> where E: serde::de::Error {
            validate_file_path(v)
                .map(|_| v.to_string())
                .map_err(|e| E::invalid_value(
                    serde::de::Unexpected::Other(&format!("path={} error={}", v, e)),
                    &Visitor {}
                ))
        }
    }

    deserializer.deserialize_str(Visitor)
}

fn deserialize_authenticator<'de, D>(deserializer: D) -> std::result::Result<Arc<dyn Authenticator>, D::Error>
    where
        D: serde::de::Deserializer<'de>,
{
    match AuthenticatorSettings::deserialize(deserializer)? {
        AuthenticatorSettings::File(x) => Ok(Arc::new(
            FileBasedAuthenticator::new(&x.path)
                .map_err(|e| serde::de::Error::invalid_value(
                    serde::de::Unexpected::Other(&format!("authenticator initialization error: {}", e)),
                    &"a file with valid authentication info"
                ))?
        )),
        AuthenticatorSettings::Radius(x) => Ok(Arc::new(RadiusAuthenticator::new(x))),
    }
}
