use std::io;
use std::sync::Arc;
use crate::{datagram_pipe, downstream, forwarder, log_utils};
use crate::forwarder::Forwarder;
use crate::net_utils::TcpDestination;
use crate::settings::Settings;
use crate::tcp_forwarder::TcpForwarder;
use crate::udp_forwarder::UdpForwarder;


pub(crate) struct DirectForwarder {
    tcp_forwarder: TcpForwarder,
    udp_forwarder: UdpForwarder,
}

impl DirectForwarder {
    pub fn new(
        core_settings: Arc<Settings>,
    ) -> Self {
        Self {
            tcp_forwarder: TcpForwarder::new(core_settings.clone()),
            udp_forwarder: UdpForwarder::new(core_settings),
        }
    }
}

impl Forwarder for DirectForwarder {
    fn tcp_connector(
        &mut self, id: log_utils::IdChain<u64>, destination: TcpDestination
    ) -> io::Result<Box<dyn forwarder::TcpConnector>> {
        self.tcp_forwarder.connect_tcp(id, destination)
    }

    fn make_udp_datagram_multiplexer(
        &mut self, id: log_utils::IdChain<u64>
    ) -> io::Result<(
        Arc<dyn forwarder::UdpDatagramPipeShared>,
        Box<dyn datagram_pipe::Source<Output = forwarder::UdpDatagramReadStatus>>,
        Box<dyn datagram_pipe::Sink<Input = downstream::UdpDatagram>>,
    )> {
        self.udp_forwarder.make_multiplexer(id)
    }
}
