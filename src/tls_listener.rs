use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio_rustls::{LazyConfigAcceptor, StartHandshake};
use tokio_rustls::server::TlsStream;
use crate::{authentication, log_utils, utils};
use crate::settings::Settings;


pub(crate) struct TlsListener {
    core_settings: Arc<Settings>,
}

pub(crate) struct TlsAcceptor {
    inner: StartHandshake<TcpStream>,
    core_settings: Arc<Settings>,
}

impl TlsListener {
    pub fn new(
        core_settings: Arc<Settings>,
    ) -> Self {
        Self {
            core_settings,
        }
    }

    pub async fn listen(&self, stream: TcpStream) -> io::Result<TlsAcceptor> {
        LazyConfigAcceptor::new(rustls::server::Acceptor::new().unwrap(), stream)
            .await
            .map(|hs| TlsAcceptor {
                inner: hs,
                core_settings: self.core_settings.clone(),
            })
    }
}

impl TlsAcceptor {
    pub fn sni(&self) -> Option<String> {
        self.inner.client_hello().server_name().map(String::from)
    }

    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.inner.client_hello()
            .alpn()
            .and_then(|mut a| a.next())
            .map(Vec::from)
    }

    pub async fn accept(self, alpn: Vec<u8>, log_id: &log_utils::IdChain<u64>) -> io::Result<TlsStream<TcpStream>> {
        let settings = &self.core_settings;
        let tunnel_tls_info = &settings.tunnel_tls_host_info;
        let sm_tls_into = settings.service_messenger_tls_host_info.as_ref();

        let (cert_file, key_file) = match self.inner.client_hello().server_name() {
            Some(x) if x == tunnel_tls_info.hostname => (
                &tunnel_tls_info.cert_chain_path,
                &tunnel_tls_info.private_key_path,
            ),
            Some(x) if Some(x) == sm_tls_into.map(|info| info.hostname.as_str()) => (
                &sm_tls_into.unwrap().cert_chain_path,
                &sm_tls_into.unwrap().private_key_path,
            ),
            x => match x.and_then(|x| utils::scan_sni_authentication(x, &tunnel_tls_info.hostname)) {
                None => return Err(io::Error::new(
                    ErrorKind::Other, format!("Unexpected server name in client hello: {:?}", x)
                )),
                Some(source) => match settings.authenticator.authenticate(source, log_id).await {
                    authentication::Status::Pass => (
                        &tunnel_tls_info.cert_chain_path,
                        &tunnel_tls_info.private_key_path,
                    ),
                    authentication::Status::Reject => return Err(io::Error::new(
                        ErrorKind::Other, "SNI authentication failed"
                    )),
                }
            }
        };

        let tls_config = {
            let mut cfg = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(utils::load_certs(cert_file)?, utils::load_private_key(key_file)?)
                .map_err(|e| io::Error::new(
                    ErrorKind::Other, format!("Failed to create TLS configuration: {}", e))
                )?;

            cfg.alpn_protocols = vec![alpn];
            Arc::new(cfg)
        };

        self.inner.into_stream(tls_config).await
    }
}
