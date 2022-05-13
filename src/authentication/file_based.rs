use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, ErrorKind};
use async_trait::async_trait;
use crypto::digest::Digest;
use crate::{authentication, log_utils};
use crate::authentication::Authenticator;


/// The [`Authenticator`] implementation which reads the authentication info from a file.
/// The file must contain an application id (`applicationId: <string>`),
/// token (`token: <string>`), and credentials (`credentials: <string>`).
/// Each one must be on a new line. The order does not matter.
///
/// *Please note*, that this is a very simple authenticator implementation which is intended mostly
/// for testing purposes and does not respect network security practices.
pub struct FileBasedAuthenticator {
    sni_auth: String,
    proxy_auth: String,
}

impl FileBasedAuthenticator {
    pub fn new(path: &str) -> io::Result<Self> {
        const AUTH_APP_ID_PREFIX: &str = "applicationId:";
        const AUTH_TOKEN_PREFIX: &str = "token:";
        const AUTH_CREDENTIALS_PREFIX: &str = "credentials:";

        let mut reader = BufReader::new(File::open(path)?);

        let mut app_id = None;
        let mut token = None;
        let mut creds = None;

        let mut line = String::with_capacity(512);
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break; // EOF
            }

            let line = line.trim_start();

            if let Some(str) = line.strip_prefix(AUTH_APP_ID_PREFIX).map(|s| s.trim()) {
                if app_id.replace(str.to_string()).is_some() {
                    return Err(io::Error::new(ErrorKind::Other, "Duplicated application ID"));
                }
            } else if let Some(str) = line.strip_prefix(AUTH_TOKEN_PREFIX).map(|s| s.trim()) {
                if token.replace(str.to_string()).is_some() {
                    return Err(io::Error::new(ErrorKind::Other, "Duplicated token"));
                }
            } else if let Some(str) = line.strip_prefix(AUTH_CREDENTIALS_PREFIX).map(|s| s.trim()) {
                if creds.replace(str.to_string()).is_some() {
                    return Err(io::Error::new(ErrorKind::Other, "Duplicated credentials"));
                }
            }
        }

        let (app_id, token, creds) = match (app_id, token, creds) {
            (None, _, _) => return Err(io::Error::new(ErrorKind::Other, "Application ID not found")),
            (_, None, _) => return Err(io::Error::new(ErrorKind::Other, "Token not found")),
            (_, _, None) => return Err(io::Error::new(ErrorKind::Other, "Credentials not found")),
            (Some(a), Some(t), Some(c)) => (a, t, c),
        };

        Ok(Self {
            sni_auth: {
                let mut hash = crypto::md5::Md5::new();
                hash.input(app_id.as_bytes());
                hash.input(&[b':']);
                hash.input(token.as_bytes());
                hash.input(&[b':']);
                hash.input(creds.as_bytes());
                hash.result_str()
            },
            proxy_auth: base64::encode(format!("{}:{}", token, creds)),
        })
    }
}

#[async_trait]
impl Authenticator for FileBasedAuthenticator {
    async fn authenticate(
        &self, source: authentication::Source<'_>, _log_id: &log_utils::IdChain<u64>,
    ) -> authentication::Status {
        match source {
            authentication::Source::Sni(str) if str == self.sni_auth => authentication::Status::Pass,
            authentication::Source::ProxyBasic(str) if str == self.proxy_auth => authentication::Status::Pass,
            _ => authentication::Status::Reject,
        }
    }
}
