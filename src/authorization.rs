use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, ErrorKind};
use async_trait::async_trait;


/// Authorization request source
#[derive(Debug)]
pub enum Source<'this> {
    /// A client tries to authorize using SNI
    Sni(Cow<'this, str>),
    /// A client tries to authorize using
    /// [the basic authentication scheme](https://datatracker.ietf.org/doc/html/rfc7617)
    ProxyBasic(Cow<'this, str>),
}

/// Authorization procedure status
pub enum Status {
    /// Success
    Pass,
    /// Failure
    Reject,
}

/// The authorizer abstract interface
#[async_trait]
pub trait Authorizer: Send + Sync {
    /// Authorize client
    async fn authorize(&self, source: Source<'_>) -> Status;
}

/// The [`Authorizer`] implementation which authorizes any request
pub struct DummyAuthorizer {}

#[async_trait]
impl Authorizer for DummyAuthorizer {
    async fn authorize(&self, _source: Source<'_>) -> Status {
        Status::Pass
    }
}

/// The [`Authorizer`] implementation which reads the authorization info from a file.
/// The file must contain an application id (`applicationId: <string>`),
/// token (`token: <string>`), and credentials (`credentials: <string>`).
/// Each one must be on a new line. The order does not matter.
pub struct FileBasedAuthorizer {
    sni_auth: String,
    proxy_auth: String,
}

impl FileBasedAuthorizer {
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
            sni_auth: format!("{:x}", md5::compute(format!("{}:{}:{}", app_id, token, creds))),
            proxy_auth: base64::encode(format!("{}:{}", token, creds)),
        })
    }
}

#[async_trait]
impl Authorizer for FileBasedAuthorizer {
    async fn authorize(&self, source: Source<'_>) -> Status {
        match source {
            Source::Sni(str) if str == self.sni_auth => Status::Pass,
            Source::ProxyBasic(str) if str == self.proxy_auth => Status::Pass,
            _ => Status::Reject,
        }
    }
}

impl<'a> ToOwned for Source<'a> {
    type Owned = Source<'a>;

    fn to_owned(&self) -> Self::Owned {
        match self {
            Source::Sni(x) => Source::Sni(x.to_owned()),
            Source::ProxyBasic(x) => Source::ProxyBasic(x.to_owned()),
        }
    }
}
