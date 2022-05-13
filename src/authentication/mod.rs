pub mod file_based;
pub mod radius;


use std::borrow::Cow;
use async_trait::async_trait;
use crate::log_utils;


/// Authentication request source
#[derive(Debug, Clone)]
pub enum Source<'this> {
    /// A client tries to authenticate using SNI
    Sni(Cow<'this, str>),
    /// A client tries to authenticate using
    /// [the basic authentication scheme](https://datatracker.ietf.org/doc/html/rfc7617)
    ProxyBasic(Cow<'this, str>),
}

/// Authentication procedure status
#[derive(Copy, Clone, PartialEq)]
pub enum Status {
    /// Success
    Pass,
    /// Failure
    Reject,
}

/// The authenticator abstract interface
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Authenticate client
    async fn authenticate(&self, source: Source<'_>, log_id: &log_utils::IdChain<u64>) -> Status;
}

/// The [`Authenticator`] implementation which authenticates any request
pub struct DummyAuthenticator {}

#[async_trait]
impl Authenticator for DummyAuthenticator {
    async fn authenticate(&self, _source: Source<'_>, _log_id: &log_utils::IdChain<u64>) -> Status {
        Status::Pass
    }
}

impl<'a> Source<'a> {
    pub fn into_owned(self) -> Source<'static> {
        match self {
            Source::Sni(x) => Source::Sni(Cow::Owned(x.into_owned())),
            Source::ProxyBasic(x) => Source::ProxyBasic(Cow::Owned(x.into_owned())),
        }
    }
}
