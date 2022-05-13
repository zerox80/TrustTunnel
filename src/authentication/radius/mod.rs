mod eap;
mod ms_chap_v2;
mod radius_utils;


use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use bytes::Bytes;
use cached::{Cached, TimedSizedCache};
use radius::client::Client;
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::core::rfc2869;
use tokio::sync::watch;
use crate::{authentication, log_id, log_utils};
use crate::authentication::Authenticator;
use crate::settings::RadiusAuthenticatorSettings;


pub(crate) struct RadiusAuthenticator {
    settings: Arc<RadiusAuthenticatorSettings>,
    state: Arc<Mutex<State>>,
}

pub(crate) struct State {
    sessions: HashMap<SessionKey, Session>,
    cache: TimedSizedCache<SessionKey, authentication::Status>,
    auth_id: eap::Identifier,
}

#[derive(Clone)]
struct SessionKey(authentication::Source<'static>);

struct Session {
    waiters_tx: watch::Sender<Result<authentication::Status, AuthenticationError>>,
}

#[derive(Clone)]
enum AuthenticationError {
    RadiusExchange(radius_utils::ExchangeError),
    EapDecode(eap::DecodeError),
    MsChapV2Decode(ms_chap_v2::DecodeError),
    Other(String),
}

impl Display for AuthenticationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticationError::RadiusExchange(x) => write!(f, "{}", x),
            AuthenticationError::EapDecode(x) => write!(f, "{}", x),
            AuthenticationError::MsChapV2Decode(x) => write!(f, "{}", x),
            AuthenticationError::Other(x) => write!(f, "{}", x),
        }
    }
}


impl RadiusAuthenticator {
    pub fn new(settings: RadiusAuthenticatorSettings) -> Self {
        let cache = TimedSizedCache::with_size_and_lifespan(
            settings.cache_size,
            settings.cache_ttl.as_secs(),
        );
        Self {
            settings: Arc::new(settings),
            state: Arc::new(Mutex::new(State {
                sessions: Default::default(),
                cache,
                auth_id: 0,
            })),
        }
    }
}

#[async_trait]
impl Authenticator for RadiusAuthenticator {
    async fn authenticate(
        &self,
        source: authentication::Source<'_>,
        log_id: &log_utils::IdChain<u64>,
    ) -> authentication::Status {
        let key = SessionKey(source.clone().into_owned());
        if let Some(status) = self.state.lock().unwrap().cache.cache_get(&key) {
            log_id!(trace, log_id, "Cache hit");
            return *status;
        }

        let mut wait = match self.state.lock().unwrap().sessions.entry(key.clone()) {
            Entry::Occupied(e) => {
                log_id!(trace, log_id, "Same authentication is already in progress, waiting for its result");
                e.get().waiters_tx.subscribe()
            },
            Entry::Vacant(e) => {
                let (tx, rx) = watch::channel(Ok(authentication::Status::Reject));
                e.insert(Session {
                    waiters_tx: tx,
                });

                tokio::spawn({
                    let settings = self.settings.clone();
                    let state = self.state.clone();
                    let source = source.clone().into_owned();
                    let log_id = log_id.clone();
                    async move {
                        let user_name =
                            match &source {
                                authentication::Source::Sni(x) => x,
                                authentication::Source::ProxyBasic(_) => todo!(),
                            };
                        let password = todo!();

                        let status = Session::authenticate(
                            &settings,
                            user_name.as_ref(),
                            password,
                            {
                                let mut state = state.lock().unwrap();
                                let x = state.auth_id;
                                state.auth_id += 1;
                                x
                            },
                            &log_id,
                        ).await;
                        state.lock().unwrap().sessions
                            .get(&SessionKey(source))
                            .map(|s| s.waiters_tx.send(status));
                    }
                });

                rx
            }
        };

        let status = match tokio::time::timeout(self.settings.timeout, wait.changed()).await
            .map_err(|e| AuthenticationError::Other(e.to_string()))
            .and_then(|x| x
                .map(|_| wait.borrow().clone())
                .map_err(|e| AuthenticationError::Other(e.to_string()))?
            )
        {
            Ok(x) => x,
            Err(e) => {
                log_id!(debug, log_id, "Failed to authenticate {:?} due to error: {}", source, e);
                authentication::Status::Reject
            }
        };

        drop(wait);

        let mut state = self.state.lock().unwrap();
        if let Entry::Occupied(e) = state.sessions.entry(key.clone()) {
            if e.get().waiters_tx.receiver_count() == 0 {
                e.remove();
            }
        }

        state.cache.cache_set(key, status);

        status
    }
}

impl Eq for SessionKey {}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (authentication::Source::Sni(a), authentication::Source::Sni(b)) => a == b,
            (authentication::Source::ProxyBasic(a), authentication::Source::ProxyBasic(b)) => a == b,
            _ => false,
        }
    }
}

impl Hash for SessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            authentication::Source::Sni(x) => x.hash(state),
            authentication::Source::ProxyBasic(x) => x.hash(state),
        }
    }
}

impl Session {
    async fn exchange_radius(
        client: &Client, server_address: &SocketAddr, request: &Packet, log_id: &log_utils::IdChain<u64>,
    ) -> Result<Packet, AuthenticationError> {
        log_id!(trace, log_id, "Sending radius request: {:?}", request);
        let reply = radius_utils::exchange(&client, server_address, &request).await
            .map_err(AuthenticationError::RadiusExchange)?;
        log_id!(trace, log_id, "Radius reply: {:?}", reply);
        Ok(reply)
    }

    fn get_eap_message(packet: &Packet) -> Option<Result<eap::Message, AuthenticationError>> {
        packet.lookup(rfc2869::EAP_MESSAGE_TYPE)
            .map(|x| eap::Message::decode(Bytes::from(x.encode_bytes()))
                .map_err(AuthenticationError::EapDecode))
    }

    async fn exchange_challenge_phase(
        client: &Client, server_address: &SocketAddr, request: &Packet, log_id: &log_utils::IdChain<u64>,
    ) -> Result<eap::Message, AuthenticationError> {
        let reply = Self::exchange_radius(&client, server_address, &request, log_id).await?;
        if reply.get_code() != Code::AccessChallenge {
            return Err(AuthenticationError::Other(
                format!("Unexpected RADIUS reply code: request={:?}, reply={:?}", request, reply)
            ));
        }

        let eap = Self::get_eap_message(&reply)
            .ok_or_else(|| AuthenticationError::Other("Server RADIUS challenge lacks EAP attribute".to_string()))??;
        if eap.code() != eap::CODE_REQUEST {
            return Err(AuthenticationError::Other(format!("Unexpected EAP message code: {}", eap)));
        }

        if !radius_utils::verify_message_authenticator(request, &reply) {
            return Err(AuthenticationError::Other("Message-Authenticator field validation failed".to_string()));
        }

        Ok(eap)
    }

    async fn authenticate(
        settings: &RadiusAuthenticatorSettings,
        user_name: &str,
        password: &str,
        auth_id: eap::Identifier,
        log_id: &log_utils::IdChain<u64>,
    ) -> Result<authentication::Status, AuthenticationError> {
        let client = Client::new(None, None);

        log_id!(trace, log_id, "Sending EAP Identity to initiate procedure");
        let eap_request = Self::exchange_challenge_phase(
            &client,
            &settings.server_address,
            &radius_utils::wrap_eap_message(
                Code::AccessRequest,
                settings.secret.as_bytes(),
                &user_name,
                &eap::encode_response(auth_id, eap::TYPE_IDENTITY, b"hello"),
            ),
            log_id,
        ).await?;

        let ms_chap_challenge = match &eap_request.payload {
            eap::Payload::Request(eap::TYPE_MS_AUTH, d) =>
                match ms_chap_v2::decode_message(eap::CODE_REQUEST, d.clone())
                    .map_err(AuthenticationError::MsChapV2Decode)?
                {
                    ms_chap_v2::Message::Challenge(x) => x,
                    _ => return Err(AuthenticationError::Other(format!("Unexpected MS-CHAP message: {}", eap_request))),
                }
            _ => return Err(AuthenticationError::Other(format!("Unexpected EAP message payload type: {}", eap_request))),
        };
        log_id!(trace, log_id, "Received MS-CHAPv2 challenge");

        log_id!(trace, log_id, "Sending MS-CHAPv2 response packet for authentication");
        let ms_chap_response = ms_chap_challenge.generate_response(&user_name, password);
        let eap_request = Self::exchange_challenge_phase(
            &client,
            &settings.server_address,
            &radius_utils::wrap_eap_message(
                Code::AccessRequest,
                settings.secret.as_bytes(),
                &user_name,
                &eap::encode_response(eap_request.identifier, eap::TYPE_MS_AUTH, &ms_chap_response.encode()),
            ),
            log_id,
        ).await?;

        let ms_chap_success_request = match &eap_request.payload {
            eap::Payload::Request(eap::TYPE_MS_AUTH, d) =>
                match ms_chap_v2::decode_message(eap::CODE_REQUEST, d.clone())
                    .map_err(AuthenticationError::MsChapV2Decode)?
                {
                    ms_chap_v2::Message::SuccessRequest(x) => x,
                    _ => return Err(AuthenticationError::Other(format!("Unexpected MS-CHAP message: {}", eap_request))),
                }
            _ => return Err(AuthenticationError::Other(format!("Unexpected EAP message payload type: {}", eap_request))),
        };
        log_id!(trace, log_id, "Received MS-CHAPv2 success request");

        if !ms_chap_v2::check_authenticator_response(
            password,
            &ms_chap_response.nt_response,
            &ms_chap_response.peer_challenge,
            &ms_chap_challenge.challenge,
            &user_name,
            &ms_chap_success_request.auth_string,
        ) {
            return Err(AuthenticationError::Other(format!("MS-CHAP authenticator response validation failed: {}", eap_request)));
        }

        log_id!(trace, log_id, "Sending MS-CHAPv2 success response packet finalizing authentication");
        let radius_reply = Self::exchange_radius(
            &client,
            &settings.server_address,
            &radius_utils::wrap_eap_message(
                Code::AccessRequest,
                settings.secret.as_bytes(),
                &user_name,
                &eap::encode_response(
                    eap_request.identifier,
                    eap::TYPE_MS_AUTH,
                    &ms_chap_v2::SuccessResponse::encode(),
                ),
            ),
            log_id,
        ).await?;

        if radius_reply.get_code() != Code::AccessAccept {
            log_id!(debug, log_id, "Unexpected RADIUS reply code after challenge: {:?}", radius_reply.get_code());
            return Ok(authentication::Status::Reject);
        }

        Ok(match Self::get_eap_message(&radius_reply) {
            None => {
                log_id!(debug, log_id, "Server RADIUS accept lacks EAP attribute");
                authentication::Status::Reject
            }
            Some(Err(e)) => {
                log_id!(debug, log_id, "Failed decoding RADIUS accept payload: {}", e);
                authentication::Status::Reject
            }
            Some(Ok(eap)) if eap.code() != eap::CODE_SUCCESS => {
                log_id!(debug, log_id, "EAP message code is not Success: {}", eap);
                authentication::Status::Reject
            }
            Some(_) => {
                log_id!(debug, log_id, "Successfully authenticated");
                authentication::Status::Pass
            }
        })
    }
}
