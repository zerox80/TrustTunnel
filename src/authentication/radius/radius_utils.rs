//! 'Remote Authentication Dial In User Service'-related staff
//! https://datatracker.ietf.org/doc/html/rfc2865
//! https://datatracker.ietf.org/doc/html/rfc2869
//! https://datatracker.ietf.org/doc/html/rfc3579


use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::md5::Md5;
use radius::client::Client;
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::core::{rfc2865, rfc2869};


#[derive(Clone)]
pub(crate) enum ExchangeError {
    /// Underlying RADIUS client error
    Client(String),
    /// Identifier of the received RADIUS reply mismatches the request's one
    IdMissmatch(u8, u8),
    /// The Authenticator field validation failed
    InvalidAuthenticator,
}

impl Display for ExchangeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RADIUS exchange error: ")?;
        match self {
            ExchangeError::Client(e) =>
                write!(f, "Underlying client error: {:?}", e),
            ExchangeError::IdMissmatch(request, reply) =>
                write!(f, "Unexpected reply id: {} (expected={})", reply, request),
            ExchangeError::InvalidAuthenticator =>
                write!(f, "Authenticator field validation failed"),
        }
    }
}


// https://datatracker.ietf.org/doc/html/rfc2865#section-3
const CODE_SIZE: usize = 1;
const IDENTIFIER_SIZE: usize = 1;
const LENGTH_SIZE: usize = 2;
const AUTHENTICATOR_SIZE: usize = 16;
const AUTHENTICATOR_OFFSET: usize = CODE_SIZE + IDENTIFIER_SIZE + LENGTH_SIZE;


/// https://datatracker.ietf.org/doc/html/rfc2865#section-3
///
/// The value of the Authenticator field in Access-Accept, Access-
/// Reject, and Access-Challenge packets is called the Response
/// Authenticator, and contains a one-way MD5 hash calculated over
/// a stream of octets consisting of: the RADIUS packet, beginning
/// with the Code field, including the Identifier, the Length, the
/// Request Authenticator field from the Access-Request packet, and
/// the response Attributes, followed by the shared secret.  That
/// is, ResponseAuth =
/// MD5(Code+ID+Length+RequestAuth+Attributes+Secret) where +
/// denotes concatenation.
fn verify_reply(request: &Packet, reply: &Packet) -> bool {
    let encoded = reply.encode().unwrap();

    let mut hasher = Md5::new();
    hasher.input(&encoded[..CODE_SIZE + IDENTIFIER_SIZE + LENGTH_SIZE]);
    hasher.input(request.get_authenticator());
    hasher.input(&encoded[CODE_SIZE + IDENTIFIER_SIZE + LENGTH_SIZE + AUTHENTICATOR_SIZE..]);
    hasher.input(request.get_secret());

    let mut hash = [0; AUTHENTICATOR_SIZE];
    hasher.result(&mut hash);

    reply.get_authenticator() == &hash
}

/// https://datatracker.ietf.org/doc/html/rfc3579#section-3.2
///
/// For Access-Challenge, Access-Accept, and Access-Reject packets,
/// the Message-Authenticator is calculated as follows, using the
/// Request-Authenticator from the Access-Request this packet is in
/// reply to:
///
///     Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
///     Request Authenticator, Attributes)
///
/// When the message integrity check is calculated the signature
/// string should be considered to be sixteen octets of zero.  The
/// shared secret is used as the key for the HMAC-MD5 message
/// integrity check.  The Message-Authenticator is calculated and
/// inserted in the packet before the Response Authenticator is
/// calculated.
pub(crate) fn verify_message_authenticator(request: &Packet, reply: &Packet) -> bool {
    reply.lookup(rfc2869::MESSAGE_AUTHENTICATOR_TYPE)
        .map_or(false, |x| {
            let mut reply = reply.clone();
            rfc2869::delete_message_authenticator(&mut reply);
            rfc2869::add_message_authenticator(&mut reply, &[0; 16]);

            let mut encoded_reply = reply.encode().unwrap();
            encoded_reply.splice(
                AUTHENTICATOR_OFFSET..AUTHENTICATOR_OFFSET + AUTHENTICATOR_SIZE,
                request.get_authenticator().into_iter().cloned()
            );

            let mut hash = Hmac::new(Md5::new(), request.get_secret());
            hash.input(&encoded_reply);

            x.encode_bytes() == hash.result().code()
        })
}

/// https://datatracker.ietf.org/doc/html/rfc3579#section-3.2
///
/// When present in an Access-Request packet, Message-Authenticator is
/// an HMAC-MD5 [RFC2104] hash of the entire Access-Request packet,
/// including Type, ID, Length and Authenticator, using the shared
/// secret as the key, as follows.
///
///     Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
///     Request Authenticator, Attributes)
///
/// When the message integrity check is calculated the signature
/// string should be considered to be sixteen octets of zero.
fn set_message_authenticator(packet: &mut Packet) {
    rfc2869::add_message_authenticator(packet, &[0; 16]);

    let mut hash = Hmac::new(Md5::new(), packet.get_secret());
    hash.input(&packet.encode().unwrap());

    rfc2869::delete_message_authenticator(packet);
    rfc2869::add_message_authenticator(packet, hash.result().code());
}

pub(crate) fn wrap_eap_message(
    code: Code, secret: &[u8], user_name: &str, payload: &[u8],
) -> Packet {
    let mut packet = Packet::new(code, &secret.to_vec());

    rfc2865::add_user_name(&mut packet, &user_name);
    rfc2869::add_eap_message(&mut packet, &payload);
    set_message_authenticator(&mut packet);

    packet
}

pub(crate) async fn exchange(
    client: &Client, server_addr: &SocketAddr, request: &Packet,
) -> Result<Packet, ExchangeError> {
    let reply = client.send_packet(server_addr, &request).await
        .map_err(|e| ExchangeError::Client(format!("{:?}", e)))?;
    debug!("Received reply: {:?}", reply);

    if request.get_identifier() != reply.get_identifier() {
        return Err(ExchangeError::IdMissmatch(request.get_identifier(), reply.get_identifier()));
    }

    if !verify_reply(request, &reply) {
        return Err(ExchangeError::InvalidAuthenticator);
    }

    Ok(reply)
}
