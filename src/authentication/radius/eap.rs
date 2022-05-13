//! 'Extensible Authentication Protocol'-related staff
//! https://www.rfc-editor.org/rfc/rfc3748.html


use std::fmt::{Display, Formatter};
use bytes::{Buf, Bytes};
use crate::utils;


pub(crate) type Identifier = u8;

pub(crate) type Code = u8;
// https://www.rfc-editor.org/rfc/rfc3748.html#section-4
pub(crate) const CODE_REQUEST: Code = 1;
pub(crate) const CODE_RESPONSE: Code = 2;
pub(crate) const CODE_SUCCESS: Code = 3;
pub(crate) const CODE_FAILURE: Code = 4;

pub(crate) type Type = u8;
// https://www.rfc-editor.org/rfc/rfc3748.html#section-5
pub(crate) const TYPE_IDENTITY: Type = 1;
// https://datatracker.ietf.org/doc/html/draft-kamath-pppext-eap-mschapv2-02#section-2.1
pub(crate) const TYPE_MS_AUTH: Type = 26;

// https://www.rfc-editor.org/rfc/rfc3748.html#section-4
const CODE_SIZE: usize = 1;
const IDENTIFIER_SIZE: usize = 1;
const LENGTH_SIZE: usize = 2;
const TYPE_SIZE: usize = 1;
const MIN_MESSAGE_SIZE: usize = CODE_SIZE + IDENTIFIER_SIZE + LENGTH_SIZE;


#[derive(Clone)]
pub(crate) struct DecodeError(String);

/// https://www.rfc-editor.org/rfc/rfc3748.html
pub(crate) struct Message {
    /// The Identifier field is one octet and aids in matching Responses with Requests
    pub identifier: Identifier,
    pub payload: Payload,
}

pub(crate) enum Payload {
    /// https://www.rfc-editor.org/rfc/rfc3748.html#section-4.1
    Request(Type, Bytes),
    /// https://www.rfc-editor.org/rfc/rfc3748.html#section-4.1
    Response(Type, Bytes),
    /// https://www.rfc-editor.org/rfc/rfc3748.html#section-4.2
    Success,
    /// https://www.rfc-editor.org/rfc/rfc3748.html#section-4.2
    Failure,
}


impl Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "EAP decode error: {}", self.0)
    }
}

impl Message {
    pub fn code(&self) -> Code {
        match self.payload {
            Payload::Request(_, _) => CODE_REQUEST,
            Payload::Response(_, _) => CODE_RESPONSE,
            Payload::Success => CODE_SUCCESS,
            Payload::Failure => CODE_FAILURE,
        }
    }

    pub fn decode(mut data: Bytes) -> Result<Self, DecodeError> {
        let orig_len = data.len();
        if orig_len < MIN_MESSAGE_SIZE {
            return Err(DecodeError(format!("Shorter than minimum packet size: {}", orig_len)));
        }

        let code = data.get_u8();
        let identifier = data.get_u8();
        let length = data.get_u16() as usize;
        if length < MIN_MESSAGE_SIZE {
            return Err(DecodeError(format!("Too small length value: {}", length)));
        }
        if orig_len < length {
            return Err(DecodeError(
                format!("Length of message exceeds buffer bounds: length={}, buffer={}", length, orig_len)
            ));
        }

        Ok(Self {
            identifier,
            payload: match code {
                CODE_REQUEST => Payload::Request(
                    data.get_u8(),
                    data.split_to(length - CODE_SIZE - IDENTIFIER_SIZE - LENGTH_SIZE - TYPE_SIZE),
                ),
                CODE_RESPONSE => Payload::Response(
                    data.get_u8(),
                    data.split_to(length - CODE_SIZE - IDENTIFIER_SIZE - LENGTH_SIZE - TYPE_SIZE),
                ),
                CODE_SUCCESS => Payload::Success,
                CODE_FAILURE => Payload::Failure,
                _ => return Err(DecodeError(format!("Unexpected message code: {}", code))),
            },
        })
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ identifier={}, payload={} }}", self.identifier, self.payload)
    }
}

impl Display for Payload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Payload::Request(t, d) => write!(f, "Request {{ type={}, data={} }}", t, utils::hex_dump(d)),
            Payload::Response(t, d) => write!(f, "Response {{ type={}, data={} }}", t, utils::hex_dump(d)),
            Payload::Success => write!(f, "Success"),
            Payload::Failure => write!(f, "Failure"),
        }
    }
}

pub(crate) fn encode_response(id: u8, typ: Type, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    let total_length = (CODE_SIZE + IDENTIFIER_SIZE + LENGTH_SIZE + TYPE_SIZE + payload.len()) as u16;

    out.push(CODE_RESPONSE);
    out.push(id);
    out.extend_from_slice(&total_length.to_be_bytes());
    out.push(typ);
    out.extend_from_slice(payload);

    out
}
