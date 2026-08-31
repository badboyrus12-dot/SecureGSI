//! SecureGSI fixed-size control IPC protocol v1.
//!
//! This module is deliberately pure Rust and allocation-free so the same parser
//! can be used by the locked AArch64 child, unit tests, cargo-fuzz, and Kani.
//! The v1 control plane carries no payload bytes. Future payload-bearing protocol
//! versions must define a new bounded format instead of relaxing these checks.

pub(crate) const MAGIC_0: u8 = b'S';
pub(crate) const MAGIC_1: u8 = b'G';
pub(crate) const PROTOCOL_VERSION: u8 = 1;
pub(crate) const PACKET_LEN: usize = 16;

pub(crate) const KIND_REQUEST: u8 = 0x01;
pub(crate) const KIND_RESPONSE: u8 = 0x02;

pub(crate) const OP_PING: u8 = 0x01;
pub(crate) const OP_STATUS: u8 = 0x02;
pub(crate) const OP_SHUTDOWN: u8 = 0x03;

pub(crate) const RESP_READY: u8 = 0x80;
pub(crate) const RESP_PONG: u8 = 0x81;
pub(crate) const RESP_LOCKED: u8 = 0x82;
pub(crate) const RESP_BYE: u8 = 0x83;
pub(crate) const RESP_ERROR: u8 = 0xff;

const FLAGS_NONE: u8 = 0;
const PAYLOAD_LEN_V1: u16 = 0;
const RESERVED_V1: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageKind {
    Request,
    Response,
}

impl MessageKind {
    const fn wire(self) -> u8 {
        match self {
            Self::Request => KIND_REQUEST,
            Self::Response => KIND_RESPONSE,
        }
    }

    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            KIND_REQUEST => Some(Self::Request),
            KIND_RESPONSE => Some(Self::Response),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Message {
    pub(crate) kind: MessageKind,
    pub(crate) opcode: u8,
    pub(crate) request_id: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParseError {
    InvalidPacketLength,
    BadMagic,
    UnsupportedVersion,
    InvalidKind,
    InvalidOpcode,
    NonZeroFlags,
    InvalidPayloadLength,
    InvalidRequestId,
    NonZeroReserved,
}

pub(crate) const fn is_request_opcode(opcode: u8) -> bool {
    matches!(opcode, OP_PING | OP_STATUS | OP_SHUTDOWN)
}

pub(crate) const fn is_response_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        RESP_READY | RESP_PONG | RESP_LOCKED | RESP_BYE | RESP_ERROR
    )
}

const fn request_id_valid(kind: MessageKind, opcode: u8, request_id: u32) -> bool {
    match kind {
        MessageKind::Request => request_id != 0,
        MessageKind::Response => match opcode {
            RESP_READY => request_id == 0,
            RESP_PONG | RESP_LOCKED | RESP_BYE => request_id != 0,
            RESP_ERROR => true,
            _ => false,
        },
    }
}

fn encode(kind: MessageKind, opcode: u8, request_id: u32) -> Option<[u8; PACKET_LEN]> {
    let opcode_valid = match kind {
        MessageKind::Request => is_request_opcode(opcode),
        MessageKind::Response => is_response_opcode(opcode),
    };

    if !opcode_valid || !request_id_valid(kind, opcode, request_id) {
        return None;
    }

    let request_id = request_id.to_le_bytes();
    let payload_len = PAYLOAD_LEN_V1.to_le_bytes();
    let reserved = RESERVED_V1.to_le_bytes();

    Some([
        MAGIC_0,
        MAGIC_1,
        PROTOCOL_VERSION,
        kind.wire(),
        opcode,
        FLAGS_NONE,
        payload_len[0],
        payload_len[1],
        request_id[0],
        request_id[1],
        request_id[2],
        request_id[3],
        reserved[0],
        reserved[1],
        reserved[2],
        reserved[3],
    ])
}

pub(crate) fn encode_request(opcode: u8, request_id: u32) -> Option<[u8; PACKET_LEN]> {
    encode(MessageKind::Request, opcode, request_id)
}

#[cfg_attr(
    all(not(target_arch = "aarch64"), not(test)),
    expect(
        dead_code,
        reason = "response encoding is used by the locked AArch64 child and protocol tests"
    )
)]
pub(crate) fn encode_response(opcode: u8, request_id: u32) -> Option<[u8; PACKET_LEN]> {
    encode(MessageKind::Response, opcode, request_id)
}

pub(crate) fn parse(bytes: &[u8; PACKET_LEN]) -> Result<Message, ParseError> {
    parse_slice(bytes)
}

pub(crate) fn parse_slice(bytes: &[u8]) -> Result<Message, ParseError> {
    if bytes.len() != PACKET_LEN {
        return Err(ParseError::InvalidPacketLength);
    }

    if bytes[0] != MAGIC_0 || bytes[1] != MAGIC_1 {
        return Err(ParseError::BadMagic);
    }

    if bytes[2] != PROTOCOL_VERSION {
        return Err(ParseError::UnsupportedVersion);
    }

    let kind = MessageKind::from_wire(bytes[3]).ok_or(ParseError::InvalidKind)?;
    let opcode = bytes[4];

    let opcode_valid = match kind {
        MessageKind::Request => is_request_opcode(opcode),
        MessageKind::Response => is_response_opcode(opcode),
    };

    if !opcode_valid {
        return Err(ParseError::InvalidOpcode);
    }

    if bytes[5] != FLAGS_NONE {
        return Err(ParseError::NonZeroFlags);
    }

    let payload_len = u16::from_le_bytes([bytes[6], bytes[7]]);
    if payload_len != PAYLOAD_LEN_V1 {
        return Err(ParseError::InvalidPayloadLength);
    }

    let request_id = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if !request_id_valid(kind, opcode, request_id) {
        return Err(ParseError::InvalidRequestId);
    }

    let reserved = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    if reserved != RESERVED_V1 {
        return Err(ParseError::NonZeroReserved);
    }

    Ok(Message {
        kind,
        opcode,
        request_id,
    })
}

pub(crate) const fn matches_response(
    message: Message,
    expected_opcode: u8,
    expected_request_id: u32,
) -> bool {
    matches!(message.kind, MessageKind::Response)
        && message.opcode == expected_opcode
        && message.request_id == expected_request_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let bytes = encode_request(OP_PING, 7).expect("valid request");
        let parsed = parse(&bytes).expect("parse request");

        assert_eq!(parsed.kind, MessageKind::Request);
        assert_eq!(parsed.opcode, OP_PING);
        assert_eq!(parsed.request_id, 7);
    }

    #[test]
    fn response_round_trip() {
        let bytes = encode_response(RESP_PONG, 99).expect("valid response");
        let parsed = parse(&bytes).expect("parse response");

        assert_eq!(parsed.kind, MessageKind::Response);
        assert_eq!(parsed.opcode, RESP_PONG);
        assert_eq!(parsed.request_id, 99);
    }

    #[test]
    fn ready_requires_zero_request_id() {
        assert!(encode_response(RESP_READY, 0).is_some());
        assert!(encode_response(RESP_READY, 1).is_none());
    }

    #[test]
    fn request_requires_nonzero_request_id() {
        assert!(encode_request(OP_STATUS, 0).is_none());
    }

    #[test]
    fn wrong_packet_length_is_rejected() {
        assert_eq!(
            parse_slice(&[0_u8; PACKET_LEN - 1]),
            Err(ParseError::InvalidPacketLength)
        );
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = encode_request(OP_PING, 1).expect("valid request");
        bytes[0] ^= 0xff;

        assert_eq!(parse(&bytes), Err(ParseError::BadMagic));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = encode_request(OP_PING, 1).expect("valid request");
        bytes[2] = PROTOCOL_VERSION.wrapping_add(1);

        assert_eq!(parse(&bytes), Err(ParseError::UnsupportedVersion));
    }

    #[test]
    fn invalid_kind_is_rejected() {
        let mut bytes = encode_request(OP_PING, 1).expect("valid request");
        bytes[3] = 0xff;

        assert_eq!(parse(&bytes), Err(ParseError::InvalidKind));
    }

    #[test]
    fn unknown_opcode_is_rejected() {
        let mut bytes = encode_request(OP_PING, 1).expect("valid request");
        bytes[4] = 0x7f;

        assert_eq!(parse(&bytes), Err(ParseError::InvalidOpcode));
    }

    #[test]
    fn nonzero_flags_are_rejected() {
        let mut bytes = encode_request(OP_PING, 1).expect("valid request");
        bytes[5] = 1;

        assert_eq!(parse(&bytes), Err(ParseError::NonZeroFlags));
    }

    #[test]
    fn payload_is_rejected_in_v1() {
        let mut bytes = encode_request(OP_PING, 1).expect("valid request");
        bytes[6] = 1;

        assert_eq!(parse(&bytes), Err(ParseError::InvalidPayloadLength));
    }

    #[test]
    fn reserved_bytes_are_rejected() {
        let mut bytes = encode_request(OP_PING, 1).expect("valid request");
        bytes[15] = 1;

        assert_eq!(parse(&bytes), Err(ParseError::NonZeroReserved));
    }

    #[test]
    fn response_opcode_cannot_be_used_as_request() {
        let mut bytes = encode_request(OP_PING, 1).expect("valid request");
        bytes[4] = RESP_PONG;

        assert_eq!(parse(&bytes), Err(ParseError::InvalidOpcode));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn accepted_packets_satisfy_v1_invariants() {
        let bytes: [u8; PACKET_LEN] = kani::any();

        if let Ok(message) = parse(&bytes) {
            assert_eq!(bytes[0], MAGIC_0);
            assert_eq!(bytes[1], MAGIC_1);
            assert_eq!(bytes[2], PROTOCOL_VERSION);
            assert_eq!(bytes[5], FLAGS_NONE);
            assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), PAYLOAD_LEN_V1);
            assert_eq!(
                u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
                RESERVED_V1
            );

            match message.kind {
                MessageKind::Request => {
                    assert!(is_request_opcode(message.opcode));
                    assert_ne!(message.request_id, 0);
                }
                MessageKind::Response => {
                    assert!(is_response_opcode(message.opcode));
                    assert!(request_id_valid(
                        MessageKind::Response,
                        message.opcode,
                        message.request_id
                    ));
                }
            }
        }
    }

    #[kani::proof]
    fn valid_requests_round_trip() {
        let opcode: u8 = kani::any();
        let request_id: u32 = kani::any();

        if is_request_opcode(opcode) && request_id != 0 {
            let bytes = encode_request(opcode, request_id).expect("valid request must encode");
            let message = parse(&bytes).expect("encoded request must parse");

            assert_eq!(message.kind, MessageKind::Request);
            assert_eq!(message.opcode, opcode);
            assert_eq!(message.request_id, request_id);
        }
    }
}
