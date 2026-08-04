//! EDNS(0) and EDNS Client Subnet support (RFC 6891 and RFC 7871).

use std::net::IpAddr;

use hickory_proto::rr::rdata::opt::ClientSubnet;
use ipnet::IpNet;

use super::wire::{
    DnsError, Message, ResourceRecord, Result, TYPE_OPT, parse_message, serialize_message,
};

pub const OPTION_ECS: u16 = 8;
pub const DEFAULT_UDP_PAYLOAD: u16 = 4096;
pub const DO_BIT: u32 = 0x8000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptRecord {
    pub udp_payload: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub do_bit: bool,
    pub options: Vec<(u16, Vec<u8>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ecs(ClientSubnet);

/// Parses an OPT RR into its EDNS header and length-delimited option list.
///
/// # Errors
///
/// Returns an error when the record is not OPT or its options are malformed.
pub fn parse_opt(record: &ResourceRecord) -> Result<OptRecord> {
    if record.rr_type != TYPE_OPT {
        return Err(DnsError::new("record is not OPT"));
    }
    let mut cursor = 0;
    let mut options = Vec::new();
    while cursor < record.rdata.len() {
        let header = record
            .rdata
            .get(
                cursor
                    ..cursor
                        .checked_add(4)
                        .ok_or(DnsError::new("EDNS offset overflow"))?,
            )
            .ok_or(DnsError::new("truncated EDNS option"))?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        cursor = cursor
            .checked_add(4)
            .ok_or(DnsError::new("EDNS offset overflow"))?;
        let end = cursor
            .checked_add(length)
            .ok_or(DnsError::new("EDNS offset overflow"))?;
        options.push((
            code,
            record
                .rdata
                .get(cursor..end)
                .ok_or(DnsError::new("truncated EDNS option data"))?
                .to_vec(),
        ));
        cursor = end;
    }
    Ok(OptRecord {
        udp_payload: record.class,
        extended_rcode: u8::try_from(record.ttl >> 24)
            .map_err(|_| DnsError::new("invalid EDNS ext-rcode"))?,
        version: u8::try_from((record.ttl >> 16) & 0xff)
            .map_err(|_| DnsError::new("invalid EDNS version"))?,
        do_bit: record.ttl & DO_BIT != 0,
        options,
    })
}

/// Decodes the first ECS option in an OPT RR.
///
/// # Errors
///
/// Returns an error when the OPT record or ECS option is malformed.
pub fn parse_ecs(record: &ResourceRecord) -> Result<Option<Ecs>> {
    let opt = parse_opt(record)?;
    parse_ecs_option(&opt)
}

/// Decodes the first ECS option in parsed EDNS state.
///
/// # Errors
///
/// Returns an error when the ECS option is malformed.
pub fn parse_ecs_option(opt: &OptRecord) -> Result<Option<Ecs>> {
    let Some((_, value)) = opt.options.iter().find(|(code, _)| *code == OPTION_ECS) else {
        return Ok(None);
    };
    let subnet = ClientSubnet::try_from(value.as_slice())
        .map_err(|error| DnsError::new(error.to_string()))?;
    let ecs = Ecs::from_subnet(subnet)?;
    if ecs.bytes()?.len() != value.len() {
        return Err(DnsError::new("invalid ECS address length"));
    }
    Ok(Some(ecs))
}

/// Finds the client ECS option in a DNS query.
///
/// # Errors
///
/// Returns an error when the DNS message or its EDNS data is malformed.
pub fn query_ecs(wire: &[u8]) -> Result<Option<Ecs>> {
    let message = parse_message(wire)?;
    let mut ecs = None;
    let mut has_opt = false;
    for record in &message.additionals {
        if record.rr_type == TYPE_OPT {
            if has_opt {
                return Err(DnsError::new("multiple OPT records"));
            }
            has_opt = true;
            ecs = parse_ecs(record)?;
        }
    }
    Ok(ecs)
}

impl Ecs {
    /// Builds a canonical ECS value. `ipnet` masks host bits and Hickory owns the wire encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when `prefix` exceeds the address-family width.
    pub fn from_ip(ip: IpAddr, prefix: u8) -> Result<Self> {
        let network = IpNet::new(ip, prefix)
            .map_err(|error| DnsError::new(error.to_string()))?
            .trunc();
        Ok(Self(ClientSubnet::from(network)))
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        Vec::<u8>::try_from(&self.0).map_err(|error| DnsError::new(error.to_string()))
    }

    fn from_subnet(subnet: ClientSubnet) -> Result<Self> {
        let network = IpNet::new(subnet.addr(), subnet.source_prefix())
            .map_err(|error| DnsError::new(error.to_string()))?
            .trunc();
        if network.addr() != subnet.addr() {
            return Err(DnsError::new("non-zero ECS host bits"));
        }
        let maximum = if subnet.addr().is_ipv4() { 32 } else { 128 };
        if subnet.scope_prefix() > maximum {
            return Err(DnsError::new("invalid ECS scope prefix"));
        }
        Ok(Self(subnet))
    }

    #[must_use]
    pub fn source_prefix(&self) -> u8 {
        self.0.source_prefix()
    }
}

fn opt_rdata(options: &[(u16, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for (code, value) in options {
        output.extend_from_slice(&code.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(value.len())
                .map_err(|_| DnsError::new("EDNS option too long"))?
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
    Ok(output)
}

/// Preserves client EDNS state while injecting a synthetic ECS option only when absent.
///
/// # Errors
///
/// Returns an error when the DNS message or its EDNS data is malformed.
pub fn prepare_query(
    wire: &[u8],
    client_ip: Option<IpAddr>,
    prefix4: u8,
    prefix6: u8,
) -> Result<Vec<u8>> {
    let mut message = parse_message(wire)?;
    let positions: Vec<_> = message
        .additionals
        .iter()
        .enumerate()
        .filter_map(|(index, record)| (record.rr_type == TYPE_OPT).then_some(index))
        .collect();
    if positions.len() > 1 {
        return Err(DnsError::new("multiple OPT records"));
    }
    let position = positions.first().copied();
    let existing = match position {
        Some(index) => Some(parse_opt(&message.additionals[index])?),
        None => None,
    };
    let mut options = match &existing {
        Some(opt) => opt.options.clone(),
        None => Vec::new(),
    };
    let has_ecs = options.iter().any(|(code, _)| *code == OPTION_ECS);
    if !has_ecs && let Some(ip) = client_ip {
        let prefix = match ip {
            IpAddr::V4(_) => prefix4,
            IpAddr::V6(_) => prefix6,
        };
        options.push((OPTION_ECS, Ecs::from_ip(ip, prefix)?.bytes()?));
    }
    let opt = ResourceRecord {
        name: String::new(),
        rr_type: TYPE_OPT,
        class: existing
            .as_ref()
            .map_or(DEFAULT_UDP_PAYLOAD, |opt| opt.udp_payload),
        ttl: existing.as_ref().map_or(0, |opt| {
            (u32::from(opt.version) << 16) | if opt.do_bit { DO_BIT } else { 0 }
        }),
        rdata: opt_rdata(&options)?,
    };
    if let Some(index) = position {
        message.additionals[index] = opt;
    } else {
        message.additionals.push(opt);
    }
    serialize_message(&message)
}

/// Removes every ECS option from a DNS message.
///
/// # Errors
///
/// Returns an error when the DNS message or its EDNS data is malformed.
pub fn remove_ecs(wire: &[u8]) -> Result<Vec<u8>> {
    rewrite_ecs(wire, None)
}

/// Normalizes ECS options in an upstream response to the client's original ECS state.
///
/// # Errors
///
/// Returns an error when the DNS message or its EDNS data is malformed.
pub fn normalize_response(wire: &[u8], client_ecs: Option<&Ecs>) -> Result<Vec<u8>> {
    rewrite_ecs(wire, client_ecs)
}

fn rewrite_ecs(wire: &[u8], client_ecs: Option<&Ecs>) -> Result<Vec<u8>> {
    let mut message: Message = parse_message(wire)?;
    let mut changed = false;
    for record in &mut message.additionals {
        if record.rr_type == TYPE_OPT {
            let opt = parse_opt(record)?;
            let mut has_ecs = false;
            let mut options = Vec::with_capacity(opt.options.len());
            for (code, value) in opt.options {
                if code == OPTION_ECS {
                    has_ecs = true;
                    if let Some(ecs) = client_ecs
                        && !options.iter().any(|(existing, _)| *existing == OPTION_ECS)
                    {
                        options.push((OPTION_ECS, ecs.bytes()?));
                    }
                } else {
                    options.push((code, value));
                }
            }
            if has_ecs {
                record.rdata = opt_rdata(&options)?;
                changed = true;
            }
        }
    }
    if changed {
        serialize_message(&message)
    } else {
        Ok(wire.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{CLASS_IN, Question, parse_message};
    use std::net::{IpAddr, Ipv4Addr};

    fn query() -> Vec<u8> {
        let message = Message {
            header: super::super::wire::Header {
                id: 1,
                flags: 0x0100,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: "example.com".to_owned(),
                qtype: 1,
                qclass: CLASS_IN,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };
        serialize_message(&message).unwrap()
    }

    #[test]
    fn injects_ecs_without_duplicates() {
        let prepared = prepare_query(
            &query(),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            24,
            56,
        )
        .unwrap();
        let parsed = parse_message(&prepared).unwrap();
        let opt = parse_opt(&parsed.additionals[0]).unwrap();
        assert!(!opt.do_bit);
        assert_eq!(opt.udp_payload, 4096);
        assert_eq!(
            opt.options
                .iter()
                .filter(|(code, _)| *code == OPTION_ECS)
                .count(),
            1
        );
        let once_more = prepare_query(
            &prepared,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            32,
            56,
        )
        .unwrap();
        assert_eq!(
            parse_ecs(&parse_message(&once_more).unwrap().additionals[0])
                .unwrap()
                .unwrap()
                .source_prefix(),
            24
        );
    }

    #[test]
    fn ecs_masks_and_supports_zero_prefix() {
        let masked = Ecs::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 1)), 13).unwrap();
        assert_eq!(masked.bytes().unwrap(), [0, 1, 13, 0, 192, 168]);
        assert_eq!(
            Ecs::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0)
                .unwrap()
                .bytes()
                .unwrap(),
            [0, 1, 0, 0]
        );
    }

    #[test]
    fn preserves_client_opt_state_while_adding_ecs() {
        let mut message = match parse_message(&query()) {
            Ok(value) => value,
            Err(error) => panic!("test query must parse: {error}"),
        };
        message.additionals.push(ResourceRecord {
            name: String::new(),
            rr_type: TYPE_OPT,
            class: 1232,
            ttl: (3_u32 << 16) | DO_BIT,
            rdata: vec![0, 12, 0, 2, 1, 2],
        });
        let input = match serialize_message(&message) {
            Ok(value) => value,
            Err(error) => panic!("test query must serialize: {error}"),
        };
        let prepared = match prepare_query(
            &input,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            24,
            56,
        ) {
            Ok(value) => value,
            Err(error) => panic!("query preparation must preserve OPT: {error}"),
        };
        let parsed = match parse_message(&prepared) {
            Ok(value) => value,
            Err(error) => panic!("prepared query must parse: {error}"),
        };
        let opt = match parse_opt(&parsed.additionals[0]) {
            Ok(value) => value,
            Err(error) => panic!("prepared OPT must parse: {error}"),
        };
        assert_eq!(opt.udp_payload, 1232);
        assert_eq!(opt.version, 3);
        assert!(opt.do_bit);
        assert!(opt.options.iter().any(|(code, _)| *code == 12));
    }

    #[test]
    fn removes_ecs_without_affecting_other_options() {
        let prepared = match prepare_query(
            &query(),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            24,
            56,
        ) {
            Ok(value) => value,
            Err(error) => panic!("query preparation must succeed: {error}"),
        };
        let without_ecs = match remove_ecs(&prepared) {
            Ok(value) => value,
            Err(error) => panic!("ECS removal must succeed: {error}"),
        };
        let parsed = match parse_message(&without_ecs) {
            Ok(value) => value,
            Err(error) => panic!("ECS-stripped query must parse: {error}"),
        };
        let opt = match parse_opt(&parsed.additionals[0]) {
            Ok(value) => value,
            Err(error) => panic!("ECS-stripped OPT must parse: {error}"),
        };
        assert!(!opt.options.iter().any(|(code, _)| *code == OPTION_ECS));
    }

    #[test]
    fn normalizes_response_to_the_client_ecs() {
        let original = match Ecs::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), 13) {
            Ok(value) => value,
            Err(error) => panic!("client ECS must build: {error}"),
        };
        let worker_ecs = match Ecs::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 24) {
            Ok(value) => value,
            Err(error) => panic!("worker ECS must build: {error}"),
        };
        let mut message = match parse_message(&query()) {
            Ok(value) => value,
            Err(error) => panic!("test response must parse: {error}"),
        };
        let worker_bytes = match worker_ecs.bytes() {
            Ok(value) => value,
            Err(error) => panic!("worker ECS must serialize: {error}"),
        };
        let rdata = match opt_rdata(&[(OPTION_ECS, worker_bytes)]) {
            Ok(value) => value,
            Err(error) => panic!("worker OPT must serialize: {error}"),
        };
        message.additionals.push(ResourceRecord {
            name: String::new(),
            rr_type: TYPE_OPT,
            class: DEFAULT_UDP_PAYLOAD,
            ttl: 0,
            rdata,
        });
        let response = match serialize_message(&message) {
            Ok(value) => value,
            Err(error) => panic!("test response must serialize: {error}"),
        };
        let normalized = match normalize_response(&response, Some(&original)) {
            Ok(value) => value,
            Err(error) => panic!("response normalization must succeed: {error}"),
        };
        let parsed = match parse_message(&normalized) {
            Ok(value) => value,
            Err(error) => panic!("normalized response must parse: {error}"),
        };
        let ecs = match parse_ecs(&parsed.additionals[0]) {
            Ok(Some(value)) => value,
            Ok(None) => panic!("normalized response must retain client ECS"),
            Err(error) => panic!("normalized ECS must parse: {error}"),
        };
        assert_eq!(ecs, original);
        let stripped = match normalize_response(&response, None) {
            Ok(value) => value,
            Err(error) => panic!("response stripping must succeed: {error}"),
        };
        let stripped = match parse_message(&stripped) {
            Ok(value) => value,
            Err(error) => panic!("stripped response must parse: {error}"),
        };
        assert!(parse_ecs(&stripped.additionals[0]).is_ok_and(|ecs| ecs.is_none()));
    }

    #[test]
    fn strips_synthetic_upstream_ecs_when_client_sent_none() {
        let mut message = match parse_message(&query()) {
            Ok(value) => value,
            Err(error) => panic!("test response must parse: {error}"),
        };
        message.header.flags = 0x8180;
        message.answers.push(ResourceRecord {
            name: "example.com".to_owned(),
            rr_type: crate::dns::wire::TYPE_A,
            class: crate::dns::wire::CLASS_IN,
            ttl: 60,
            rdata: vec![192, 0, 2, 1],
        });
        let worker_ecs = match Ecs::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 24) {
            Ok(value) => value,
            Err(error) => panic!("worker ECS must build: {error}"),
        };
        let worker_bytes = match worker_ecs.bytes() {
            Ok(value) => value,
            Err(error) => panic!("worker ECS must serialize: {error}"),
        };
        let rdata = match opt_rdata(&[(OPTION_ECS, worker_bytes), (12, vec![1, 2])]) {
            Ok(value) => value,
            Err(error) => panic!("worker OPT must serialize: {error}"),
        };
        message.additionals.push(ResourceRecord {
            name: String::new(),
            rr_type: TYPE_OPT,
            class: DEFAULT_UDP_PAYLOAD,
            ttl: 0,
            rdata,
        });
        let response = match serialize_message(&message) {
            Ok(value) => value,
            Err(error) => panic!("test response must serialize: {error}"),
        };
        let normalized = match normalize_response(&response, None) {
            Ok(value) => value,
            Err(error) => panic!("response normalization must succeed: {error}"),
        };
        let parsed = match parse_message(&normalized) {
            Ok(value) => value,
            Err(error) => panic!("normalized response must parse: {error}"),
        };
        assert_eq!(parsed.answers.len(), 1);
        let opt = match parse_opt(&parsed.additionals[0]) {
            Ok(value) => value,
            Err(error) => panic!("normalized OPT must parse: {error}"),
        };
        assert!(!opt.options.iter().any(|(code, _)| *code == OPTION_ECS));
        assert!(opt.options.iter().any(|(code, _)| *code == 12));
    }
}
