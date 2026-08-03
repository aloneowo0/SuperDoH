//! Semantic validation for upstream DNS responses.

use std::net::IpAddr;

use super::{
    parse_opt,
    wire::{
        Question, ResourceRecord, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_NS, TYPE_OPT, decode_name,
        extract_ip_bytes, parse_message,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegativeKind {
    NxDomain,
    NoData,
    Referral,
}

fn record_ip(record: &ResourceRecord) -> Option<IpAddr> {
    let bytes = extract_ip_bytes(record)?;
    match record.rr_type {
        TYPE_A => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        TYPE_AAAA => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Positive,
    Negative(NegativeKind),
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub network: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// Returns true when `address` is within this CIDR, with address-family mismatch rejected.
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) if self.prefix <= 32 => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) if self.prefix <= 128 => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

/// Validates identity, query semantics, RCODE and blocked A/AAAA answers.
#[must_use]
pub fn classify_response(
    wire: &[u8],
    id: u16,
    expected: &Question,
    blocked: &[Cidr],
) -> Classification {
    let Ok(message) = parse_message(wire) else {
        return Classification::Invalid;
    };
    let header = message.header;
    if header.id != id
        || header.flags & 0x8000 == 0
        || header.flags & 0x7800 != 0
        || header.qd_count != 1
        || message.questions.first() != Some(expected)
        || expected.qclass != 1
    {
        return Classification::Invalid;
    }
    let extended_rcode = message
        .additionals
        .iter()
        .filter(|record| record.rr_type == TYPE_OPT)
        .try_fold(0_u8, |_, record| {
            parse_opt(record).map(|opt| opt.extended_rcode)
        });
    let Ok(extended_rcode) = extended_rcode else {
        return Classification::Invalid;
    };
    let rcode = header.flags & 0x000f;
    if extended_rcode != 0 {
        return Classification::Invalid;
    }
    if rcode == 3 {
        return Classification::Negative(NegativeKind::NxDomain);
    }
    if rcode != 0 {
        return Classification::Invalid;
    }
    if message.answers.is_empty()
        && message
            .authorities
            .iter()
            .any(|record| record.rr_type == TYPE_NS)
    {
        return Classification::Negative(NegativeKind::Referral);
    }
    if message.answers.is_empty() {
        return Classification::Negative(NegativeKind::NoData);
    }
    let mut owner = expected.name.trim_end_matches('.').to_ascii_lowercase();
    let mut matched = false;
    for _ in 0..message.answers.len() {
        if message.answers.iter().any(|record| {
            record
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&owner)
                && record.rr_type == expected.qtype
                && record.class == expected.qclass
        }) {
            matched = true;
            break;
        }
        let Some(cname) = message.answers.iter().find(|record| {
            record
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&owner)
                && record.rr_type == TYPE_CNAME
                && record.class == expected.qclass
        }) else {
            break;
        };
        let mut cursor = 0;
        let Ok(target) = decode_name(&cname.rdata, &mut cursor) else {
            return Classification::Invalid;
        };
        if cursor != cname.rdata.len() {
            return Classification::Invalid;
        }
        owner = target.to_ascii_lowercase();
    }
    if !matched {
        return Classification::Invalid;
    }
    for record in &message.answers {
        let Some(ip) = record_ip(record) else {
            continue;
        };
        if blocked.iter().copied().any(|range| range.contains(ip)) {
            return Classification::Invalid;
        }
    }
    Classification::Positive
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{
        CLASS_IN, Header, Message, ResourceRecord, TYPE_A, TYPE_CNAME, TYPE_NS, TYPE_OPT, TYPE_SOA,
        build_response, encode_name, serialize_message,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn expected() -> Question {
        Question {
            name: "example.com".to_owned(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        }
    }

    #[test]
    fn classifies_positive_negative_and_blacklisted() {
        let response =
            match build_response(4, "example.com", TYPE_A, &[vec![1, 1, 1, 1]], 60, 0x8180) {
                Ok(value) => value,
                Err(error) => panic!("positive response must build: {error}"),
            };
        assert_eq!(
            classify_response(&response, 4, &expected(), &[]),
            Classification::Positive
        );
        let nxdomain = match build_response(4, "example.com", TYPE_A, &[], 60, 0x8183) {
            Ok(value) => value,
            Err(error) => panic!("NXDOMAIN response must build: {error}"),
        };
        assert_eq!(
            classify_response(&nxdomain, 4, &expected(), &[]),
            Classification::Negative(NegativeKind::NxDomain)
        );
        let blocked = [Cidr {
            network: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 0)),
            prefix: 24,
        }];
        assert_eq!(
            classify_response(&response, 4, &expected(), &blocked),
            Classification::Invalid
        );
    }

    #[test]
    fn distinguishes_nodata_from_a_referral_and_follows_cname() {
        let base = Message {
            header: Header {
                id: 4,
                flags: 0x8180,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![expected()],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };
        let nodata_without_soa = match serialize_message(&base) {
            Ok(value) => value,
            Err(error) => panic!("NODATA must serialize: {error}"),
        };
        assert_eq!(
            classify_response(&nodata_without_soa, 4, &expected(), &[]),
            Classification::Negative(NegativeKind::NoData)
        );
        let mut nodata = base.clone();
        nodata.authorities.push(ResourceRecord {
            name: "example.com".to_owned(),
            rr_type: TYPE_SOA,
            class: CLASS_IN,
            ttl: 60,
            rdata: [vec![0], vec![0], vec![0; 20]].concat(),
        });
        let nodata = match serialize_message(&nodata) {
            Ok(value) => value,
            Err(error) => panic!("NODATA must serialize: {error}"),
        };
        assert_eq!(
            classify_response(&nodata, 4, &expected(), &[]),
            Classification::Negative(NegativeKind::NoData)
        );
        let mut referral = base.clone();
        referral.authorities.push(ResourceRecord {
            name: "com".to_owned(),
            rr_type: TYPE_NS,
            class: CLASS_IN,
            ttl: 60,
            rdata: name_rdata("ns.example.com"),
        });
        let referral = match serialize_message(&referral) {
            Ok(value) => value,
            Err(error) => panic!("referral must serialize: {error}"),
        };
        assert_eq!(
            classify_response(&referral, 4, &expected(), &[]),
            Classification::Negative(NegativeKind::Referral)
        );
        let cname_target = match encode_name("target.example") {
            Ok(value) => value,
            Err(error) => panic!("test CNAME target must encode: {error}"),
        };
        let mut cname_only = base.clone();
        cname_only.answers = vec![ResourceRecord {
            name: "example.com".to_owned(),
            rr_type: TYPE_CNAME,
            class: CLASS_IN,
            ttl: 60,
            rdata: cname_target.clone(),
        }];
        let cname_only = match serialize_message(&cname_only) {
            Ok(value) => value,
            Err(error) => panic!("CNAME-only response must serialize: {error}"),
        };
        assert_eq!(
            classify_response(&cname_only, 4, &expected(), &[]),
            Classification::Invalid
        );
        let mut chained = base;
        chained.answers = vec![
            ResourceRecord {
                name: "example.com".to_owned(),
                rr_type: TYPE_CNAME,
                class: CLASS_IN,
                ttl: 60,
                rdata: cname_target,
            },
            ResourceRecord {
                name: "target.example".to_owned(),
                rr_type: TYPE_A,
                class: CLASS_IN,
                ttl: 60,
                rdata: vec![192, 0, 2, 1],
            },
        ];
        let chained = match serialize_message(&chained) {
            Ok(value) => value,
            Err(error) => panic!("CNAME chain must serialize: {error}"),
        };
        assert_eq!(
            classify_response(&chained, 4, &expected(), &[]),
            Classification::Positive
        );
    }

    #[test]
    fn rejects_nonzero_extended_rcodes() {
        let response = Message {
            header: Header {
                id: 4,
                flags: 0x8180,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![expected()],
            answers: vec![ResourceRecord {
                name: "example.com".to_owned(),
                rr_type: TYPE_A,
                class: CLASS_IN,
                ttl: 60,
                rdata: vec![192, 0, 2, 1],
            }],
            authorities: vec![],
            additionals: vec![ResourceRecord {
                name: String::new(),
                rr_type: TYPE_OPT,
                class: 1232,
                ttl: 1 << 24,
                rdata: vec![],
            }],
        };
        let response = match serialize_message(&response) {
            Ok(value) => value,
            Err(error) => panic!("BADVERS response must serialize: {error}"),
        };
        assert_eq!(
            classify_response(&response, 4, &expected(), &[]),
            Classification::Invalid
        );
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        match encode_name(name) {
            Ok(value) => value,
            Err(error) => panic!("test name must encode: {error}"),
        }
    }
}
