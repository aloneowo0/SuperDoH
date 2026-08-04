use crate::dns::wire::{CLASS_IN, TYPE_RRSIG};
use crate::dns::{self, Header, Message, Question, ResourceRecord};

use super::{ParsedQuery, PolicyError};

const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const FLAG_RA: u16 = 0x0080;
const FLAG_AD: u16 = 0x0020;
const FLAG_RD_CD: u16 = 0x0110;
const MAX_WIRE_SIZE: usize = 65_535;

pub(crate) fn nodata(query: &ParsedQuery, ttl: u32) -> Result<Vec<u8>, PolicyError> {
    synthetic_response(query, 0, ttl, None)
}

pub(crate) fn nxdomain(query: &ParsedQuery, ttl: u32) -> Result<Vec<u8>, PolicyError> {
    synthetic_response(query, 3, ttl, None)
}

pub(crate) fn servfail(query: &ParsedQuery, text: &str) -> Result<Vec<u8>, PolicyError> {
    synthetic_response(query, 2, 0, Some(text))
}

fn synthetic_response(
    query: &ParsedQuery,
    rcode: u16,
    _ttl: u32,
    ede_text: Option<&str>,
) -> Result<Vec<u8>, PolicyError> {
    let additionals = query
        .edns
        .as_ref()
        .map(|opt| {
            let mut rdata = Vec::new();
            if let Some(text) = ede_text {
                let mut ede = crate::config::SERVFAIL_EDE_CODE.to_be_bytes().to_vec();
                ede.extend_from_slice(text.as_bytes());
                let ede_length = u16::try_from(ede.len())
                    .map_err(|_| PolicyError::Build("EDE text too long"))?;
                rdata.extend_from_slice(&15_u16.to_be_bytes());
                rdata.extend_from_slice(&ede_length.to_be_bytes());
                rdata.extend_from_slice(&ede);
            }
            Ok::<ResourceRecord, PolicyError>(ResourceRecord {
                name: String::new(),
                rr_type: dns::wire::TYPE_OPT,
                class: opt.udp_payload,
                ttl: (u32::from(opt.version) << 16) | if opt.do_bit { 0x8000 } else { 0 },
                rdata,
            })
        })
        .transpose()?;
    let message = Message {
        header: Header {
            id: query.id,
            flags: reply_flags(query, rcode),
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: u16::from(additionals.is_some()),
        },
        questions: vec![query.question.clone()],
        answers: vec![],
        authorities: vec![],
        additionals: additionals.into_iter().collect(),
    };
    serialize_response(&message)
}

pub(crate) fn replace_ips(
    original: &[u8],
    query: &ParsedQuery,
    ips: &[Vec<u8>],
    ttl: u32,
) -> Result<Vec<u8>, PolicyError> {
    let mut message = dns::parse_message(original)?;
    let mut answer_name = query.question.name.clone();
    let mut modified_owners = Vec::new();
    let mut found = false;
    message.answers.retain(|record| {
        let replace =
            record.rr_type == query.question.qtype && dns::extract_ip_bytes(record).is_some();
        if replace
            && !modified_owners
                .iter()
                .any(|owner: &String| owner.eq_ignore_ascii_case(&record.name))
        {
            modified_owners.push(record.name.clone());
        }
        if replace && !found {
            answer_name.clone_from(&record.name);
            found = true;
        }
        !replace
    });
    message.answers.extend(ips.iter().map(|ip| ResourceRecord {
        name: answer_name.clone(),
        rr_type: query.question.qtype,
        class: CLASS_IN,
        ttl,
        rdata: ip.clone(),
    }));
    clear_authentication(&mut message, &answer_name, query.question.qtype);
    for owner in modified_owners {
        if !owner.eq_ignore_ascii_case(&answer_name) {
            remove_rrsig_for_rrset(&mut message, &owner, query.question.qtype);
        }
    }
    serialize_response(&message)
}

pub(crate) fn normalize_https_hints(
    original: &[u8],
    remove_ipv4: bool,
    remove_ipv6: bool,
) -> Result<Option<Vec<u8>>, PolicyError> {
    if !remove_ipv4 && !remove_ipv6 {
        return Ok(None);
    }

    let mut message = dns::parse_message(original)?;
    let mut modified_owners = Vec::new();
    let mut changed = false;
    for record in &mut message.answers {
        if record.rr_type != dns::wire::TYPE_HTTPS {
            continue;
        }
        let Some(updated) = dns::svcb::remove_ip_hints(&record.rdata, remove_ipv4, remove_ipv6)?
        else {
            continue;
        };
        record.rdata = updated;
        if !modified_owners
            .iter()
            .any(|owner: &String| owner.eq_ignore_ascii_case(&record.name))
        {
            modified_owners.push(record.name.clone());
        }
        changed = true;
    }
    if !changed {
        return Ok(None);
    }

    for owner in modified_owners {
        clear_authentication(&mut message, &owner, dns::wire::TYPE_HTTPS);
    }
    serialize_response(&message).map(Some)
}

pub(crate) fn serialize_response(message: &Message) -> Result<Vec<u8>, PolicyError> {
    let mut output = vec![0; 12];
    for question in &message.questions {
        append_question(&mut output, question)?;
    }

    let mut answer_count = 0_u16;
    let mut authority_count = 0_u16;
    let mut additional_count = 0_u16;
    let mut truncated = false;
    for (records, count) in [
        (&message.answers, &mut answer_count),
        (&message.authorities, &mut authority_count),
        (&message.additionals, &mut additional_count),
    ] {
        for record in records {
            let encoded = encoded_record(record)?;
            if output
                .len()
                .checked_add(encoded.len())
                .is_none_or(|length| length > MAX_WIRE_SIZE)
            {
                truncated = true;
                break;
            }
            output.extend_from_slice(&encoded);
            *count = count
                .checked_add(1)
                .ok_or(PolicyError::Build("too many DNS records"))?;
        }
        if truncated {
            break;
        }
    }

    if output.len() > MAX_WIRE_SIZE {
        return Err(PolicyError::Build("DNS message exceeds 65535 octets"));
    }
    let qd_count = u16::try_from(message.questions.len())
        .map_err(|_| PolicyError::Build("too many DNS questions"))?;
    let flags = if truncated {
        message.header.flags | FLAG_TC
    } else {
        message.header.flags & !FLAG_TC
    };
    write_header(
        &mut output,
        Header {
            id: message.header.id,
            flags,
            qd_count,
            an_count: answer_count,
            ns_count: authority_count,
            ar_count: additional_count,
        },
    );
    Ok(output)
}

pub(crate) fn clear_authentication(message: &mut Message, owner: &str, covered_type: u16) {
    message.header.flags &= !FLAG_AD;
    // This proxy does not validate DNSSEC, so changed RRsets cannot remain authenticated.
    remove_rrsig_for_rrset(message, owner, covered_type);
}

fn remove_rrsig_for_rrset(message: &mut Message, owner: &str, covered_type: u16) {
    for section in [
        &mut message.answers,
        &mut message.authorities,
        &mut message.additionals,
    ] {
        section.retain(|record| {
            !record.name.eq_ignore_ascii_case(owner) || !covers_type(record, covered_type)
        });
    }
}

fn reply_flags(query: &ParsedQuery, rcode: u16) -> u16 {
    FLAG_QR | FLAG_RA | (query.flags & FLAG_RD_CD) | rcode
}

fn covers_type(record: &ResourceRecord, covered_type: u16) -> bool {
    record.rr_type == TYPE_RRSIG
        && record.rdata.len() >= 2
        && u16::from_be_bytes([record.rdata[0], record.rdata[1]]) == covered_type
}

fn append_question(output: &mut Vec<u8>, question: &Question) -> Result<(), PolicyError> {
    output.extend_from_slice(&dns::encode_name(&question.name)?);
    output.extend_from_slice(&question.qtype.to_be_bytes());
    output.extend_from_slice(&question.qclass.to_be_bytes());
    Ok(())
}

fn encoded_record(record: &ResourceRecord) -> Result<Vec<u8>, PolicyError> {
    let name = dns::encode_name(&record.name)?;
    let rdata = dns::reencode_rdata(record.rr_type, &record.rdata)?;
    let rdata_length =
        u16::try_from(rdata.len()).map_err(|_| PolicyError::Build("RDATA exceeds 65535 octets"))?;
    let capacity = name
        .len()
        .checked_add(10)
        .and_then(|length| length.checked_add(rdata.len()))
        .ok_or(PolicyError::Build("DNS record length overflow"))?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&name);
    encoded.extend_from_slice(&record.rr_type.to_be_bytes());
    encoded.extend_from_slice(&record.class.to_be_bytes());
    encoded.extend_from_slice(&record.ttl.to_be_bytes());
    encoded.extend_from_slice(&rdata_length.to_be_bytes());
    encoded.extend_from_slice(&rdata);
    Ok(encoded)
}

fn write_header(output: &mut [u8], header: Header) {
    for (index, field) in [
        header.id,
        header.flags,
        header.qd_count,
        header.an_count,
        header.ns_count,
        header.ar_count,
    ]
    .iter()
    .enumerate()
    {
        let offset = index * 2;
        output[offset..offset + 2].copy_from_slice(&field.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{TYPE_A, TYPE_AAAA};
    use crate::dns::{Question, parse_message};

    fn query() -> ParsedQuery {
        ParsedQuery {
            id: 9,
            flags: 0x0110,
            question: Question {
                name: "example.com".to_owned(),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            },
            client_sent_ecs: false,
            edns: None,
        }
    }

    #[test]
    fn replacement_clears_ad_and_related_rrsig() {
        let response =
            crate::dns::build_response(9, "example.com", TYPE_A, &[vec![192, 0, 2, 1]], 60, 0x81a0);
        let response = match response {
            Ok(response) => response,
            Err(error) => panic!("test response must build: {error}"),
        };
        let changed = replace_ips(&response, &query(), &[vec![192, 0, 2, 2]], 60);
        let changed = match changed {
            Ok(changed) => changed,
            Err(error) => panic!("replacement must serialize: {error}"),
        };
        let parsed = match parse_message(&changed) {
            Ok(parsed) => parsed,
            Err(error) => panic!("replacement must parse: {error}"),
        };
        assert_eq!(parsed.header.flags & FLAG_AD, 0);
        assert_eq!(parsed.answers[0].rdata, [192, 0, 2, 2]);
    }

    #[test]
    fn hint_normalization_clears_https_authentication() {
        let message = Message {
            header: Header {
                id: 9,
                flags: 0x81a0,
                qd_count: 1,
                an_count: 2,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: "example.com".to_owned(),
                qtype: dns::wire::TYPE_HTTPS,
                qclass: CLASS_IN,
            }],
            answers: vec![
                ResourceRecord {
                    name: "example.com".to_owned(),
                    rr_type: dns::wire::TYPE_HTTPS,
                    class: CLASS_IN,
                    ttl: 60,
                    rdata: vec![0, 1, 0, 0, 4, 0, 4, 1, 1, 1, 1],
                },
                ResourceRecord {
                    name: "example.com".to_owned(),
                    rr_type: TYPE_RRSIG,
                    class: CLASS_IN,
                    ttl: 60,
                    rdata: vec![0, 65, 0],
                },
            ],
            authorities: vec![],
            additionals: vec![],
        };
        let original = match serialize_response(&message) {
            Ok(value) => value,
            Err(error) => panic!("test HTTPS response must serialize: {error}"),
        };
        let changed = match normalize_https_hints(&original, true, false) {
            Ok(Some(value)) => value,
            Ok(None) => panic!("IPv4 hint must be removed"),
            Err(error) => panic!("hint normalization must succeed: {error}"),
        };
        let parsed = match parse_message(&changed) {
            Ok(value) => value,
            Err(error) => panic!("normalized response must parse: {error}"),
        };
        assert_eq!(parsed.header.flags & FLAG_AD, 0);
        assert!(
            !parsed
                .answers
                .iter()
                .any(|record| record.rr_type == TYPE_RRSIG)
        );
        assert!(dns::proto::https_hint_ips(&changed).is_empty());
    }

    #[test]
    fn synthetic_responses_mirror_client_edns_without_forcing_do() {
        let mut request = query();
        request.edns = Some(crate::dns::OptRecord {
            udp_payload: 1232,
            extended_rcode: 0,
            version: 0,
            do_bit: false,
            options: vec![],
        });
        let response = match nodata(&request, 60) {
            Ok(value) => value,
            Err(error) => panic!("NODATA must serialize: {error}"),
        };
        let parsed = match parse_message(&response) {
            Ok(value) => value,
            Err(error) => panic!("NODATA must parse: {error}"),
        };
        assert_eq!(parsed.header.flags & FLAG_RD_CD, request.flags & FLAG_RD_CD);
        assert_eq!(parsed.additionals.len(), 1);
        let opt = match crate::dns::parse_opt(&parsed.additionals[0]) {
            Ok(value) => value,
            Err(error) => panic!("response OPT must parse: {error}"),
        };
        assert_eq!(opt.udp_payload, 1232);
        assert!(!opt.do_bit);
        let mut without_edns = query();
        without_edns.edns = None;
        let failure = match servfail(&without_edns, "unavailable") {
            Ok(value) => value,
            Err(error) => panic!("SERVFAIL must serialize: {error}"),
        };
        let failure = match parse_message(&failure) {
            Ok(value) => value,
            Err(error) => panic!("SERVFAIL must parse: {error}"),
        };
        assert!(failure.additionals.is_empty());
    }

    #[test]
    fn synthetic_servfail_preserves_client_do_and_cd() {
        let mut request = query();
        request.edns = Some(crate::dns::OptRecord {
            udp_payload: 1232,
            extended_rcode: 0,
            version: 0,
            do_bit: true,
            options: vec![],
        });
        let response = match servfail(&request, "unavailable") {
            Ok(value) => value,
            Err(error) => panic!("SERVFAIL must serialize: {error}"),
        };
        let parsed = match parse_message(&response) {
            Ok(value) => value,
            Err(error) => panic!("SERVFAIL must parse: {error}"),
        };
        assert_eq!(parsed.header.flags & FLAG_RD_CD, request.flags & FLAG_RD_CD);
        let opt = match crate::dns::parse_opt(&parsed.additionals[0]) {
            Ok(value) => value,
            Err(error) => panic!("SERVFAIL OPT must parse: {error}"),
        };
        assert_eq!(opt.udp_payload, 1232);
        assert!(opt.do_bit);
    }

    #[test]
    fn replacement_removes_only_the_modified_rrset_signature() {
        let original = match crate::dns::build_response(
            9,
            "example.com",
            TYPE_A,
            &[vec![192, 0, 2, 1]],
            60,
            0x81a0,
        ) {
            Ok(value) => value,
            Err(error) => panic!("test response must build: {error}"),
        };
        let mut original = match parse_message(&original) {
            Ok(value) => value,
            Err(error) => panic!("test response must parse: {error}"),
        };
        original.answers.extend([
            ResourceRecord {
                name: "example.com".to_owned(),
                rr_type: TYPE_RRSIG,
                class: CLASS_IN,
                ttl: 60,
                rdata: TYPE_A.to_be_bytes().to_vec(),
            },
            ResourceRecord {
                name: "other.example".to_owned(),
                rr_type: TYPE_RRSIG,
                class: CLASS_IN,
                ttl: 60,
                rdata: TYPE_A.to_be_bytes().to_vec(),
            },
            ResourceRecord {
                name: "example.com".to_owned(),
                rr_type: TYPE_RRSIG,
                class: CLASS_IN,
                ttl: 60,
                rdata: TYPE_AAAA.to_be_bytes().to_vec(),
            },
        ]);
        let original = match serialize_response(&original) {
            Ok(value) => value,
            Err(error) => panic!("test response must serialize: {error}"),
        };
        let changed = match replace_ips(&original, &query(), &[vec![192, 0, 2, 2]], 60) {
            Ok(value) => value,
            Err(error) => panic!("replacement must serialize: {error}"),
        };
        let changed = match parse_message(&changed) {
            Ok(value) => value,
            Err(error) => panic!("replacement must parse: {error}"),
        };
        assert!(
            changed
                .answers
                .iter()
                .any(|record| record.name == "other.example")
        );
        assert!(!changed.answers.iter().any(|record| {
            record.name == "example.com"
                && record.rr_type == TYPE_RRSIG
                && covers_type(record, TYPE_A)
        }));
        assert!(changed.answers.iter().any(|record| {
            record.name == "example.com"
                && record.rr_type == TYPE_RRSIG
                && covers_type(record, TYPE_AAAA)
        }));
    }

    #[test]
    fn truncates_oversized_responses_at_record_boundaries() {
        const TYPE_TXT: u16 = 16;
        const LARGE_RDATA: usize = 32_000;
        let message = Message {
            header: Header {
                id: 9,
                flags: 0x8180,
                qd_count: 1,
                an_count: 4,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: "example.com".to_owned(),
                qtype: TYPE_TXT,
                qclass: CLASS_IN,
            }],
            answers: (0..4)
                .map(|_| ResourceRecord {
                    name: "example.com".to_owned(),
                    rr_type: TYPE_TXT,
                    class: CLASS_IN,
                    ttl: 60,
                    rdata: vec![0; LARGE_RDATA],
                })
                .collect(),
            authorities: vec![],
            additionals: vec![],
        };
        let serialized = match serialize_response(&message) {
            Ok(value) => value,
            Err(error) => panic!("oversized response must serialize truncated: {error}"),
        };
        assert!(serialized.len() <= MAX_WIRE_SIZE);
        let parsed = match parse_message(&serialized) {
            Ok(value) => value,
            Err(error) => panic!("truncated response must parse: {error}"),
        };
        assert_ne!(parsed.header.flags & FLAG_TC, 0);
        assert_eq!(parsed.answers.len(), 2);
        for record in &parsed.answers {
            assert_eq!(record.rdata.len(), LARGE_RDATA);
        }
    }
}
