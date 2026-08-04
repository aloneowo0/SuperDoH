//! Mature DNS protocol decoding helpers backed by Hickory.
//!
//! `SuperDoH` keeps policy semantics locally, but delegates generic DNS wire decoding and typed
//! RDATA parsing to `hickory-proto` instead of duplicating protocol parsers.

use hickory_proto::{
    op::Message,
    rr::{RData, rdata::svcb::SvcParamValue},
};

use super::wire::{TYPE_A, TYPE_AAAA};

/// Extracts A or AAAA answer addresses from a complete DNS message.
#[must_use]
pub fn answer_ips(wire: &[u8], qtype: u16) -> Vec<Vec<u8>> {
    let Ok(message) = Message::from_vec(wire) else {
        return Vec::new();
    };

    message
        .answers
        .iter()
        .filter_map(|record| match (qtype, &record.data) {
            (TYPE_A, RData::A(address)) => Some(address.octets().to_vec()),
            (TYPE_AAAA, RData::AAAA(address)) => Some(address.octets().to_vec()),
            _ => None,
        })
        .collect()
}

/// Extracts `ipv4hint` and `ipv6hint` addresses from `ServiceMode` HTTPS answers.
///
/// `AliasMode` records are intentionally ignored because their service parameters are not used by
/// clients. The returned addresses are only protocol data; ownership policy remains in
/// `policy::classify`.
#[must_use]
pub fn https_hint_ips(wire: &[u8]) -> Vec<Vec<u8>> {
    let Ok(message) = Message::from_vec(wire) else {
        return Vec::new();
    };

    let mut output = Vec::new();
    for record in &message.answers {
        let RData::HTTPS(https) = &record.data else {
            continue;
        };
        if https.0.svc_priority == 0 {
            continue;
        }
        for (_, value) in &https.svc_params {
            match value {
                SvcParamValue::Ipv4Hint(hints) => {
                    output.extend(hints.0.iter().map(|address| address.octets().to_vec()));
                }
                SvcParamValue::Ipv6Hint(hints) => {
                    output.extend(hints.0.iter().map(|address| address.octets().to_vec()));
                }
                _ => {}
            }
        }
    }
    output
}

/// Returns whether the response contains at least one `ServiceMode` HTTPS answer that can
/// potentially carry ECH.
#[must_use]
pub fn has_https_service_mode(wire: &[u8]) -> bool {
    let Ok(message) = Message::from_vec(wire) else {
        return false;
    };
    message
        .answers
        .iter()
        .any(|record| matches!(&record.data, RData::HTTPS(https) if https.0.svc_priority != 0))
}

/// Returns the first `ECHConfigList` carried by an HTTPS answer.
#[must_use]
pub fn https_ech_config(wire: &[u8]) -> Option<Vec<u8>> {
    let message = Message::from_vec(wire).ok()?;
    message.answers.iter().find_map(|record| {
        let RData::HTTPS(https) = &record.data else {
            return None;
        };
        https.svc_params.iter().find_map(|(_, value)| {
            let SvcParamValue::EchConfigList(ech) = value else {
                return None;
            };
            Some(ech.0.clone())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_mode_preflight_ignores_non_https_answers() {
        let a = match crate::dns::build_response(
            1,
            "example.com",
            TYPE_A,
            &[vec![1, 1, 1, 1]],
            60,
            0x8180,
        ) {
            Ok(value) => value,
            Err(error) => panic!("test A response must build: {error}"),
        };
        assert!(!has_https_service_mode(&a));

        let https = match crate::dns::build_response(
            1,
            "example.com",
            super::super::wire::TYPE_HTTPS,
            &[vec![0, 1, 0]],
            60,
            0x8180,
        ) {
            Ok(value) => value,
            Err(error) => panic!("test HTTPS response must build: {error}"),
        };
        assert!(has_https_service_mode(&https));
    }
}
