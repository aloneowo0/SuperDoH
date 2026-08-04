//! SVCB/HTTPS helpers backed by Hickory's RFC 9460 implementation.

use hickory_proto::{
    op::Message,
    rr::{
        RData,
        rdata::svcb::{EchConfigList, Mandatory, SVCB, SvcParamKey, SvcParamValue},
    },
    serialize::binary::BinEncodable,
};

use super::wire::{DnsError, Result, TYPE_HTTPS};

pub const PARAM_ECH: u16 = 5;

/// Validates and canonicalizes HTTPS/SVCB RDATA through Hickory.
pub(crate) fn canonicalize(rdata: &[u8]) -> Result<Vec<u8>> {
    parse_https_rdata(rdata)?
        .to_bytes()
        .map_err(|error| DnsError::new(error.to_string()))
}

/// Returns the `ECHConfigList` from canonical HTTPS RDATA when present.
///
/// # Errors
///
/// Returns an error when the RDATA cannot be decoded as an HTTPS record.
pub fn ech_config(rdata: &[u8]) -> Result<Option<Vec<u8>>> {
    let record = parse_https_rdata(rdata)?;
    Ok(record.svc_params.iter().find_map(|(_, value)| {
        let SvcParamValue::EchConfigList(ech) = value else {
            return None;
        };
        Some(ech.0.clone())
    }))
}

/// Replaces or adds the ECH `SvcParam` in a `ServiceMode` HTTPS record.
///
/// Hickory owns SVCB parameter parsing, ordering and serialization. `AliasMode` records are left
/// untouched because injecting `ServiceMode` parameters into them would be invalid.
///
/// # Errors
///
/// Returns an error when the input is malformed or the resulting record cannot be encoded.
pub fn replace_ech(rdata: &[u8], ech: &[u8]) -> Result<Option<Vec<u8>>> {
    if ech.is_empty() {
        return Err(DnsError::new("SVCB ECH parameter is empty"));
    }

    let mut record = parse_https_rdata(rdata)?;
    if record.svc_priority == 0 {
        return Ok(None);
    }

    let ech_key = SvcParamKey::from(PARAM_ECH);
    record.svc_params.retain(|(key, _)| *key != ech_key);
    record.svc_params.push((
        ech_key,
        SvcParamValue::EchConfigList(EchConfigList(ech.to_vec())),
    ));
    record
        .svc_params
        .sort_by(|(left, _), (right, _)| left.cmp(right));

    record
        .to_bytes()
        .map(Some)
        .map_err(|error| DnsError::new(error.to_string()))
}

/// Removes selected IP hint parameters from a `ServiceMode` HTTPS record and keeps `mandatory`
/// self-consistent.
///
/// `AliasMode` is left untouched. If all mandatory keys are removed, the now-empty `mandatory`
/// parameter is removed as well because an empty Mandatory value is invalid.
///
/// # Errors
///
/// Returns an error when the input is malformed or the resulting record cannot be encoded.
pub fn remove_ip_hints(
    rdata: &[u8],
    remove_ipv4: bool,
    remove_ipv6: bool,
) -> Result<Option<Vec<u8>>> {
    if !remove_ipv4 && !remove_ipv6 {
        return Ok(None);
    }

    let mut record = parse_https_rdata(rdata)?;
    if record.svc_priority == 0 {
        return Ok(None);
    }

    let should_remove = |key: SvcParamKey| {
        (remove_ipv4 && key == SvcParamKey::Ipv4Hint)
            || (remove_ipv6 && key == SvcParamKey::Ipv6Hint)
    };
    if !record.svc_params.iter().any(|(key, _)| should_remove(*key)) {
        return Ok(None);
    }

    for (_, value) in &mut record.svc_params {
        if let SvcParamValue::Mandatory(Mandatory(keys)) = value {
            keys.retain(|key| !should_remove(*key));
        }
    }
    record.svc_params.retain(|(key, value)| {
        if should_remove(*key) {
            return false;
        }
        !matches!(value, SvcParamValue::Mandatory(Mandatory(keys)) if keys.is_empty())
    });
    record
        .svc_params
        .sort_by(|(left, _), (right, _)| left.cmp(right));

    record
        .to_bytes()
        .map(Some)
        .map_err(|error| DnsError::new(error.to_string()))
}

/// Hickory decodes SVCB as typed RDATA in the context of a DNS record. Wrap canonical RDATA in a
/// minimal one-answer message so all RFC 9460 validation stays in Hickory rather than being
/// duplicated here.
fn parse_https_rdata(rdata: &[u8]) -> Result<SVCB> {
    let rdata_len = u16::try_from(rdata.len())
        .map_err(|_| DnsError::new("HTTPS RDATA exceeds 65535 octets"))?;
    let mut wire = Vec::with_capacity(23_usize.saturating_add(rdata.len()));
    wire.extend_from_slice(&[
        0, 0, // ID
        0x81, 0x80, // standard response
        0, 0, // QDCOUNT
        0, 1, // ANCOUNT
        0, 0, // NSCOUNT
        0, 0, // ARCOUNT
        0, // root owner name
    ]);
    wire.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes()); // IN
    wire.extend_from_slice(&0_u32.to_be_bytes()); // TTL
    wire.extend_from_slice(&rdata_len.to_be_bytes());
    wire.extend_from_slice(rdata);

    let message = Message::from_vec(&wire).map_err(|error| DnsError::new(error.to_string()))?;
    let Some(answer) = message.answers.first() else {
        return Err(DnsError::new("HTTPS RDATA produced no record"));
    };
    let RData::HTTPS(https) = &answer.data else {
        return Err(DnsError::new("RDATA is not HTTPS"));
    };
    Ok(https.0.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_ech_and_rejects_alias_mode() {
        let service = [0, 1, 0];
        let ech = [0, 5, 0xfe, 0x0d, 0, 1, 1];
        let updated = match replace_ech(&service, &ech) {
            Ok(Some(value)) => value,
            Ok(None) => panic!("service mode must be editable"),
            Err(error) => panic!("service mode must decode: {error}"),
        };
        assert_eq!(ech_config(&updated), Ok(Some(ech.to_vec())));

        let alias = [0, 0, 1, b'x', 0];
        assert_eq!(replace_ech(&alias, &ech), Ok(None));
    }

    #[test]
    fn removes_hints_and_keeps_mandatory_consistent() {
        let service = [
            0, 1, // priority = ServiceMode
            0, // target = root
            0, 0, 0, 4, 0, 4, 0, 6, // mandatory = ipv4hint, ipv6hint
            0, 4, 0, 4, 1, 1, 1, 1, // ipv4hint = 1.1.1.1
            0, 6, 0, 16, // ipv6hint = 2606:4700::1
            0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];

        let without_v4 = match remove_ip_hints(&service, true, false) {
            Ok(Some(value)) => value,
            Ok(None) => panic!("IPv4 hint must be removed"),
            Err(error) => panic!("valid HTTPS RDATA must decode: {error}"),
        };
        let parsed = match parse_https_rdata(&without_v4) {
            Ok(value) => value,
            Err(error) => panic!("updated HTTPS RDATA must parse: {error}"),
        };
        assert!(
            !parsed
                .svc_params
                .iter()
                .any(|(key, _)| *key == SvcParamKey::Ipv4Hint)
        );
        assert!(
            parsed
                .svc_params
                .iter()
                .any(|(key, _)| *key == SvcParamKey::Ipv6Hint)
        );
        let mandatory = parsed.svc_params.iter().find_map(|(_, value)| {
            let SvcParamValue::Mandatory(Mandatory(keys)) = value else {
                return None;
            };
            Some(keys.as_slice())
        });
        assert_eq!(mandatory, Some([SvcParamKey::Ipv6Hint].as_slice()));

        let without_hints = match remove_ip_hints(&service, true, true) {
            Ok(Some(value)) => value,
            Ok(None) => panic!("IP hints must be removed"),
            Err(error) => panic!("valid HTTPS RDATA must decode: {error}"),
        };
        let parsed = match parse_https_rdata(&without_hints) {
            Ok(value) => value,
            Err(error) => panic!("updated HTTPS RDATA must parse: {error}"),
        };
        assert!(parsed.svc_params.is_empty());
    }
}
