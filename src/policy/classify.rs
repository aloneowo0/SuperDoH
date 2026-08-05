use std::net::IpAddr;

use crate::dns::wire::{TYPE_A, TYPE_AAAA, TYPE_HTTPS};
use crate::{
    config,
    dns::{self, Cidr},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owner {
    Cf,
    Meta,
    Cft,
    Vercel,
    Google,
}

impl Owner {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Cf => "CF",
            Self::Meta => "META",
            Self::Cft => "CFT",
            Self::Vercel => "VRC",
            Self::Google => "GOOGLE",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DomainMatch {
    Remap,
    Meta,
    Google(&'static config::GoogleProxy),
}

const META_SUFFIXES: &[&str] = &[
    "facebook.com",
    "fbcdn.net",
    "instagram.com",
    "cdninstagram.com",
    "messenger.com",
    "whatsapp.com",
    "whatsapp.net",
    "threads.net",
    "meta.com",
    "oculus.com",
    "fbsbx.com",
    "thefacebook.com",
    "connect.facebook.net",
];

const VERCEL_CIDRS: &[&str] = &[
    "143.13.0.0/16",
    "155.121.0.0/16",
    "198.169.1.0/24",
    "198.169.2.0/24",
    "216.150.1.0/24",
    "216.150.16.0/24",
    "216.198.79.0/24",
    "216.230.84.0/24",
    "216.230.86.0/24",
    "64.239.109.0/24",
    "64.239.123.0/24",
    "64.29.17.0/24",
    "66.33.60.0/24",
    "76.76.21.0/24",
];

#[must_use]
pub(crate) fn region_for(country: &str) -> Option<&'static config::RegionConfig> {
    if config::CONFIGURED == 0 || config::REGION_CONFIG.is_empty() {
        return None;
    }
    config::REGION_CONFIG
        .iter()
        .find(|region| region.name.eq_ignore_ascii_case(country))
        .or_else(|| {
            config::REGION_CONFIG
                .iter()
                .find(|region| region.name == "*")
        })
}

#[must_use]
pub(crate) fn domain_match(
    name: &str,
    qtype: u16,
    region: &config::RegionConfig,
) -> Option<DomainMatch> {
    if matches_any_suffix(name, region.remap) {
        return Some(DomainMatch::Remap);
    }
    if qtype == TYPE_A
        && region.google_enabled
        && let Some(proxy) = region.google_proxies.and_then(|proxies| {
            proxies
                .iter()
                .find(|proxy| matches_any_suffix(name, proxy.match_patterns))
        })
    {
        return Some(DomainMatch::Google(proxy));
    }
    if is_meta_domain(name) {
        return Some(DomainMatch::Meta);
    }
    None
}

#[must_use]
pub(crate) fn is_remap_domain(name: &str, region: &config::RegionConfig) -> bool {
    matches_any_suffix(name, region.remap)
}

#[must_use]
pub(crate) fn is_meta_domain(name: &str) -> bool {
    matches_any_suffix(name, META_SUFFIXES)
}

#[must_use]
pub(crate) fn matches_any_suffix(name: &str, suffixes: &[&str]) -> bool {
    let normalized = normalize_name(name);
    suffixes.iter().any(|suffix| {
        let suffix = normalize_name(suffix);
        normalized == suffix
            || normalized
                .strip_suffix(&suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[must_use]
pub(crate) fn owner_for_ip(ip: IpAddr) -> Option<Owner> {
    owner_in_ranges(ip, config::GEOIP_CF, Owner::Cf)
        .or_else(|| owner_in_ranges(ip, config::GEOIP_META, Owner::Meta))
        .or_else(|| owner_in_ranges(ip, config::GEOIP_CFT, Owner::Cft))
        .or_else(|| owner_in_ranges(ip, VERCEL_CIDRS, Owner::Vercel))
}

#[must_use]
pub(crate) fn owner_for_response(wire: &[u8], qtype: u16) -> Option<Owner> {
    let ips = match qtype {
        TYPE_A | TYPE_AAAA => dns::proto::answer_ips(wire, qtype),
        TYPE_HTTPS => dns::proto::https_hint_ips(wire),
        _ => return None,
    };
    let mut owner = None;
    let mut found = false;
    for ip in ips {
        let Some(ip) = ip_from_bytes(&ip) else {
            continue;
        };
        found = true;
        let record_owner = owner_for_ip(ip)?;
        if let Some(current) = owner {
            if current != record_owner {
                return None;
            }
        } else {
            owner = Some(record_owner);
        }
    }
    found.then_some(owner).flatten()
}

#[must_use]
pub(crate) fn ips_for_type(wire: &[u8], qtype: u16) -> Vec<Vec<u8>> {
    dns::proto::answer_ips(wire, qtype)
}

#[must_use]
pub(crate) fn is_blocked(ip: IpAddr) -> bool {
    config::BLOCKED_RANGES.iter().any(|range| {
        if (range.family == 4 && !ip.is_ipv4()) || (range.family == 6 && !ip.is_ipv6()) {
            return false;
        }
        config_cidr(range.address, range.prefix).is_some_and(|cidr| cidr.contains(&ip))
    })
}

#[must_use]
pub(crate) fn blocked_cidrs() -> Vec<Cidr> {
    config::BLOCKED_RANGES
        .iter()
        .filter_map(|range| config_cidr(range.address, range.prefix))
        .collect()
}

#[must_use]
pub(crate) fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [a, b, c, d] => Some(IpAddr::from([*a, *b, *c, *d])),
        bytes if bytes.len() == 16 => {
            let array = <[u8; 16]>::try_from(bytes).ok()?;
            Some(IpAddr::from(array))
        }
        _ => None,
    }
}

fn owner_in_ranges(ip: IpAddr, ranges: &[&str], owner: Owner) -> Option<Owner> {
    ranges
        .iter()
        .filter_map(|range| parse_cidr(range))
        .any(|range| range.contains(&ip))
        .then_some(owner)
}

fn parse_cidr(value: &str) -> Option<Cidr> {
    value.parse().ok()
}

fn config_cidr(address: &str, prefix: u8) -> Option<Cidr> {
    format!("{address}/{prefix}").parse().ok()
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_suffixes_without_partial_labels() {
        assert!(matches_any_suffix("www.example.com.", &["example.com"]));
        assert!(!matches_any_suffix("notexample.com", &["example.com"]));
    }

    #[test]
    fn rejects_mixed_owner_answers() {
        let cf = crate::dns::build_response(
            1,
            "example.com",
            TYPE_A,
            &[vec![1, 1, 1, 1], vec![31, 13, 24, 1]],
            60,
            0x8180,
        );
        let body = match cf {
            Ok(body) => body,
            Err(error) => panic!("test response must build: {error}"),
        };
        assert_eq!(owner_for_response(&body, TYPE_A), None);
    }

    #[test]
    fn classifies_https_from_service_mode_hints() {
        let service = vec![
            0, 1, // priority = ServiceMode
            0, // target = root
            0, 4, // ipv4hint
            0, 4, // length
            1, 1, 1, 1,
        ];
        let body = crate::dns::build_response(1, "example.com", TYPE_HTTPS, &[service], 60, 0x8180);
        let body = match body {
            Ok(body) => body,
            Err(error) => panic!("test HTTPS response must build: {error}"),
        };
        assert_eq!(owner_for_response(&body, TYPE_HTTPS), Some(Owner::Cf));
    }

    #[test]
    fn meta_non_https_negative_responses_are_not_synthesized() {
        use crate::dns::wire::{CLASS_IN, serialize_message};
        use crate::dns::{
            Classification, Header, Message, NegativeKind, Question, build_response,
            classify_response,
        };

        assert!(is_meta_domain("www.facebook.com"));

        let nxdomain = match build_response(7, "www.facebook.com", TYPE_A, &[], 60, 0x8183) {
            Ok(body) => body,
            Err(error) => panic!("NXDOMAIN response must build: {error}"),
        };
        let expected = Question {
            name: "www.facebook.com".to_owned(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        assert_eq!(
            classify_response(&nxdomain, 7, &expected, &[]),
            Classification::Negative(NegativeKind::NxDomain)
        );
        assert!(owner_for_response(&nxdomain, TYPE_A).is_none());
        assert!(ips_for_type(&nxdomain, TYPE_A).is_empty());

        let nodata = Message {
            header: Header {
                id: 7,
                flags: 0x8180,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![expected.clone()],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };
        let nodata = match serialize_message(&nodata) {
            Ok(body) => body,
            Err(error) => panic!("NODATA response must serialize: {error}"),
        };
        assert_eq!(
            classify_response(&nodata, 7, &expected, &[]),
            Classification::Negative(NegativeKind::NoData)
        );
    }
}
