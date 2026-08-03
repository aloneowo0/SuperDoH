use std::cell::RefCell;

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::{config, dns};

use super::{
    ParsedQuery, PolicyError, RequestCtx, RuntimeUpstream,
    classify::Owner,
    fast_query,
    logger::{self, LogLevel},
    response,
    upstream::{self, UpstreamTrace},
};

#[derive(Clone)]
struct CachedEch {
    fetched_at_ms: f64,
    value: Vec<u8>,
}

const MAX_ECH_CONFIG_LIST_LEN: usize = 16 * 1024;
const ECH_CONFIG_VERSION: u16 = 0xfe0d;

thread_local! {
    static CF_ECH_CACHE: RefCell<Option<CachedEch>> = const { RefCell::new(None) };
}

pub(crate) async fn inject(
    original: &[u8],
    query: &ParsedQuery,
    owner: Owner,
    client_ip: Option<std::net::IpAddr>,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
    ctx: &mut RequestCtx,
) -> Result<Vec<u8>, PolicyError> {
    let ech = match owner {
        Owner::Cf => fetch_cf_ech(query, client_ip, runtime_upstreams, trace, ctx).await,
        Owner::Meta => meta_ech_config(&query.question.name),
        Owner::Cft | Owner::Vercel | Owner::Google => None,
    };
    let Some(ech) = ech else {
        return Ok(original.to_vec());
    };
    let Some(updated) = inject_config(original, &ech)? else {
        logger::log_event(
            ctx,
            LogLevel::Debug,
            "ech_skipped",
            serde_json::json!({"owner": owner.label(), "reason": "no_safe_https_rr"}),
        );
        return Ok(original.to_vec());
    };
    ctx.optimization_applied = true;
    logger::log_event(
        ctx,
        LogLevel::Info,
        "ech_injected",
        serde_json::json!({"owner": owner.label()}),
    );
    Ok(updated)
}

async fn fetch_cf_ech(
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
    ctx: &mut RequestCtx,
) -> Option<Vec<u8>> {
    let now = logger::now_ms();
    if let Some(value) = cached_value(now, false) {
        return Some(value);
    }
    let wire = upstream::build_query("cloudflare-ech.com", dns::wire::TYPE_HTTPS, query.id).ok()?;
    let ech_query = ParsedQuery {
        id: query.id,
        flags: 0x0100,
        question: dns::Question {
            name: "cloudflare-ech.com".to_owned(),
            qtype: dns::wire::TYPE_HTTPS,
            qclass: dns::wire::CLASS_IN,
        },
        client_sent_ecs: false,
        edns: None,
    };
    let result = fast_query(
        &wire,
        &ech_query,
        client_ip,
        false,
        runtime_upstreams,
        trace,
        |_| true,
    )
    .await;
    if let Some(result) = result
        && let Some(value) = ech_from_response(&result.body)
    {
        CF_ECH_CACHE.with(|cache| {
            *cache.borrow_mut() = Some(CachedEch {
                fetched_at_ms: now,
                value: value.clone(),
            });
        });
        return Some(value);
    }
    let stale = cached_value(now, true);
    if stale.is_some() {
        logger::log_event(
            ctx,
            LogLevel::Warn,
            "fallback",
            serde_json::json!({"stage": "cf_ech", "reason": "using_stale_ech"}),
        );
    }
    stale
}

fn cached_value(now: f64, stale: bool) -> Option<Vec<u8>> {
    let age_limit = if stale {
        f64::from(crate::config::CF_ECH_STALE_TTL_MS)
    } else {
        f64::from(crate::config::CF_ECH_CACHE_TTL_MS)
    };
    CF_ECH_CACHE.with(|cache| {
        cache.borrow().as_ref().and_then(|cached| {
            ((now - cached.fetched_at_ms) >= 0.0 && (now - cached.fetched_at_ms) < age_limit)
                .then(|| cached.value.clone())
        })
    })
}

fn meta_ech_config(name: &str) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    config::META_ECH_MAP
        .iter()
        .filter(|entry| meta_pattern_matches(&name, entry.domain_pattern))
        .max_by_key(|entry| entry.domain_pattern.len())
        .and_then(|entry| STANDARD.decode(entry.config_b64).ok())
        .filter(|value| validate_ech_config_list(value))
}

fn meta_pattern_matches(name: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'));
    }
    name == pattern
}

fn ech_from_response(wire: &[u8]) -> Option<Vec<u8>> {
    let message = dns::parse_message(wire).ok()?;
    message
        .answers
        .iter()
        .filter(|record| record.rr_type == dns::wire::TYPE_HTTPS)
        .find_map(|record| ech_param(&record.rdata))
}

fn ech_param(rdata: &[u8]) -> Option<Vec<u8>> {
    dns::svcb::parse_rdata(rdata)
        .ok()?
        .param(dns::svcb::PARAM_ECH)
        .map(ToOwned::to_owned)
        .filter(|value| validate_ech_config_list(value))
}

fn validate_ech_config_list(value: &[u8]) -> bool {
    if value.len() < 2 || value.len() > MAX_ECH_CONFIG_LIST_LEN {
        return false;
    }
    let list_len = usize::from(u16::from_be_bytes([value[0], value[1]]));
    if list_len == 0 || list_len != value.len() - 2 {
        return false;
    }
    let mut offset = 2;
    while offset < value.len() {
        if value.len() - offset < 4 {
            return false;
        }
        let version = u16::from_be_bytes([value[offset], value[offset + 1]]);
        let config_len = usize::from(u16::from_be_bytes([value[offset + 2], value[offset + 3]]));
        offset += 4;
        if version != ECH_CONFIG_VERSION || config_len == 0 || value.len() - offset < config_len {
            return false;
        }
        offset += config_len;
    }
    offset == value.len()
}

fn inject_config(original: &[u8], ech: &[u8]) -> Result<Option<Vec<u8>>, PolicyError> {
    if !validate_ech_config_list(ech) {
        return Ok(None);
    }
    let mut message = dns::parse_message(original)?;
    if message.header.flags & 0x020f != 0 {
        return Ok(None);
    }
    let mut changed = false;
    let mut modified_owners = Vec::new();
    for record in &mut message.answers {
        if record.rr_type != dns::wire::TYPE_HTTPS {
            continue;
        }
        if let Some(updated) = inject_service_record(&record.rdata, ech) {
            record.rdata = updated;
            if !modified_owners
                .iter()
                .any(|owner: &String| owner == &record.name)
            {
                modified_owners.push(record.name.clone());
            }
            changed = true;
        }
    }
    if !changed {
        return Ok(None);
    }
    for owner in modified_owners {
        response::clear_authentication(&mut message, &owner, dns::wire::TYPE_HTTPS);
    }
    response::serialize_response(&message).map(Some)
}

fn inject_service_record(rdata: &[u8], ech: &[u8]) -> Option<Vec<u8>> {
    dns::svcb::replace_ech(rdata, ech).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_record(priority: u16, params: &[(u16, &[u8])]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&priority.to_be_bytes());
        output.push(0);
        for (key, value) in params {
            output.extend_from_slice(&key.to_be_bytes());
            let length = match u16::try_from(value.len()) {
                Ok(length) => length,
                Err(_) => panic!("test SVC parameter exceeds wire limit"),
            };
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(value);
        }
        output
    }

    #[test]
    fn does_not_add_parameters_to_alias_mode() {
        assert_eq!(
            inject_service_record(&service_record(0, &[]), &[1, 2]),
            None
        );
    }

    #[test]
    fn replaces_ech_in_service_mode() {
        let record = service_record(1, &[(1, b"\x02h2"), (5, b"old")]);
        let ech = valid_ech_config_list();
        let updated = inject_service_record(&record, &ech);
        let updated = match updated {
            Some(updated) => updated,
            None => panic!("service-mode record must be modified"),
        };
        assert_eq!(ech_param(&updated), Some(ech));
    }

    fn valid_ech_config_list() -> Vec<u8> {
        vec![0, 5, 0xfe, 0x0d, 0, 1, 1]
    }

    #[test]
    fn validates_well_framed_ech_config_lists() {
        assert!(validate_ech_config_list(&valid_ech_config_list()));
    }

    #[test]
    fn rejects_malformed_ech_config_lists() {
        assert!(!validate_ech_config_list(&[0, 4, 0xfe, 0x0d, 0, 1, 1]));
        assert!(!validate_ech_config_list(&[0, 5, 0xfe, 0x0d, 0, 2, 1]));
        assert!(!validate_ech_config_list(&[0, 5, 0xfe, 0x0e, 0, 1, 1]));
        assert!(!validate_ech_config_list(&[0, 0]));
    }

    #[test]
    fn skips_truncated_https_responses() {
        let message = dns::Message {
            header: dns::Header {
                id: 1,
                flags: 0x8380,
                qd_count: 0,
                an_count: 1,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![],
            answers: vec![dns::ResourceRecord {
                name: "example.com".to_owned(),
                rr_type: dns::wire::TYPE_HTTPS,
                class: dns::wire::CLASS_IN,
                ttl: 60,
                rdata: service_record(1, &[]),
            }],
            authorities: vec![],
            additionals: vec![],
        };
        let wire = match crate::dns::wire::serialize_message(&message) {
            Ok(value) => value,
            Err(error) => panic!("truncated test response must serialize: {error}"),
        };
        assert_eq!(inject_config(&wire, &valid_ech_config_list()), Ok(None));
    }

    #[test]
    fn looks_up_only_mapped_meta_domains() {
        let mapped = meta_ech_config("scontent.xx.fbcdn.net.");
        assert!(mapped.is_some_and(|value| !value.is_empty()));
        assert!(meta_ech_config("www.facebook.com").is_none());
        assert!(meta_pattern_matches("edge.xx.fbcdn.net", "*.xx.fbcdn.net"));
        assert!(!meta_pattern_matches("xx.fbcdn.net", "*.xx.fbcdn.net"));
    }
}
