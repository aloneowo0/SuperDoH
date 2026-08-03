use std::collections::HashSet;

use crate::{config, dns};

use super::{
    ParsedQuery, PolicyError, RequestCtx, RuntimeUpstream,
    classify::{self, Owner},
    logger::{self, LogLevel},
    mix_query, response,
    upstream::UpstreamTrace,
};

const EXACT_ROUTES: &[(&str, [u8; 4])] = &[
    ("facebook.com", [57, 144, 44, 1]),
    ("www.facebook.com", [57, 144, 44, 1]),
    ("m.facebook.com", [57, 144, 44, 1]),
    ("b-graph.facebook.com", [57, 144, 44, 1]),
    ("fbsbx.com", [57, 144, 44, 1]),
    ("instagram.com", [57, 144, 44, 34]),
    ("www.instagram.com", [57, 144, 44, 34]),
    ("i.instagram.com", [57, 144, 44, 192]),
    ("lookaside.facebook.com", [57, 144, 44, 128]),
    ("connect.facebook.net", [57, 144, 44, 128]),
    ("graph.facebook.com", [157, 240, 31, 16]),
    ("edge-mqtt.facebook.com", [157, 240, 31, 7]),
    ("messenger.com", [57, 144, 44, 141]),
    ("www.messenger.com", [57, 144, 44, 141]),
    ("threads.net", [57, 144, 44, 192]),
    ("www.threads.net", [57, 144, 44, 192]),
    ("meta.com", [57, 144, 44, 141]),
    ("whatsapp.com", [57, 144, 45, 32]),
    ("web.whatsapp.com", [57, 144, 45, 32]),
    ("oculus.com", [57, 144, 45, 141]),
    ("thefacebook.com", [57, 144, 44, 141]),
];

const WILDCARD_ROUTES: &[(&str, [u8; 4])] = &[
    ("fbcdn.net", [57, 144, 44, 128]),
    ("xx.fbcdn.net", [57, 144, 44, 128]),
    ("cdninstagram.com", [57, 144, 44, 192]),
    ("facebook.com", [57, 144, 44, 141]),
    ("fb.com", [57, 144, 44, 141]),
    ("whatsapp.com", [57, 144, 45, 32]),
    ("whatsapp.net", [57, 144, 45, 32]),
    ("fbsbx.com", [57, 144, 44, 128]),
];

pub(crate) async fn enhance(
    original: &[u8],
    query_body: &[u8],
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
    ctx: &mut RequestCtx,
) -> Result<Vec<u8>, PolicyError> {
    if !matches!(
        query.question.qtype,
        dns::wire::TYPE_A | dns::wire::TYPE_AAAA
    ) {
        return Ok(original.to_vec());
    }

    let mut candidates = classify::ips_for_type(original, query.question.qtype);
    let primary_count = candidates.len();
    candidates.extend(static_route(&query.question.name, query.question.qtype));
    let static_count = candidates.len().saturating_sub(primary_count);
    candidates.extend(mix_query(query_body, query, client_ip, runtime_upstreams, trace).await);
    let candidates_before_filter = candidates.len();
    let candidates = filter_candidates(candidates, query.question.qtype);
    if candidates.is_empty() {
        logger::log_event(
            ctx,
            LogLevel::Warn,
            "meta_unreachable",
            serde_json::json!({"candidateCount": candidates_before_filter}),
        );
        return response::servfail(query, "No reachable Meta IP");
    }
    let output = response::replace_ips(original, query, &candidates, config::MIX_TTL)?;
    ctx.optimization_applied = true;
    logger::log_event(
        ctx,
        LogLevel::Info,
        "meta_merged",
        serde_json::json!({
            "primaryCount": primary_count,
            "staticCount": static_count,
            "candidateCount": candidates_before_filter,
            "reachableCount": candidates.len(),
        }),
    );
    Ok(output)
}

fn static_route(name: &str, qtype: u16) -> Vec<Vec<u8>> {
    if qtype != dns::wire::TYPE_A {
        return Vec::new();
    }
    let normalized = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some((_, address)) = EXACT_ROUTES.iter().find(|(route, _)| *route == normalized) {
        return vec![address.to_vec()];
    }
    WILDCARD_ROUTES
        .iter()
        .find(|(route, _)| {
            normalized == *route
                || normalized
                    .strip_suffix(route)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
        .map_or_else(Vec::new, |(_, address)| vec![address.to_vec()])
}

fn filter_candidates(candidates: Vec<Vec<u8>>, qtype: u16) -> Vec<Vec<u8>> {
    let expected_length = match qtype {
        dns::wire::TYPE_A => 4,
        dns::wire::TYPE_AAAA => 16,
        _ => return Vec::new(),
    };
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|ip| ip.len() == expected_length)
        .filter(|ip| seen.insert(ip.clone()))
        .filter(|ip| {
            classify::ip_from_bytes(ip).is_some_and(|address| {
                classify::owner_for_ip(address) == Some(Owner::Meta)
                    && !classify::is_blocked(address)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_only_a_records_statically() {
        assert_eq!(
            static_route("www.facebook.com", dns::wire::TYPE_A),
            vec![vec![57, 144, 44, 1]]
        );
        assert!(static_route("www.facebook.com", dns::wire::TYPE_AAAA).is_empty());
    }

    #[test]
    fn removes_non_meta_addresses() {
        let filtered = filter_candidates(
            vec![
                vec![57, 144, 44, 1],
                vec![192, 0, 2, 1],
                vec![57, 144, 44, 1],
            ],
            dns::wire::TYPE_A,
        );
        assert_eq!(filtered, vec![vec![57, 144, 44, 1]]);
    }
}
