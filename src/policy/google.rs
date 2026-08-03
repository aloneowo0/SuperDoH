use std::collections::HashSet;

use crate::config;

use super::{
    ParsedQuery, PolicyError, RequestCtx, classify,
    logger::{self, LogLevel},
    response,
};

pub(crate) fn merge(
    original: &[u8],
    query: &ParsedQuery,
    proxy: &config::GoogleProxy,
    ctx: &mut RequestCtx,
) -> Result<Vec<u8>, PolicyError> {
    if query.question.qtype != crate::dns::wire::TYPE_A {
        return Ok(original.to_vec());
    }
    let mut ips = Vec::new();
    let mut seen = HashSet::new();
    for value in proxy.ips {
        let Some(ip) = parse_ipv4(value) else {
            continue;
        };
        if seen.insert(ip.clone()) {
            ips.push(ip);
        }
    }
    let proxy_count = ips.len();
    for ip in classify::ips_for_type(original, crate::dns::wire::TYPE_A) {
        if seen.insert(ip.clone()) {
            ips.push(ip);
        }
    }
    if proxy_count == 0 {
        return Ok(original.to_vec());
    }
    let output = response::replace_ips(original, query, &ips, crate::config::MIX_TTL)?;
    ctx.optimization_applied = true;
    logger::log_event(
        ctx,
        LogLevel::Info,
        "google_proxy_merged",
        serde_json::json!({
            "proxyCount": proxy_count,
            "totalCount": ips.len(),
        }),
    );
    Ok(output)
}

fn parse_ipv4(value: &str) -> Option<Vec<u8>> {
    let octets = value.parse::<std::net::Ipv4Addr>().ok()?.octets().to_vec();
    Some(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_proxy_addresses() {
        assert_eq!(parse_ipv4("192.0.2.1"), Some(vec![192, 0, 2, 1]));
        assert_eq!(parse_ipv4("not-an-ip"), None);
    }
}
