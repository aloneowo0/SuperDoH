use std::collections::BTreeMap;

use serde::Serialize;
use worker::{Response, Result};

use crate::{
    config,
    http::{RuntimeConfig, json_response},
};

#[derive(Serialize)]
struct UpstreamResponse<'a> {
    name: &'a str,
    transport: &'static str,
    ecs: bool,
}

#[derive(Serialize)]
struct RegionResponse<'a> {
    #[serde(rename = "preferredCf")]
    preferred_cf: &'a str,
    #[serde(rename = "preferredCft")]
    preferred_cft: &'a str,
    #[serde(rename = "preferredVrc")]
    preferred_vrc: &'a str,
    remap: &'a [&'a str],
    ech: bool,
    google: bool,
}

#[derive(Serialize)]
struct ConfigResponse<'a> {
    configured: u8,
    upstreams: Vec<UpstreamResponse<'a>>,
    #[serde(rename = "foreignUpstreams")]
    foreign_upstreams: &'a [String],
    #[serde(rename = "upstreamConcurrency")]
    upstream_concurrency: usize,
    #[serde(rename = "fastTimeoutMs")]
    fast_timeout_ms: u32,
    #[serde(rename = "mixTimeoutMs")]
    mix_timeout_ms: u32,
    #[serde(rename = "mixTtl")]
    mix_ttl: u32,
    #[serde(rename = "preferredTtl")]
    preferred_ttl: u32,
    #[serde(rename = "servfailEdeCode")]
    servfail_ede_code: u16,
    #[serde(rename = "cfEchCacheTtlMs")]
    cf_ech_cache_ttl_ms: u32,
    #[serde(rename = "cfEchStaleTtlMs")]
    cf_ech_stale_ttl_ms: u32,
    #[serde(rename = "ecsPrefix4")]
    ecs_prefix4: u8,
    #[serde(rename = "ecsPrefix6")]
    ecs_prefix6: u8,
    #[serde(rename = "blockedCidrs")]
    blocked_cidrs: String,
    #[serde(rename = "logLevel")]
    log_level: &'a str,
    region: Option<&'a str>,
    #[serde(rename = "regionConfig")]
    region_config: BTreeMap<&'a str, RegionResponse<'a>>,
}

/// Serves the complete configuration-wizard contract.
///
/// # Errors
///
/// Returns a Worker error when configuration serialization fails.
pub fn serve(runtime: &RuntimeConfig) -> Result<Response> {
    let region_config = config::REGION_CONFIG
        .iter()
        .map(|region| {
            (
                region.name,
                RegionResponse {
                    preferred_cf: region.preferred_cf,
                    preferred_cft: region.preferred_cft,
                    preferred_vrc: region.preferred_vrc,
                    remap: region.remap,
                    ech: region.ech,
                    google: region.google_enabled,
                },
            )
        })
        .collect();
    let upstreams = runtime.upstreams.iter().map(upstream_response).collect();
    let blocked_cidrs = config::BLOCKED_RANGES
        .iter()
        .map(|cidr| format!("{}/{}", cidr.address, cidr.prefix))
        .collect::<Vec<_>>()
        .join(" ");

    let value = serde_json::to_value(ConfigResponse {
        configured: config::CONFIGURED,
        upstreams,
        foreign_upstreams: &runtime.foreign_upstreams,
        upstream_concurrency: config::UPSTREAM_CONCURRENCY,
        fast_timeout_ms: config::FAST_TIMEOUT_MS,
        mix_timeout_ms: config::MIX_TIMEOUT_MS,
        mix_ttl: config::MIX_TTL,
        preferred_ttl: config::PREFERRED_TTL,
        servfail_ede_code: config::SERVFAIL_EDE_CODE,
        cf_ech_cache_ttl_ms: config::CF_ECH_CACHE_TTL_MS,
        cf_ech_stale_ttl_ms: config::CF_ECH_STALE_TTL_MS,
        ecs_prefix4: config::ECS_PREFIX4,
        ecs_prefix6: config::ECS_PREFIX6,
        blocked_cidrs,
        log_level: config::LOG_LEVEL,
        region: (!config::REGION.is_empty()).then_some(config::REGION),
        region_config,
    })
    .map_err(|error| {
        worker::Error::RustError(format!("failed to serialize config response: {error}"))
    })?;
    json_response(&value, 200)
}

fn upstream_response(upstream: &crate::http::RuntimeUpstream) -> UpstreamResponse<'_> {
    UpstreamResponse {
        name: &upstream.name,
        transport: match upstream.transport {
            crate::http::RuntimeUpstreamTransport::Doh { .. } => "doh",
            crate::http::RuntimeUpstreamTransport::Tcp { .. } => "tcp",
        },
        ecs: upstream.ecs,
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigResponse, upstream_response};
    use crate::http::{RuntimeUpstream, RuntimeUpstreamTransport};

    #[test]
    fn serializes_the_complete_wizard_contract() {
        let value = match serde_json::to_value(ConfigResponse {
            configured: 1,
            upstreams: vec![],
            foreign_upstreams: &[],
            upstream_concurrency: 2,
            fast_timeout_ms: 300,
            mix_timeout_ms: 200,
            mix_ttl: 300,
            preferred_ttl: 60,
            servfail_ede_code: 22,
            cf_ech_cache_ttl_ms: 600_000,
            cf_ech_stale_ttl_ms: 3_600_000,
            ecs_prefix4: 24,
            ecs_prefix6: 56,
            blocked_cidrs: String::new(),
            log_level: "info",
            region: Some("CN"),
            region_config: Default::default(),
        }) {
            Ok(value) => value,
            Err(error) => panic!("config contract must serialize: {error}"),
        };
        for field in [
            "configured",
            "upstreams",
            "foreignUpstreams",
            "upstreamConcurrency",
            "fastTimeoutMs",
            "mixTimeoutMs",
            "mixTtl",
            "preferredTtl",
            "servfailEdeCode",
            "cfEchCacheTtlMs",
            "cfEchStaleTtlMs",
            "ecsPrefix4",
            "ecsPrefix6",
            "blockedCidrs",
            "logLevel",
            "region",
            "regionConfig",
        ] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
    }

    #[test]
    fn exposes_transport_without_endpoint_details() {
        let upstream = RuntimeUpstream {
            name: "custom".to_owned(),
            transport: RuntimeUpstreamTransport::Doh {
                url: "https://user:secret@resolver.example/dns-query?key=secret".to_owned(),
            },
            ecs: true,
        };
        let value = match serde_json::to_value(upstream_response(&upstream)) {
            Ok(value) => value,
            Err(error) => panic!("redacted upstream must serialize: {error}"),
        };

        assert_eq!(value["name"], "custom");
        assert_eq!(value["ecs"], true);
        assert_eq!(value["transport"], "doh");
        assert!(value.get("url").is_none());
        assert!(!value.to_string().contains("secret"));
    }
}
