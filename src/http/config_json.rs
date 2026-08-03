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
    url: &'static str,
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
    #[serde(rename = "autoConcurrency")]
    auto_concurrency: usize,
    #[serde(rename = "ecsProtectMs")]
    ecs_protect_ms: u32,
    #[serde(rename = "hardTimeoutMs")]
    hard_timeout_ms: u32,
    #[serde(rename = "metaHardTimeoutMs")]
    meta_hard_timeout_ms: u32,
    #[serde(rename = "metaCollectWindowMs")]
    meta_collect_window_ms: u32,
    #[serde(rename = "metaMaxIps")]
    meta_max_ips: usize,
    #[serde(rename = "preferredTimeoutMs")]
    preferred_timeout_ms: u32,
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
        auto_concurrency: config::AUTO_CONCURRENCY,
        ecs_protect_ms: config::ECS_PROTECT_MS,
        hard_timeout_ms: config::HARD_TIMEOUT_MS,
        meta_hard_timeout_ms: config::META_HARD_TIMEOUT_MS,
        meta_collect_window_ms: config::META_COLLECT_WINDOW_MS,
        meta_max_ips: config::META_MAX_IPS,
        preferred_timeout_ms: config::PREFERRED_TIMEOUT_MS,
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
        url: "",
        ecs: upstream.ecs,
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigResponse, upstream_response};
    use crate::http::RuntimeUpstream;

    #[test]
    fn serializes_the_complete_wizard_contract() {
        let value = match serde_json::to_value(ConfigResponse {
            configured: 1,
            upstreams: vec![],
            foreign_upstreams: &[],
            auto_concurrency: 6,
            ecs_protect_ms: 20,
            hard_timeout_ms: 800,
            meta_hard_timeout_ms: 800,
            meta_collect_window_ms: 50,
            meta_max_ips: 4,
            preferred_timeout_ms: 300,
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
            "autoConcurrency",
            "ecsProtectMs",
            "hardTimeoutMs",
            "metaHardTimeoutMs",
            "metaCollectWindowMs",
            "metaMaxIps",
            "preferredTimeoutMs",
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
    fn redacts_runtime_upstream_urls() {
        let upstream = RuntimeUpstream {
            name: "custom".to_owned(),
            url: "https://user:secret@resolver.example/dns-query?key=secret".to_owned(),
            ecs: true,
        };
        let value = match serde_json::to_value(upstream_response(&upstream)) {
            Ok(value) => value,
            Err(error) => panic!("redacted upstream must serialize: {error}"),
        };

        assert_eq!(value["name"], "custom");
        assert_eq!(value["ecs"], true);
        assert_eq!(value["url"], "");
        assert!(!value.to_string().contains("secret"));
    }
}
