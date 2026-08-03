use serde::Serialize;
use worker::{Response, Result};

use crate::{
    config,
    http::{RuntimeConfig, json_response},
};

#[derive(Serialize)]
struct HealthResponse<'a> {
    status: &'static str,
    configured: u8,
    upstreams: Vec<&'a str>,
    #[serde(rename = "hardTimeoutMs")]
    hard_timeout_ms: u32,
    #[serde(rename = "ecsProtectMs")]
    ecs_protect_ms: u32,
    region: Option<&'a str>,
    #[serde(rename = "regionConfig")]
    region_config: Option<serde_json::Value>,
    #[serde(rename = "echEnabled")]
    ech_enabled: bool,
}

/// Serves the public health and active-configuration summary.
///
/// # Errors
///
/// Returns a Worker error when the region summary cannot be serialized.
pub fn serve(runtime: &RuntimeConfig) -> Result<Response> {
    let region_config = serde_json::to_value(
        config::REGION_CONFIG
            .iter()
            .map(|region| {
                (
                    region.name,
                    serde_json::json!({
                        "preferredCf": region.preferred_cf,
                        "preferredCft": region.preferred_cft,
                        "preferredVrc": region.preferred_vrc,
                        "remap": region.remap,
                        "ech": region.ech,
                        "google": region.google_enabled,
                    }),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>(),
    )
    .map_err(|error| {
        worker::Error::RustError(format!("failed to serialize region health: {error}"))
    })?;
    let response = HealthResponse {
        status: "ok",
        configured: config::CONFIGURED,
        upstreams: std::iter::once(config::AUTO_PROVIDER)
            .chain(
                runtime
                    .upstreams
                    .iter()
                    .map(|upstream| upstream.name.as_str()),
            )
            .collect(),
        hard_timeout_ms: config::HARD_TIMEOUT_MS,
        ecs_protect_ms: config::ECS_PROTECT_MS,
        region: (!config::REGION.is_empty()).then_some(config::REGION),
        region_config: (!config::REGION_CONFIG.is_empty()).then_some(region_config),
        ech_enabled: config::REGION_CONFIG.iter().any(|region| region.ech),
    };
    json_response(&response, 200)
}
