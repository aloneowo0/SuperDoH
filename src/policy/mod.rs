//! DNS policy orchestration for the Worker runtime.

use crate::dns::wire::{CLASS_IN, TYPE_A, TYPE_AAAA};
use crate::{
    config,
    dns::{self, Classification, Question},
    http::RuntimeUpstream,
};
use core::fmt;

mod classify;
mod ech;
mod google;
mod https;
pub mod logger;
mod meta;
mod prefer;
mod remap;
mod response;
#[expect(
    clippy::drop_non_drop,
    reason = "the cancellation branch releases a pinned operation before its abort guard drops"
)]
mod upstream;

pub use logger::{LogEvent, LogLevel};

/// Per-request policy trace. It is intended for structured Worker logs only.
#[derive(Debug, Clone, Default)]
pub struct RequestCtx {
    pub request_id: String,
    pub started_at_ms: f64,
    pub qname: String,
    pub qtype: u16,
    pub client_country: String,
    pub upstreams: Vec<String>,
    pub owner: Option<String>,
    pub optimization_applied: bool,
    pub events: Vec<LogEvent>,
}

/// Lightweight failures produced before a DNS response can be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    InvalidQuery(&'static str),
    Dns(String),
    Transport(String),
    Build(&'static str),
    Cancelled,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQuery(message) | Self::Build(message) => formatter.write_str(message),
            Self::Dns(message) | Self::Transport(message) => formatter.write_str(message),
            Self::Cancelled => formatter.write_str("upstream query cancelled"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<dns::DnsError> for PolicyError {
    fn from(error: dns::DnsError) -> Self {
        Self::Dns(error.to_string())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedQuery {
    id: u16,
    flags: u16,
    question: Question,
    client_sent_ecs: bool,
    edns: Option<dns::OptRecord>,
}

/// Resolves a wire-format DNS query through the complete Worker policy pipeline.
///
/// This API is asynchronous because Worker `Fetch` is promise-based; callers must await the
/// returned response bytes.
///
/// # Errors
///
/// Returns an error only for malformed input or a failure to construct a DNS response.
pub async fn process_query(
    query_body: &[u8],
    client_ip: Option<&str>,
    client_country: &str,
    ctx: &mut RequestCtx,
) -> Result<Vec<u8>, PolicyError> {
    process_query_inner(query_body, client_ip, client_country, None, ctx).await
}

/// Resolves a wire-format DNS query using the request's complete runtime upstream set.
///
/// # Errors
///
/// Returns an error only for malformed input or a failure to construct a DNS response.
pub async fn process_query_with_upstreams(
    query_body: &[u8],
    client_ip: Option<&str>,
    client_country: &str,
    runtime_upstreams: &[RuntimeUpstream],
    ctx: &mut RequestCtx,
) -> Result<Vec<u8>, PolicyError> {
    process_query_inner(
        query_body,
        client_ip,
        client_country,
        Some(runtime_upstreams),
        ctx,
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixed public entry intentionally makes policy ordering auditable"
)]
async fn process_query_inner(
    query_body: &[u8],
    client_ip: Option<&str>,
    client_country: &str,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    ctx: &mut RequestCtx,
) -> Result<Vec<u8>, PolicyError> {
    begin_request(ctx, client_country);
    let query = match parse_query(query_body) {
        Ok(query) => query,
        Err(error) => {
            logger::log_event(
                ctx,
                LogLevel::Warn,
                "invalid_query",
                serde_json::json!({"error": error.to_string()}),
            );
            return Err(error);
        }
    };
    ctx.qname.clone_from(&query.question.name);
    ctx.qtype = query.question.qtype;
    logger::log_event(
        ctx,
        LogLevel::Info,
        "request_start",
        serde_json::json!({"country": client_country}),
    );

    if is_doh_canary(&query) {
        let body = response::nxdomain(&query, config::PREFERRED_TTL)?;
        return Ok(finish(ctx, body, "canary_nxdomain"));
    }

    let supplied_client_ip = client_ip;
    let client_ip = supplied_client_ip.and_then(|value| value.parse().ok());
    if supplied_client_ip.is_some() && client_ip.is_none() {
        logger::log_event(
            ctx,
            LogLevel::Warn,
            "client_ip_ignored",
            serde_json::json!({}),
        );
    }
    let region = classify::region_for(client_country);
    if let Some(region) = region
        && remap::blocks_aaaa(&query, region)
    {
        let body = response::nodata(&query, config::MIX_TTL)?;
        return Ok(finish(ctx, body, "remap_nodata"));
    }

    let trace = upstream::UpstreamTrace::default();
    let primary = fast_query(
        query_body,
        &query,
        client_ip,
        false,
        runtime_upstreams,
        &trace,
        |_| true,
    )
    .await;
    update_upstreams(ctx, &trace);
    let Some(primary) = primary else {
        let body = response::servfail(&query, "No reachable upstream")?;
        return Ok(finish(ctx, body, "servfail"));
    };
    if primary.classification != Classification::Positive {
        if primary.classification == Classification::Negative(dns::NegativeKind::NoData)
            && query.question.qtype == dns::wire::TYPE_HTTPS
            && let Some(region) = region
            && let Some(body) = https::synthesize_nodata(
                &primary.body,
                &query,
                region,
                client_ip,
                runtime_upstreams,
                &trace,
                ctx,
            )
            .await?
        {
            update_upstreams(ctx, &trace);
            let client_ecs = client_ecs(&query)?;
            let body = dns::normalize_response(&body, client_ecs.as_ref())?;
            return Ok(finish(ctx, body, "completed"));
        }
        return Ok(finish(ctx, primary.body, "negative"));
    }
    let Some(region) = region else {
        return Ok(finish(ctx, primary.body, "unconfigured_region"));
    };

    let (owner, source) =
        match classify::domain_match(&query.question.name, query.question.qtype, region) {
            Some(classify::DomainMatch::Remap) => (classify::Owner::Cf, "domain_remap"),
            Some(classify::DomainMatch::Meta) => (classify::Owner::Meta, "domain_meta"),
            Some(classify::DomainMatch::Google(proxy)) => {
                let body = google::merge(&primary.body, &query, proxy, ctx)?;
                ctx.owner = Some(classify::Owner::Google.label().to_owned());
                logger::log_event(
                    ctx,
                    LogLevel::Info,
                    "owner_classified",
                    serde_json::json!({"owner": "GOOGLE", "source": "domain_google"}),
                );
                return Ok(finish(ctx, body, "completed"));
            }
            None => {
                let Some(owner) = classify::owner_for_response(&primary.body, query.question.qtype)
                else {
                    return Ok(finish(ctx, primary.body, "unclassified"));
                };
                let source = if query.question.qtype == dns::wire::TYPE_HTTPS {
                    "response_hint"
                } else {
                    "response_ip"
                };
                (owner, source)
            }
        };
    ctx.owner = Some(owner.label().to_owned());
    logger::log_event(
        ctx,
        LogLevel::Info,
        "owner_classified",
        serde_json::json!({"owner": owner.label(), "source": source}),
    );

    let body = match owner {
        classify::Owner::Cf => {
            prefer::replace(
                &primary.body,
                &query,
                region.preferred_cf,
                owner,
                client_ip,
                runtime_upstreams,
                &trace,
                ctx,
            )
            .await?
        }
        classify::Owner::Cft => {
            prefer::replace(
                &primary.body,
                &query,
                region.preferred_cft,
                owner,
                client_ip,
                runtime_upstreams,
                &trace,
                ctx,
            )
            .await?
        }
        classify::Owner::Vercel => {
            prefer::replace(
                &primary.body,
                &query,
                region.preferred_vrc,
                owner,
                client_ip,
                runtime_upstreams,
                &trace,
                ctx,
            )
            .await?
        }
        classify::Owner::Meta => {
            meta::enhance(
                &primary.body,
                query_body,
                &query,
                client_ip,
                runtime_upstreams,
                &trace,
                ctx,
            )
            .await?
        }
        classify::Owner::Google => primary.body,
    };
    update_upstreams(ctx, &trace);

    let (remove_ipv4_hint, remove_ipv6_hint) =
        hint_removal_policy(owner, source, region, query.question.qtype);
    let body = if let Some(updated) =
        response::normalize_https_hints(&body, remove_ipv4_hint, remove_ipv6_hint)?
    {
        ctx.optimization_applied = true;
        logger::log_event(
            ctx,
            LogLevel::Info,
            "https_hints_removed",
            serde_json::json!({
                "owner": owner.label(),
                "ipv4": remove_ipv4_hint,
                "ipv6": remove_ipv6_hint,
            }),
        );
        updated
    } else {
        body
    };

    let body = if region.ech && matches!(owner, classify::Owner::Cf | classify::Owner::Meta) {
        let output = ech::inject(
            &body,
            &query,
            ech::InjectionMode::Existing(owner),
            client_ip,
            runtime_upstreams,
            &trace,
            ctx,
        )
        .await?;
        update_upstreams(ctx, &trace);
        output
    } else {
        body
    };
    let client_ecs = client_ecs(&query)?;
    let body = dns::normalize_response(&body, client_ecs.as_ref())?;
    Ok(finish(ctx, body, "completed"))
}

fn hint_removal_policy(
    owner: classify::Owner,
    classification_source: &str,
    region: &config::RegionConfig,
    qtype: u16,
) -> (bool, bool) {
    if qtype != dns::wire::TYPE_HTTPS {
        return (false, false);
    }

    match owner {
        classify::Owner::Cf if classification_source == "domain_remap" => {
            (!region.preferred_cf.is_empty(), true)
        }
        classify::Owner::Cf => {
            let enabled = !region.preferred_cf.is_empty();
            (enabled, enabled)
        }
        classify::Owner::Cft => {
            let enabled = !region.preferred_cft.is_empty();
            (enabled, enabled)
        }
        classify::Owner::Vercel => {
            let enabled = !region.preferred_vrc.is_empty();
            (enabled, enabled)
        }
        classify::Owner::Meta => (true, true),
        classify::Owner::Google => (false, false),
    }
}

async fn fast_query<F>(
    body: &[u8],
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    foreign_only: bool,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &upstream::UpstreamTrace,
    accept: F,
) -> Option<crate::algo::QueryOutcome>
where
    F: Fn(&crate::algo::QueryOutcome) -> bool,
{
    upstream::fast_query(
        body,
        query,
        client_ip,
        foreign_only,
        runtime_upstreams,
        trace,
        accept,
    )
    .await
}

async fn mix_query(
    body: &[u8],
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &upstream::UpstreamTrace,
) -> Vec<Vec<u8>> {
    upstream::mix_query(body, query, client_ip, runtime_upstreams, trace).await
}

fn begin_request(ctx: &mut RequestCtx, client_country: &str) {
    if ctx.request_id.is_empty() {
        ctx.request_id = logger::request_id();
    }
    ctx.started_at_ms = logger::now_ms();
    client_country.clone_into(&mut ctx.client_country);
    ctx.events.clear();
    ctx.upstreams.clear();
    ctx.owner = None;
    ctx.optimization_applied = false;
}

fn parse_query(wire: &[u8]) -> Result<ParsedQuery, PolicyError> {
    let message = dns::parse_message(wire)?;
    if message.header.flags & 0x8000 != 0 {
        return Err(PolicyError::InvalidQuery("DNS query has QR set"));
    }
    if message.header.qd_count != 1 || message.questions.len() != 1 {
        return Err(PolicyError::InvalidQuery(
            "DNS query must contain one question",
        ));
    }
    let mut client_sent_ecs = false;
    let mut edns = None;
    let mut has_opt = false;
    for record in &message.additionals {
        if record.rr_type == dns::wire::TYPE_OPT {
            if has_opt {
                return Err(PolicyError::InvalidQuery(
                    "DNS query has multiple OPT records",
                ));
            }
            has_opt = true;
            let opt = dns::parse_opt(record)?;
            client_sent_ecs = dns::parse_ecs(record)?.is_some();
            edns = Some(opt);
        }
    }
    let question = message
        .questions
        .into_iter()
        .next()
        .ok_or(PolicyError::InvalidQuery("DNS query has no question"))?;
    if question.qclass != CLASS_IN {
        return Err(PolicyError::InvalidQuery("DNS query class is not IN"));
    }
    Ok(ParsedQuery {
        id: message.header.id,
        flags: message.header.flags,
        question,
        client_sent_ecs,
        edns,
    })
}

fn client_ecs(query: &ParsedQuery) -> Result<Option<dns::Ecs>, PolicyError> {
    let Some(opt) = &query.edns else {
        return Ok(None);
    };
    dns::parse_ecs_option(opt).map_err(PolicyError::from)
}

fn is_doh_canary(query: &ParsedQuery) -> bool {
    matches!(query.question.qtype, TYPE_A | TYPE_AAAA)
        && query
            .question
            .name
            .trim_end_matches('.')
            .eq_ignore_ascii_case("use-application-dns.net")
}

fn update_upstreams(ctx: &mut RequestCtx, trace: &upstream::UpstreamTrace) {
    for upstream in trace.names() {
        if !ctx.upstreams.iter().any(|existing| existing == &upstream) {
            ctx.upstreams.push(upstream);
        }
    }
}

fn finish(ctx: &mut RequestCtx, body: Vec<u8>, result: &str) -> Vec<u8> {
    logger::request_end(ctx, result);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let encoded = match dns::encode_name(name) {
            Ok(encoded) => encoded,
            Err(error) => panic!("test DNS name must encode: {error}"),
        };
        let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        wire.extend_from_slice(&encoded);
        wire.extend_from_slice(&qtype.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        wire
    }

    #[test]
    fn parses_a_single_in_question() {
        let parsed = parse_query(&query("example.com", TYPE_A));
        assert!(parsed.is_ok());
        assert_eq!(parsed.map(|value| value.id), Ok(1));
    }

    #[test]
    fn recognizes_the_doh_canary() {
        let parsed = parse_query(&query("use-application-dns.net", TYPE_A));
        assert!(parsed.is_ok());
        assert!(parsed.is_ok_and(|value| is_doh_canary(&value)));
    }
}
