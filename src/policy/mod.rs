//! DNS policy orchestration for the Worker runtime.

use core::fmt;
use core::time::Duration;

use futures_util::{
    future::{Either, LocalBoxFuture, select},
    pin_mut,
};
use worker::{AbortController, Fetch, Headers, Method, Request, RequestInit};

use crate::dns::wire::{CLASS_IN, TYPE_A, TYPE_AAAA};
use crate::{
    algo::{self, DeadlineTimer, QueryOutcome, Upstream, fast::FastOptions, mix::MixOptions},
    config,
    dns::{self, Classification, Question},
    http::RuntimeUpstream,
};

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

#[derive(Clone)]
struct RuntimeWorkerUpstream<'a> {
    config: &'a RuntimeUpstream,
    expected: Question,
    query_id: u16,
    client_ip: Option<std::net::IpAddr>,
    client_sent_ecs: bool,
    blocked: Vec<dns::Cidr>,
}

impl<'a> RuntimeWorkerUpstream<'a> {
    fn new(
        config: &'a RuntimeUpstream,
        query: &ParsedQuery,
        client_ip: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            config,
            expected: query.question.clone(),
            query_id: query.id,
            client_ip,
            client_sent_ecs: query.client_sent_ecs,
            blocked: classify::blocked_cidrs(),
        }
    }
}

impl Upstream for RuntimeWorkerUpstream<'_> {
    type Error = PolicyError;
    type Query<'a>
        = LocalBoxFuture<'a, Result<QueryOutcome, Self::Error>>
    where
        Self: 'a;

    fn query<'a>(
        &'a self,
        body: &'a [u8],
        cancellation: algo::CancellationToken,
    ) -> Self::Query<'a> {
        let client_ecs = if self.client_sent_ecs {
            dns::query_ecs(body).map_err(PolicyError::from)
        } else {
            Ok(None)
        };
        let body = prepare_runtime_upstream_query(body, self.config.ecs, self.client_ip);
        let expected = self.expected.clone();
        let query_id = self.query_id;
        let blocked = self.blocked.clone();
        let url = self.config.url.clone();

        Box::pin(async move {
            let body = body?;
            let client_ecs = client_ecs?;
            let request = runtime_dns_request(&url, &body)?;
            let controller = AbortController::default();
            let signal = controller.signal();
            let fetch = Fetch::Request(request);
            let operation = async move {
                let mut response = fetch
                    .send_with_signal(&signal)
                    .await
                    .map_err(|error| PolicyError::Transport(error.to_string()))?;
                if response.status_code() != 200 {
                    return Err(PolicyError::Transport(
                        "DNS upstream returned non-200 status".to_owned(),
                    ));
                }
                response
                    .bytes()
                    .await
                    .map_err(|error| PolicyError::Transport(error.to_string()))
            };
            let cancelled = cancellation.cancelled();
            pin_mut!(operation, cancelled);
            let response_body = match select(operation, cancelled).await {
                Either::Left((result, _)) => result?,
                Either::Right(((), _)) => {
                    controller.abort();
                    return Err(PolicyError::Cancelled);
                }
            };
            let response_body = dns::normalize_response(&response_body, client_ecs.as_ref())?;
            let classification =
                dns::classify_response(&response_body, query_id, &expected, &blocked);
            Ok(QueryOutcome::new(response_body, classification))
        })
    }
}

#[derive(Clone, Copy)]
struct RuntimeWorkerTimer;

impl DeadlineTimer for RuntimeWorkerTimer {
    type Wait = worker::Delay;

    fn wait(&self, duration: Duration) -> Self::Wait {
        worker::Delay::from(duration)
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
) -> Option<QueryOutcome>
where
    F: Fn(&QueryOutcome) -> bool,
{
    let Some(runtime_upstreams) = runtime_upstreams else {
        return upstream::fast_query(body, query, client_ip, foreign_only, trace, accept).await;
    };
    let upstreams = configured_runtime_upstreams(runtime_upstreams, query, client_ip, foreign_only);
    algo::fast::race(
        &upstreams,
        body,
        FastOptions {
            deadline: Duration::from_millis(u64::from(config::FAST_TIMEOUT_MS)),
        },
        &RuntimeWorkerTimer,
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
    let Some(runtime_upstreams) = runtime_upstreams else {
        return upstream::mix_query(body, query, client_ip, trace).await;
    };
    let upstreams = configured_runtime_upstreams(runtime_upstreams, query, client_ip, false);
    algo::mix::collect(
        &upstreams,
        body,
        MixOptions {
            deadline: Duration::from_millis(u64::from(config::MIX_TIMEOUT_MS)),
        },
        &RuntimeWorkerTimer,
    )
    .await
}

fn configured_runtime_upstreams<'a>(
    runtime_upstreams: &'a [RuntimeUpstream],
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    foreign_only: bool,
) -> Vec<RuntimeWorkerUpstream<'a>> {
    let maximum = if config::AUTO_CONCURRENCY == 0 {
        runtime_upstreams.len()
    } else {
        config::AUTO_CONCURRENCY.min(runtime_upstreams.len())
    };
    runtime_upstreams
        .iter()
        .filter(|upstream| !foreign_only || is_foreign_runtime_upstream(&upstream.name))
        .take(maximum)
        .map(|upstream| RuntimeWorkerUpstream::new(upstream, query, client_ip))
        .collect()
}

fn is_foreign_runtime_upstream(name: &str) -> bool {
    name != "dnspod" && name != "alidns"
}

fn prepare_runtime_upstream_query(
    body: &[u8],
    use_ecs: bool,
    client_ip: Option<std::net::IpAddr>,
) -> Result<Vec<u8>, PolicyError> {
    if use_ecs {
        dns::prepare_query(body, client_ip, config::ECS_PREFIX4, config::ECS_PREFIX6)
            .map_err(PolicyError::from)
    } else {
        dns::remove_ecs(body).map_err(PolicyError::from)
    }
}

fn runtime_dns_request(url: &str, body: &[u8]) -> Result<Request, PolicyError> {
    let headers = Headers::new();
    headers
        .set("content-type", "application/dns-message")
        .map_err(|error| PolicyError::Transport(error.to_string()))?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let bytes = worker::js_sys::Uint8Array::from(body);
    init.with_body(Some(bytes.into()));
    Request::new_with_init(url, &init).map_err(|error| PolicyError::Transport(error.to_string()))
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

    #[test]
    fn selects_custom_upstreams_for_fast_and_mix_races() {
        let parsed = match parse_query(&query("example.com", TYPE_A)) {
            Ok(parsed) => parsed,
            Err(error) => panic!("test query must parse: {error}"),
        };
        let mut upstreams = config::UPSTREAMS
            .iter()
            .map(|upstream| RuntimeUpstream {
                name: upstream.name.to_owned(),
                url: upstream.url.to_owned(),
                ecs: upstream.ecs,
            })
            .collect::<Vec<_>>();
        upstreams.insert(
            0,
            RuntimeUpstream {
                name: "custom".to_owned(),
                url: "https://resolver.example/dns-query".to_owned(),
                ecs: true,
            },
        );

        let selected = configured_runtime_upstreams(&upstreams, &parsed, None, false);
        assert!(
            selected
                .iter()
                .any(|upstream| upstream.config.name == "custom")
        );
    }
}
