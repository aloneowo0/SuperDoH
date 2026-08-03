use core::time::Duration;
use std::{cell::RefCell, rc::Rc};

use futures_util::{
    StreamExt,
    future::{Either, LocalBoxFuture, select},
    pin_mut,
};
use worker::{AbortController, Fetch, Headers, Method, Request, RequestInit};

use crate::{
    algo::{self, DeadlineTimer, QueryOutcome, Upstream, fast::FastOptions, mix::MixOptions},
    config, dns,
};

use super::{ParsedQuery, PolicyError, classify};

const MAX_DNS_RESPONSE_SIZE: usize = 65_535;

#[derive(Clone, Default)]
pub(crate) struct UpstreamTrace {
    names: Rc<RefCell<Vec<String>>>,
}

impl UpstreamTrace {
    #[must_use]
    pub(crate) fn names(&self) -> Vec<String> {
        self.names.borrow().clone()
    }

    fn record(&self, name: &str) {
        let mut names = self.names.borrow_mut();
        if !names.iter().any(|entry| entry == name) {
            names.push(name.to_owned());
        }
    }
}

#[derive(Clone)]
pub(crate) struct WorkerUpstream {
    config: &'static config::Upstream,
    expected: dns::Question,
    query_id: u16,
    client_ip: Option<std::net::IpAddr>,
    client_sent_ecs: bool,
    blocked: Vec<dns::Cidr>,
    trace: UpstreamTrace,
}

impl WorkerUpstream {
    fn new(
        config: &'static config::Upstream,
        query: &ParsedQuery,
        client_ip: Option<std::net::IpAddr>,
        trace: UpstreamTrace,
    ) -> Self {
        Self {
            config,
            expected: query.question.clone(),
            query_id: query.id,
            client_ip,
            client_sent_ecs: query.client_sent_ecs,
            blocked: classify::blocked_cidrs(),
            trace,
        }
    }
}

trait Abort {
    fn abort(self);
}

impl Abort for AbortController {
    fn abort(self) {
        AbortController::abort(self);
    }
}

struct AbortOnDrop<T: Abort> {
    target: Option<T>,
}

impl<T: Abort> AbortOnDrop<T> {
    fn new(target: T) -> Self {
        Self {
            target: Some(target),
        }
    }

    fn disarm(&mut self) {
        self.target.take();
    }
}

impl<T: Abort> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(target) = self.target.take() {
            target.abort();
        }
    }
}

impl Upstream for WorkerUpstream {
    type Error = PolicyError;
    type Query<'a> = LocalBoxFuture<'a, Result<QueryOutcome, Self::Error>>;

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
        let body = prepare_upstream_query(body, self.config.ecs, self.client_ip);
        let name = self.config.name;
        let trace = self.trace.clone();
        let expected = self.expected.clone();
        let query_id = self.query_id;
        let blocked = self.blocked.clone();
        let url = self.config.url;

        Box::pin(async move {
            let body = body?;
            let client_ecs = client_ecs?;
            let request = dns_request(url, &body)?;
            let controller = AbortController::default();
            let signal = controller.signal();
            let mut abort_on_drop = AbortOnDrop::new(controller);
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
                let response_body = read_dns_response_body(&mut response).await?;
                Ok::<Vec<u8>, PolicyError>(response_body)
            };
            let cancelled = cancellation.cancelled();
            pin_mut!(operation, cancelled);
            let response_body = match select(operation, cancelled).await {
                Either::Left((result, _)) => result?,
                Either::Right(((), operation)) => {
                    drop(operation);
                    return Err(PolicyError::Cancelled);
                }
            };
            abort_on_drop.disarm();
            let response_body = dns::normalize_response(&response_body, client_ecs.as_ref())?;
            let classification =
                dns::classify_response(&response_body, query_id, &expected, &blocked);
            trace.record(name);
            Ok(QueryOutcome::new(response_body, classification))
        })
    }
}

async fn read_dns_response_body(response: &mut worker::Response) -> Result<Vec<u8>, PolicyError> {
    let content_length = response
        .headers()
        .get("content-length")
        .map_err(|error| PolicyError::Transport(error.to_string()))?;
    if content_length_exceeds_limit(content_length.as_deref()) {
        return Err(response_size_error());
    }

    let mut response_body = Vec::new();
    let mut stream = response
        .stream()
        .map_err(|error| PolicyError::Transport(error.to_string()))?;
    while let Some(chunk) = stream.next().await {
        append_response_chunk(
            &mut response_body,
            &chunk.map_err(|error| PolicyError::Transport(error.to_string()))?,
        )?;
    }
    Ok(response_body)
}

fn content_length_exceeds_limit(content_length: Option<&str>) -> bool {
    content_length
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|length| length > 65_535)
}

fn append_response_chunk(response_body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), PolicyError> {
    if chunk.len() > MAX_DNS_RESPONSE_SIZE.saturating_sub(response_body.len()) {
        return Err(response_size_error());
    }
    response_body.extend_from_slice(chunk);
    Ok(())
}

fn response_size_error() -> PolicyError {
    PolicyError::Transport("DNS upstream response exceeds 65535 bytes".to_owned())
}

fn prepare_upstream_query(
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

#[derive(Clone, Copy)]
struct WorkerTimer;

impl DeadlineTimer for WorkerTimer {
    type Wait = worker::Delay;

    fn wait(&self, duration: Duration) -> Self::Wait {
        worker::Delay::from(duration)
    }
}

pub(crate) async fn fast_query<F>(
    body: &[u8],
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    foreign_only: bool,
    trace: &UpstreamTrace,
    accept: F,
) -> Option<QueryOutcome>
where
    F: Fn(&QueryOutcome) -> bool,
{
    let upstreams = configured_upstreams(query, client_ip, foreign_only, trace);
    algo::fast::race(
        &upstreams,
        body,
        FastOptions {
            deadline: Duration::from_millis(u64::from(config::FAST_TIMEOUT_MS)),
        },
        &WorkerTimer,
        accept,
    )
    .await
}

pub(crate) async fn mix_query(
    body: &[u8],
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    trace: &UpstreamTrace,
) -> Vec<Vec<u8>> {
    let upstreams = configured_upstreams(query, client_ip, false, trace);
    algo::mix::collect(
        &upstreams,
        body,
        MixOptions {
            deadline: Duration::from_millis(u64::from(config::MIX_TIMEOUT_MS)),
        },
        &WorkerTimer,
    )
    .await
}

pub(crate) fn build_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, PolicyError> {
    let encoded_name = dns::encode_name(name)?;
    let mut query = Vec::with_capacity(
        12_usize
            .checked_add(encoded_name.len())
            .and_then(|length| length.checked_add(4))
            .ok_or(PolicyError::Build("DNS query length overflow"))?,
    );
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&encoded_name);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&dns::wire::CLASS_IN.to_be_bytes());
    Ok(query)
}

fn configured_upstreams(
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    foreign_only: bool,
    trace: &UpstreamTrace,
) -> Vec<WorkerUpstream> {
    let maximum = upstream_limit(config::AUTO_CONCURRENCY, config::UPSTREAMS.len());
    config::UPSTREAMS
        .iter()
        .filter(|upstream| !foreign_only || config::FOREIGN_UPSTREAMS.contains(&upstream.name))
        .take(maximum)
        .map(|upstream| WorkerUpstream::new(upstream, query, client_ip, (*trace).clone()))
        .collect()
}

fn upstream_limit(auto_concurrency: usize, upstream_count: usize) -> usize {
    if auto_concurrency == 0 {
        upstream_count
    } else {
        auto_concurrency
            .min(algo::MAX_CONCURRENT_UPSTREAMS)
            .min(upstream_count)
    }
}

fn dns_request(url: &str, body: &[u8]) -> Result<Request, PolicyError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll},
    };
    use std::cell::Cell;

    use crate::dns::ResourceRecord;
    use futures_util::task::noop_waker_ref;

    struct AbortSpy(Rc<Cell<usize>>);

    impl Abort for AbortSpy {
        fn abort(self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn cancellation_drops_guard_and_aborts_transport() {
        let cancellation = algo::CancellationToken::default();
        let aborts = Rc::new(Cell::new(0));
        let future = async {
            let _guard = AbortOnDrop::new(AbortSpy(aborts.clone()));
            cancellation.cancelled().await;
        };
        let waker = noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);

        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        cancellation.cancel();
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(())
        ));
        assert_eq!(aborts.get(), 1);
    }

    #[test]
    fn zero_auto_concurrency_keeps_all_candidates() {
        assert_eq!(upstream_limit(0, 8), 8);
    }

    #[test]
    fn auto_concurrency_is_capped_at_connection_limit() {
        assert_eq!(upstream_limit(8, 9), algo::MAX_CONCURRENT_UPSTREAMS);
    }

    #[test]
    fn streaming_response_rejects_bytes_beyond_limit() {
        let mut response_body = vec![0; MAX_DNS_RESPONSE_SIZE];

        let result = append_response_chunk(&mut response_body, &[0]);

        assert!(
            matches!(result, Err(PolicyError::Transport(message)) if message == "DNS upstream response exceeds 65535 bytes")
        );
        assert_eq!(response_body.len(), MAX_DNS_RESPONSE_SIZE);
    }

    #[test]
    fn content_length_only_rejects_declared_oversized_responses() {
        assert!(content_length_exceeds_limit(Some("65536")));
        assert!(!content_length_exceeds_limit(Some("65535")));
        assert!(!content_length_exceeds_limit(Some("unknown")));
    }

    #[test]
    fn wire_query_has_one_in_question() {
        let query = build_query("example.com", 1, 7);
        let query = match query {
            Ok(query) => query,
            Err(error) => panic!("test query must build: {error}"),
        };
        let parsed = match dns::parse_message(&query) {
            Ok(parsed) => parsed,
            Err(error) => panic!("test query must parse: {error}"),
        };
        assert_eq!(parsed.header.id, 7);
        assert_eq!(parsed.questions[0].qclass, dns::wire::CLASS_IN);
    }

    #[test]
    fn ecs_disabled_upstream_receives_a_query_without_ecs() {
        let query = match build_query("example.com", 1, 7) {
            Ok(value) => value,
            Err(error) => panic!("test query must build: {error}"),
        };
        let mut message = match dns::parse_message(&query) {
            Ok(value) => value,
            Err(error) => panic!("test query must parse: {error}"),
        };
        let mut rdata = Vec::new();
        let encoded = [0, 1, 24, 0, 192, 0, 2];
        rdata.extend_from_slice(&dns::OPTION_ECS.to_be_bytes());
        rdata.extend_from_slice(&7_u16.to_be_bytes());
        rdata.extend_from_slice(&encoded);
        message.additionals.push(ResourceRecord {
            name: String::new(),
            rr_type: dns::wire::TYPE_OPT,
            class: 1232,
            ttl: 0,
            rdata,
        });
        let input = match dns::wire::serialize_message(&message) {
            Ok(value) => value,
            Err(error) => panic!("test query must serialize: {error}"),
        };
        let prepared = match prepare_upstream_query(&input, false, None) {
            Ok(value) => value,
            Err(error) => panic!("ECS-disabled preparation must succeed: {error}"),
        };
        let parsed = match dns::parse_message(&prepared) {
            Ok(value) => value,
            Err(error) => panic!("prepared query must parse: {error}"),
        };
        let opt = match dns::parse_opt(&parsed.additionals[0]) {
            Ok(value) => value,
            Err(error) => panic!("prepared OPT must parse: {error}"),
        };
        assert!(!opt.options.iter().any(|(code, _)| *code == dns::OPTION_ECS));
    }
}
