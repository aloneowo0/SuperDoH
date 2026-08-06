use core::time::Duration;
use std::{cell::RefCell, rc::Rc};

use futures_util::{
    StreamExt,
    future::{Either, LocalBoxFuture, select},
    pin_mut,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{AbortController, Fetch, Headers, Method, Request, RequestInit, Socket};

use crate::{
    algo::{self, DeadlineTimer, QueryOutcome, Upstream, fast::FastOptions, mix::MixOptions},
    config, dns,
    http::{RuntimeUpstream, RuntimeUpstreamTransport},
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum TransportEndpoint {
    Doh(String),
    Tcp { host: String, port: u16 },
}

#[derive(Clone)]
pub(crate) struct WorkerUpstream {
    name: String,
    endpoint: TransportEndpoint,
    ecs: bool,
    expected: dns::Question,
    query_id: u16,
    client_ip: Option<std::net::IpAddr>,
    client_sent_ecs: bool,
    blocked: Vec<dns::Cidr>,
    trace: UpstreamTrace,
}

impl WorkerUpstream {
    fn from_config(
        config: &'static config::Upstream,
        query: &ParsedQuery,
        client_ip: Option<std::net::IpAddr>,
        trace: UpstreamTrace,
    ) -> Self {
        Self {
            name: config.name.to_owned(),
            endpoint: match config.transport {
                config::UpstreamTransport::Doh => TransportEndpoint::Doh(config.doh_url.to_owned()),
                config::UpstreamTransport::Tcp => TransportEndpoint::Tcp {
                    host: config.tcp_host.to_owned(),
                    port: config.tcp_port,
                },
            },
            ecs: config.ecs,
            expected: query.question.clone(),
            query_id: query.id,
            client_ip,
            client_sent_ecs: query.client_sent_ecs,
            blocked: classify::blocked_cidrs(),
            trace,
        }
    }

    fn from_runtime(
        config: &RuntimeUpstream,
        query: &ParsedQuery,
        client_ip: Option<std::net::IpAddr>,
        trace: UpstreamTrace,
    ) -> Self {
        Self {
            name: config.name.clone(),
            endpoint: match &config.transport {
                RuntimeUpstreamTransport::Doh { url } => TransportEndpoint::Doh(url.clone()),
                RuntimeUpstreamTransport::Tcp { host, port } => TransportEndpoint::Tcp {
                    host: host.clone(),
                    port: *port,
                },
            },
            ecs: config.ecs,
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
        let body = prepare_upstream_query(body, self.ecs, self.client_ip);
        let name = self.name.clone();
        let trace = self.trace.clone();
        let expected = self.expected.clone();
        let query_id = self.query_id;
        let blocked = self.blocked.clone();
        let endpoint = self.endpoint.clone();

        Box::pin(async move {
            let body = body?;
            let client_ecs = client_ecs?;
            let response_body = match endpoint {
                TransportEndpoint::Doh(url) => query_doh(&url, &body, cancellation).await?,
                TransportEndpoint::Tcp { host, port } => {
                    query_tcp(&host, port, &body, cancellation).await?
                }
            };
            let response_body = dns::normalize_response(&response_body, client_ecs.as_ref())?;
            let classification =
                dns::classify_response(&response_body, query_id, &expected, &blocked);
            trace.record(&name);
            Ok(QueryOutcome::new(response_body, classification))
        })
    }
}

async fn query_doh(
    url: &str,
    body: &[u8],
    cancellation: algo::CancellationToken,
) -> Result<Vec<u8>, PolicyError> {
    let request = dns_request(url, body)?;
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
        read_dns_response_body(&mut response).await
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
    Ok(response_body)
}

struct SocketOnDrop {
    socket: Option<Socket>,
}

impl SocketOnDrop {
    fn new(socket: Socket) -> Self {
        Self {
            socket: Some(socket),
        }
    }

    fn socket_mut(&mut self) -> Result<&mut Socket, PolicyError> {
        self.socket
            .as_mut()
            .ok_or_else(|| PolicyError::Transport("DNS TCP socket already closed".to_owned()))
    }

    async fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.close().await;
        }
    }
}

impl Drop for SocketOnDrop {
    fn drop(&mut self) {
        let Some(mut socket) = self.socket.take() else {
            return;
        };
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            let _ = socket.close().await;
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = &mut socket;
        }
    }
}

async fn query_tcp(
    host: &str,
    port: u16,
    body: &[u8],
    cancellation: algo::CancellationToken,
) -> Result<Vec<u8>, PolicyError> {
    let frame_length = tcp_request_length(body)?;
    let socket = Socket::builder()
        .connect(host, port)
        .map_err(|error| PolicyError::Transport(error.to_string()))?;
    let mut socket = SocketOnDrop::new(socket);
    let result = {
        let operation = async {
            let stream = socket.socket_mut()?;
            stream
                .write_all(&frame_length)
                .await
                .map_err(|error| PolicyError::Transport(error.to_string()))?;
            stream
                .write_all(body)
                .await
                .map_err(|error| PolicyError::Transport(error.to_string()))?;
            stream
                .flush()
                .await
                .map_err(|error| PolicyError::Transport(error.to_string()))?;

            let mut response_length = [0_u8; 2];
            stream
                .read_exact(&mut response_length)
                .await
                .map_err(|error| PolicyError::Transport(error.to_string()))?;
            let response_length = tcp_response_length(response_length)?;
            let mut response_body = vec![0_u8; response_length];
            stream
                .read_exact(&mut response_body)
                .await
                .map_err(|error| PolicyError::Transport(error.to_string()))?;
            Ok::<Vec<u8>, PolicyError>(response_body)
        };
        let cancelled = cancellation.cancelled();
        pin_mut!(operation, cancelled);
        match select(operation, cancelled).await {
            Either::Left((result, _)) => result,
            Either::Right(((), operation)) => {
                drop(operation);
                Err(PolicyError::Cancelled)
            }
        }
    };
    socket.close().await;
    result
}

fn tcp_request_length(body: &[u8]) -> Result<[u8; 2], PolicyError> {
    let length = u16::try_from(body.len())
        .map_err(|_| PolicyError::Transport("DNS TCP query exceeds 65535 bytes".to_owned()))?;
    if length == 0 {
        return Err(PolicyError::Transport(
            "DNS TCP query cannot be empty".to_owned(),
        ));
    }
    Ok(length.to_be_bytes())
}

fn tcp_response_length(prefix: [u8; 2]) -> Result<usize, PolicyError> {
    let length = usize::from(u16::from_be_bytes(prefix));
    if length == 0 {
        return Err(PolicyError::Transport(
            "DNS TCP upstream returned an empty frame".to_owned(),
        ));
    }
    Ok(length)
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
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
    accept: F,
) -> Option<QueryOutcome>
where
    F: Fn(&QueryOutcome) -> bool,
{
    let upstreams = configured_upstreams(query, client_ip, foreign_only, runtime_upstreams, trace);
    algo::fast::race(
        &upstreams,
        body,
        FastOptions {
            deadline: Duration::from_millis(u64::from(config::FAST_TIMEOUT_MS)),
            max_concurrency: config::UPSTREAM_CONCURRENCY,
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
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
) -> Vec<Vec<u8>> {
    let upstreams = configured_upstreams(query, client_ip, false, runtime_upstreams, trace);
    algo::mix::collect(
        &upstreams,
        body,
        MixOptions {
            deadline: Duration::from_millis(u64::from(config::MIX_TIMEOUT_MS)),
            max_concurrency: config::UPSTREAM_CONCURRENCY,
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
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
) -> Vec<WorkerUpstream> {
    if let Some(runtime_upstreams) = runtime_upstreams {
        return runtime_upstreams
            .iter()
            .filter(|upstream| !foreign_only || is_foreign_upstream(&upstream.name))
            .map(|upstream| {
                WorkerUpstream::from_runtime(upstream, query, client_ip, (*trace).clone())
            })
            .collect();
    }

    config::UPSTREAMS
        .iter()
        .filter(|upstream| !foreign_only || config::FOREIGN_UPSTREAMS.contains(&upstream.name))
        .map(|upstream| WorkerUpstream::from_config(upstream, query, client_ip, (*trace).clone()))
        .collect()
}

fn is_foreign_upstream(name: &str) -> bool {
    name != "dnspod" && name != "alidns"
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
    fn tcp_framing_accepts_the_dns_wire_size_range() {
        assert!(matches!(
            tcp_request_length(&[]),
            Err(PolicyError::Transport(message)) if message == "DNS TCP query cannot be empty"
        ));
        assert_eq!(tcp_request_length(&[0; 12]), Ok(12_u16.to_be_bytes()));
        assert_eq!(
            tcp_request_length(&vec![0; MAX_DNS_RESPONSE_SIZE]),
            Ok(u16::MAX.to_be_bytes())
        );
        assert!(matches!(
            tcp_request_length(&vec![0; MAX_DNS_RESPONSE_SIZE + 1]),
            Err(PolicyError::Transport(message)) if message == "DNS TCP query exceeds 65535 bytes"
        ));
        assert!(tcp_response_length([0, 0]).is_err());
        assert_eq!(tcp_response_length([0, 53]), Ok(53));
    }

    #[test]
    fn runtime_transport_selects_the_configured_tcp_endpoint() {
        let wire = match build_query("example.com", 1, 7) {
            Ok(wire) => wire,
            Err(error) => panic!("query must build: {error}"),
        };
        let query = match super::super::parse_query(&wire) {
            Ok(query) => query,
            Err(error) => panic!("query must parse: {error}"),
        };
        let runtime = [RuntimeUpstream {
            name: "quad9".to_owned(),
            transport: RuntimeUpstreamTransport::Tcp {
                host: "9.9.9.11".to_owned(),
                port: 53,
            },
            ecs: true,
        }];
        let trace = UpstreamTrace::default();
        let selected = configured_upstreams(&query, None, false, Some(&runtime), &trace);

        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].endpoint,
            TransportEndpoint::Tcp {
                host: "9.9.9.11".to_owned(),
                port: 53,
            }
        );
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
