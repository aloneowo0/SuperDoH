use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use worker::{Env, Error, Headers, Request, Response, Result, js_sys};

use crate::config;

const PROXY_STRIPPED_RESPONSE_HEADERS: &[&str] = &[
    "Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "Set-Cookie",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
    "Server",
    "Via",
    "X-AspNet-Version",
    "X-Powered-By",
    "X-Runtime",
    "X-Served-By",
];

pub mod config_json;
pub mod doh;
pub mod health;
pub mod home;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeUpstreamTransport {
    Doh { url: String },
    Tcp { host: String, port: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeUpstream {
    pub name: String,
    pub transport: RuntimeUpstreamTransport,
    pub ecs: bool,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub upstreams: Vec<RuntimeUpstream>,
    pub foreign_upstreams: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub runtime: RuntimeConfig,
    pub entrance: String,
    proxy: Option<String>,
}

impl AppState {
    #[must_use]
    pub fn from_env(env: &Env) -> Self {
        let entrance = binding_value(env, "ENTRANCE")
            .as_deref()
            .map(normalize_entrance)
            .unwrap_or_default();
        let proxy = binding_value(env, "PROXY").filter(|value| valid_proxy_target(value));
        let proxy = (!entrance.is_empty()).then_some(proxy).flatten();

        Self {
            runtime: runtime_config(env),
            entrance,
            proxy,
        }
    }
}

#[must_use]
pub fn internal_path(path: &str, entrance: &str) -> Option<String> {
    if entrance.is_empty() {
        return Some(path.to_owned());
    }

    if path == entrance {
        return Some("/".to_owned());
    }
    path.strip_prefix(entrance)
        .filter(|suffix| suffix.starts_with('/'))
        .map(ToOwned::to_owned)
}

/// Handles an unmatched public path, using camouflage only when enabled.
///
/// # Errors
///
/// Returns a Worker error when request inspection or proxy response construction fails.
pub async fn fallback(req: Request, state: &AppState) -> Result<Response> {
    if let Some(proxy) = &state.proxy {
        if is_misrouted_doh(&req)? {
            return Response::error("Not Found", 404);
        }
        return proxy_fetch(req, proxy).await;
    }
    Response::error("Not Found", 404)
}

/// Builds a JSON response with the endpoint API media type.
///
/// # Errors
///
/// Returns a Worker error when JSON serialization or header construction fails.
pub fn json_response<T: serde::Serialize>(value: &T, status: u16) -> Result<Response> {
    let body = serde_json::to_vec(value)
        .map_err(|error| Error::RustError(format!("failed to serialize JSON response: {error}")))?;
    let builder = Response::builder()
        .with_status(status)
        .with_header("Content-Type", "application/json;charset=utf-8")?;
    Ok(builder.fixed(body))
}

/// Builds a cache-revalidating static frontend response.
///
/// # Errors
///
/// Returns a Worker error when response headers cannot be constructed.
pub fn static_response(body: &'static str, content_type: &str) -> Result<Response> {
    let builder = Response::builder()
        .with_header("Content-Type", content_type)?
        .with_header("Cache-Control", "no-cache")?;
    Ok(builder.fixed(body.as_bytes().to_vec()))
}

fn runtime_config(env: &Env) -> RuntimeConfig {
    let mut upstreams: Vec<RuntimeUpstream> = config::UPSTREAMS
        .iter()
        .map(|upstream| RuntimeUpstream {
            name: upstream.name.to_owned(),
            transport: match upstream.transport {
                config::UpstreamTransport::Doh => RuntimeUpstreamTransport::Doh {
                    url: upstream.doh_url.to_owned(),
                },
                config::UpstreamTransport::Tcp => RuntimeUpstreamTransport::Tcp {
                    host: upstream.tcp_host.to_owned(),
                    port: upstream.tcp_port,
                },
            },
            ecs: upstream.ecs,
        })
        .collect();

    let env_value: &worker::wasm_bindgen::JsValue = env.as_ref();
    let env_object = js_sys::Object::from(env_value.clone());
    for binding in js_sys::Object::keys(&env_object).iter() {
        let Some(binding) = binding.as_string() else {
            continue;
        };
        let Some(name) = binding.strip_prefix("CUSTOM_") else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        if !valid_custom_name(&name) {
            continue;
        }
        let Some(url) = binding_value(env, &binding) else {
            continue;
        };
        if !url.starts_with("https://") {
            continue;
        }

        let custom = RuntimeUpstream {
            name: name.clone(),
            transport: RuntimeUpstreamTransport::Doh { url },
            ecs: true,
        };
        merge_runtime_upstream(&mut upstreams, custom);
    }

    let foreign_upstreams = upstreams
        .iter()
        .filter(|upstream| upstream.name != "dnspod" && upstream.name != "alidns")
        .map(|upstream| upstream.name.clone())
        .collect();
    RuntimeConfig {
        upstreams,
        foreign_upstreams,
    }
}

fn merge_runtime_upstream(upstreams: &mut Vec<RuntimeUpstream>, custom: RuntimeUpstream) {
    if let Some(existing) = upstreams
        .iter_mut()
        .find(|upstream| upstream.name == custom.name)
    {
        *existing = custom;
    } else {
        upstreams.insert(0, custom);
    }
}

fn binding_value(env: &Env, name: &str) -> Option<String> {
    env.var(name).ok().map(|value| value.to_string())
}

fn valid_custom_name(name: &str) -> bool {
    let mut characters = name.bytes();
    matches!(characters.next(), Some(b'a'..=b'z'))
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == b'_'
        })
}

fn normalize_entrance(raw: &str) -> String {
    let path = raw.trim().trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    if path == "/"
        || path.is_empty()
        || !path.strip_prefix('/').is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .split('/')
                    .all(|segment| !segment.is_empty() && valid_path_segment(segment))
        })
    {
        String::new()
    } else {
        path
    }
}

fn valid_path_segment(segment: &str) -> bool {
    segment.bytes().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, b'.' | b'_' | b'~' | b'-')
    })
}

fn is_misrouted_doh(req: &Request) -> Result<bool> {
    let content_type = req
        .headers()
        .get("Content-Type")?
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("application/dns-message");
    let url = req.url()?;
    let has_dns_parameters = url.query_pairs().any(|(key, _)| key == "dns")
        || (url.query_pairs().any(|(key, _)| key == "name")
            && url.query_pairs().any(|(key, _)| key == "type"));
    Ok(content_type || has_dns_parameters)
}

async fn proxy_fetch(req: Request, proxy: &str) -> Result<Response> {
    match proxy_fetch_inner(req, proxy).await {
        Ok(response) => Ok(response),
        Err(_) => Response::error("Bad Gateway", 502),
    }
}

async fn proxy_fetch_inner(req: Request, proxy: &str) -> Result<Response> {
    let request_url = req.url()?;
    let target = parse_proxy_target(proxy)?;

    let base_path = target.path().trim_end_matches('/').to_owned();
    let mut upstream_url = target.clone();
    upstream_url.set_path(&format!("{base_path}{}", request_url.path()));
    upstream_url.set_query(request_url.query());
    upstream_url.set_fragment(None);

    let headers = proxy_headers(req.headers())?;
    let mut init = worker::RequestInit::new();
    init.headers = headers;
    init.method = req.method();
    init.redirect = worker::RequestRedirect::Manual;
    if !matches!(req.method(), worker::Method::Get | worker::Method::Head) {
        init.body = req.inner().body().map(Into::into);
    }

    let upstream_request = Request::new_with_init(upstream_url.as_str(), &init)?;
    let response = worker::Fetch::Request(upstream_request).send().await?;
    let status = response.status_code();
    let headers = response.headers().clone();
    strip_proxy_response_headers(&headers)?;
    if (300..400).contains(&status)
        && let Some(location) = headers.get("Location")?
    {
        let rewritten =
            rewrite_proxy_location(&location, &upstream_url, &request_url, &target, &base_path)?
                .ok_or_else(|| Error::RustError("unsafe proxy redirect".into()))?;
        headers.set("Location", &rewritten)?;
    }

    let (_, body) = response.into_parts();
    Ok(Response::from_body(body)?
        .with_status(status)
        .with_headers(headers))
}

fn valid_proxy_target(value: &str) -> bool {
    parse_proxy_target(value).is_ok()
}

fn parse_proxy_target(proxy: &str) -> Result<worker::Url> {
    let target = worker::Url::parse(proxy)
        .map_err(|error| Error::RustError(format!("invalid proxy URL: {error}")))?;
    if target.scheme() != "https" {
        return Err(Error::RustError("unsupported proxy protocol".into()));
    }
    if !target.username().is_empty() || target.password().is_some() || target.fragment().is_some() {
        return Err(Error::RustError("unsafe proxy URL".into()));
    }
    let host = target
        .host_str()
        .ok_or_else(|| Error::RustError("proxy URL has no host".into()))?;
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if host.parse::<IpAddr>().is_ok_and(forbidden_proxy_address) {
        return Err(Error::RustError("unsafe proxy address".into()));
    }
    Ok(target)
}

fn forbidden_proxy_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => forbidden_proxy_ipv4(address),
        IpAddr::V6(address) => forbidden_proxy_ipv6(address),
    }
}

fn forbidden_proxy_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _] = address.octets();
    first == 0
        || first == 10
        || first == 127
        || first >= 224
        || (first == 100 && (64..=127).contains(&second))
        || (first == 169 && second == 254)
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192
            && ((second == 0 && (third == 0 || third == 2))
                || (second == 31 && third == 196)
                || (second == 52 && third == 193)
                || (second == 88 && third == 99)
                || second == 168
                || (second == 175 && third == 48)))
        || (first == 198 && ((second == 18 || second == 19) || (second == 51 && third == 100)))
        || (first == 203 && second == 0 && third == 113)
}

fn forbidden_proxy_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.to_ipv4_mapped().is_some_and(forbidden_proxy_ipv4)
        || segments[..6].iter().all(|segment| *segment == 0)
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x0100 && segments[1..].iter().all(|segment| *segment == 0))
        || (segments[0] == 0x2001
            && ((segments[1] & 0xfff0 == 0x0010) || segments[1] == 0x0002 || segments[1] == 0x0db8))
        || segments[0] == 0x2002
}

fn strip_proxy_response_headers(headers: &Headers) -> Result<()> {
    let connection_headers = headers.get("Connection")?.unwrap_or_default();
    for name in PROXY_STRIPPED_RESPONSE_HEADERS {
        headers.delete(name)?;
    }
    for name in connection_headers
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        headers.delete(name)?;
    }
    Ok(())
}

#[cfg(test)]
fn stripped_proxy_response_header(name: &str, connection_headers: &str) -> bool {
    PROXY_STRIPPED_RESPONSE_HEADERS
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
        || connection_headers
            .split(',')
            .map(str::trim)
            .any(|header| !header.is_empty() && name.eq_ignore_ascii_case(header))
}

fn proxy_headers(request_headers: &Headers) -> Result<Headers> {
    const SENSITIVE_HEADERS: &[&str] = &[
        "host",
        "cf-connecting-ip",
        "x-forwarded-for",
        "x-real-ip",
        "true-client-ip",
        "authorization",
        "proxy-authorization",
        "cookie",
        "referer",
        "origin",
        "cf-access-jwt-assertion",
        "cf-access-client-id",
        "cf-access-client-secret",
    ];

    let headers = Headers::new();
    for (name, value) in request_headers {
        if !SENSITIVE_HEADERS
            .iter()
            .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
        {
            headers.set(&name, &value)?;
        }
    }
    Ok(headers)
}

fn rewrite_proxy_location(
    location: &str,
    upstream_url: &worker::Url,
    request_url: &worker::Url,
    target: &worker::Url,
    base_path: &str,
) -> Result<Option<String>> {
    let next = upstream_url
        .join(location)
        .map_err(|error| Error::RustError(format!("invalid proxy redirect: {error}")))?;
    if next.origin() != target.origin() {
        return Ok(None);
    }
    let public_path = if base_path.is_empty() {
        next.path().to_owned()
    } else if next.path() == base_path {
        "/".to_owned()
    } else if let Some(path) = next.path().strip_prefix(base_path) {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            return Ok(None);
        }
    } else {
        return Ok(None);
    };

    let mut visible = request_url.clone();
    visible.set_path(&public_path);
    visible.set_query(next.query());
    visible.set_fragment(next.fragment());
    Ok(Some(visible.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeUpstream, RuntimeUpstreamTransport, forbidden_proxy_address, internal_path,
        merge_runtime_upstream, normalize_entrance, parse_proxy_target,
        stripped_proxy_response_header, valid_custom_name,
    };
    use std::net::IpAddr;

    #[test]
    fn entrance_routes_only_secret_paths_internally() {
        assert_eq!(normalize_entrance(" secret/path/ "), "/secret/path");
        assert_eq!(normalize_entrance("/"), "");
        assert_eq!(normalize_entrance("/bad path"), "");
        assert_eq!(
            internal_path("/secret/dns-query", "/secret"),
            Some("/dns-query".to_owned())
        );
        assert_eq!(internal_path("/dns-query", "/secret"), None);
        assert_eq!(internal_path("/secret-other/dns-query", "/secret"), None);
        assert_eq!(
            internal_path("/dns-query", ""),
            Some("/dns-query".to_owned())
        );
    }

    #[test]
    fn validates_custom_upstream_names() {
        assert!(valid_custom_name("resolver_1"));
        assert!(!valid_custom_name("1resolver"));
        assert!(!valid_custom_name("resolver-name"));
    }

    #[test]
    fn entrance_without_prefix_never_routes_to_doh() {
        assert_eq!(normalize_entrance("secret"), "/secret");
        for path in [
            "/dns-query",
            "/health",
            "/config.json",
            "/",
            "/secret-other/dns-query",
        ] {
            assert_eq!(
                internal_path(path, "/secret"),
                None,
                "path without the entrance prefix must not route internally: {path}"
            );
        }
        assert_eq!(
            internal_path("/secret/dns-query", "/secret"),
            Some("/dns-query".to_owned())
        );
        assert_eq!(internal_path("/secret", "/secret"), Some("/".to_owned()));
        assert_eq!(internal_path("/SECRET/dns-query", "/secret"), None);
    }

    #[test]
    fn prioritizes_runtime_custom_upstreams() {
        let mut upstreams = vec![RuntimeUpstream {
            name: "google".to_owned(),
            transport: RuntimeUpstreamTransport::Doh {
                url: "https://dns.google/dns-query".to_owned(),
            },
            ecs: true,
        }];
        merge_runtime_upstream(
            &mut upstreams,
            RuntimeUpstream {
                name: "custom".to_owned(),
                transport: RuntimeUpstreamTransport::Doh {
                    url: "https://resolver.example/dns-query".to_owned(),
                },
                ecs: true,
            },
        );
        assert_eq!(upstreams[0].name, "custom");
    }

    #[test]
    fn validates_proxy_targets() {
        assert!(parse_proxy_target("https://example.com/base").is_ok());
        for target in [
            "http://example.com",
            "https://user:secret@example.com",
            "https://example.com/#fragment",
            "https://127.0.0.1",
            "https://169.254.169.254",
            "https://[::1]",
            "https://[fe80::1]",
            "https://[2001:db8::1]",
        ] {
            assert!(parse_proxy_target(target).is_err(), "must reject {target}");
        }
    }

    #[test]
    fn rejects_non_public_proxy_ip_ranges() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "172.16.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
            "fc00::1",
            "2001:db8::1",
        ] {
            let address = match address.parse::<IpAddr>() {
                Ok(address) => address,
                Err(error) => panic!("test address must parse: {error}"),
            };
            assert!(forbidden_proxy_address(address));
        }
        let public_address = match "1.1.1.1".parse::<IpAddr>() {
            Ok(address) => address,
            Err(error) => panic!("test address must parse: {error}"),
        };
        assert!(!forbidden_proxy_address(public_address));
    }

    #[test]
    fn removes_proxy_fingerprinting_and_hop_by_hop_headers() {
        for header in [
            "Connection",
            "Keep-Alive",
            "Transfer-Encoding",
            "Upgrade",
            "Set-Cookie",
            "Server",
            "Via",
            "X-Powered-By",
        ] {
            assert!(stripped_proxy_response_header(header, ""));
        }
        assert!(stripped_proxy_response_header(
            "X-Upstream-Debug",
            "keep-alive, X-Upstream-Debug"
        ));
        assert!(!stripped_proxy_response_header("Content-Type", ""));
    }
}
