use worker::{Error, Request, Response, Result};

use crate::{
    config,
    http::{RuntimeConfig, static_response},
};

const INDEX_HTML: &str = include_str!("../../frontend/index.html");
const EN_HTML: &str = include_str!("../../frontend/en.html");
const STYLESHEET: &str = include_str!("../../frontend/css/style.css");
const RESOLVER_SCRIPT: &str = include_str!("../../frontend/js/resolver.js");
const WIZARD_SCRIPT: &str = include_str!("../../frontend/js/config-wizard.js");

/// Renders the Chinese or English homepage with request-specific placeholders.
///
/// # Errors
///
/// Returns a Worker error when the request host or injected JSON value is invalid.
#[expect(
    clippy::needless_pass_by_value,
    reason = "worker Router async handlers require an owned request"
)]
pub fn serve(
    req: Request,
    runtime: &RuntimeConfig,
    entrance: &str,
    english: bool,
) -> Result<Response> {
    let host = request_host(&req)?;
    let template = if english { EN_HTML } else { INDEX_HTML };
    let body = inject(template, &host, runtime, entrance, config::CONFIGURED)?;
    Response::from_html(body)
}

/// Serves the embedded stylesheet.
///
/// # Errors
///
/// Returns a Worker error when response headers cannot be constructed.
pub fn stylesheet() -> Result<Response> {
    static_response(STYLESHEET, "text/css;charset=utf-8")
}

/// Serves the embedded resolver UI script.
///
/// # Errors
///
/// Returns a Worker error when response headers cannot be constructed.
pub fn resolver_script() -> Result<Response> {
    static_response(RESOLVER_SCRIPT, "application/javascript;charset=utf-8")
}

/// Serves the embedded configuration-wizard script.
///
/// # Errors
///
/// Returns a Worker error when response headers cannot be constructed.
pub fn wizard_script() -> Result<Response> {
    static_response(WIZARD_SCRIPT, "application/javascript;charset=utf-8")
}

fn request_host(req: &Request) -> Result<String> {
    let url = req.url()?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::RustError("request URL has no host".into()))?;
    Ok(url
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}")))
}

fn inject(
    template: &str,
    host: &str,
    runtime: &RuntimeConfig,
    entrance: &str,
    configured: u8,
) -> Result<String> {
    let base_path_html = escape_html(entrance);
    let base_path_json = serde_json::to_string(entrance).map_err(|error| {
        Error::RustError(format!("failed to serialize home base path: {error}"))
    })?;
    Ok(template
        .replace("__BASE_PATH_HTML__", &base_path_html)
        .replace("__BASE_PATH_JSON__", &base_path_json)
        .replace("__HOST__", &escape_html(host))
        .replace("__UPSTREAM_LIST__", &endpoint_list(&base_path_html))
        .replace("__EDNS_CAPS_TABLE__", &caps_table(runtime))
        .replace("__CONFIGURED_VALUE__", &configured.to_string()))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn endpoint_list(base_path: &str) -> String {
    format!("<span class=\"endpoint\">{base_path}/dns-query</span>")
}

fn caps_table(runtime: &RuntimeConfig) -> String {
    if runtime.upstreams.is_empty() {
        return "<em>none</em>".to_owned();
    }
    let mut table = String::from(
        "<table class=\"caps-table\"><thead><tr><th>Upstream</th><th>ECS</th></tr></thead><tbody>",
    );
    for upstream in &runtime.upstreams {
        let ecs = if upstream.ecs {
            "<span class=\"yes\">✅</span>"
        } else {
            "<span class=\"no\">✖</span>"
        };
        table.push_str("<tr><td><strong>");
        table.push_str(&escape_html(&upstream.name));
        table.push_str("</strong></td><td>");
        table.push_str(ecs);
        table.push_str("</td></tr>");
    }
    table.push_str("</tbody></table>");
    table.push_str("<p style=\"font-size:.78em;color:#888;margin-top:6px\">ECS = EDNS Client-Subnet（地理位置优化 / geo-optimized resolution）</p>");
    table
}

#[cfg(test)]
mod tests {
    use super::inject;
    use crate::http::RuntimeConfig;

    #[test]
    fn injects_every_homepage_placeholder_without_xss() {
        let runtime = RuntimeConfig {
            upstreams: vec![],
            foreign_upstreams: vec![],
        };
        let result = match inject(
            "__BASE_PATH_HTML__|__BASE_PATH_JSON__|__HOST__|__UPSTREAM_LIST__|__EDNS_CAPS_TABLE__|__CONFIGURED_VALUE__",
            "example.test<script>",
            &runtime,
            "/secret",
            1,
        ) {
            Ok(result) => result,
            Err(error) => panic!("template injection must succeed: {error}"),
        };
        assert_eq!(
            result,
            "/secret|\"/secret\"|example.test&lt;script&gt;|<span class=\"endpoint\">/secret/dns-query</span>|<em>none</em>|1"
        );
    }
}
