use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use worker::{
    Error, Headers, Method, Request, Response, Result,
    wasm_bindgen::{JsCast, JsValue},
};

use crate::{
    config,
    dns::{Question, build_response, encode_name, parse_message, servfail},
    http::{AppState, json_response},
    policy,
};

const DNS_MEDIA_TYPE: &str = "application/dns-message";
const DNS_JSON_MEDIA_TYPE: &str = "application/dns-json;charset=utf-8";
const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

struct ParsedDohRequest {
    body: Vec<u8>,
    question: Question,
    id: u16,
    wants_json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientError {
    status: u16,
    error: &'static str,
    allow: bool,
}

impl ClientError {
    const fn new(status: u16, error: &'static str) -> Self {
        Self {
            status,
            error,
            allow: false,
        }
    }

    const fn method_not_allowed() -> Self {
        Self {
            status: 405,
            error: "method_not_allowed",
            allow: true,
        }
    }
}

/// Validates one `DoH` request, applies canary semantics, and runs the policy pipeline.
///
/// # Errors
///
/// Returns a Worker error when Cloudflare request metadata, policy output, or response headers fail.
pub async fn serve(req: Request, state: &AppState) -> Result<Response> {
    let client_ip = req.headers().get("CF-Connecting-IP")?;
    let country = req.cf().and_then(worker::Cf::country).unwrap_or_default();
    let parsed = match parse_request(req).await {
        Ok(parsed) => parsed,
        Err(error) => return client_error_response(error),
    };
    let mut ctx = policy::RequestCtx::default();

    let wire = if is_canary(&parsed.question) {
        canary_response(parsed.id, &parsed.question)?
    } else {
        match policy::process_query_with_upstreams(
            &parsed.body,
            client_ip.as_deref(),
            &country,
            &state.runtime.upstreams,
            &mut ctx,
        )
        .await
        {
            Ok(wire) if wire.len() <= MAX_DNS_MESSAGE_SIZE => wire,
            Ok(_) | Err(_) => servfail(
                parsed.id,
                &parsed.question,
                config::SERVFAIL_EDE_CODE,
                "Resolution failure",
            )
            .map_err(|error| {
                Error::RustError(format!("failed to build SERVFAIL response: {error}"))
            })?,
        }
    };

    doh_response(wire, parsed.wants_json)
}

async fn parse_request(mut req: Request) -> std::result::Result<ParsedDohRequest, ClientError> {
    let wants_json =
        wants_dns_json(req.headers()).map_err(|_| ClientError::new(400, "invalid_dns_query"))?;
    let body = match req.method() {
        Method::Post => {
            if !has_media_type(req.headers(), DNS_MEDIA_TYPE)
                .map_err(|_| ClientError::new(400, "invalid_dns_query"))?
            {
                return Err(ClientError::new(415, "unsupported_media_type"));
            }
            let content_length = req
                .headers()
                .get("Content-Length")
                .map_err(|_| ClientError::new(400, "invalid_dns_query"))?;
            if content_length
                .as_deref()
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > MAX_DNS_MESSAGE_SIZE)
            {
                return Err(ClientError::new(413, "dns_message_too_large"));
            }
            let body = req
                .bytes()
                .await
                .map_err(|_| ClientError::new(400, "invalid_dns_query"))?;
            if body.len() > MAX_DNS_MESSAGE_SIZE {
                return Err(ClientError::new(413, "dns_message_too_large"));
            }
            body
        }
        Method::Get => parse_get_payload(&req)?,
        _ => return Err(ClientError::method_not_allowed()),
    };
    let (id, question) =
        validate_query(&body).map_err(|()| ClientError::new(400, "invalid_dns_query"))?;
    Ok(ParsedDohRequest {
        body,
        question,
        id,
        wants_json,
    })
}

fn parse_get_payload(req: &Request) -> std::result::Result<Vec<u8>, ClientError> {
    let url = req
        .url()
        .map_err(|_| ClientError::new(400, "invalid_dns_query"))?;
    let parameters: Vec<_> = url.query_pairs().collect();
    let dns = parameters
        .iter()
        .find(|(key, _)| key == "dns")
        .map(|(_, value)| value.as_ref());
    let name = parameters
        .iter()
        .find(|(key, _)| key == "name")
        .map(|(_, value)| value.as_ref());
    if dns.is_some() && name.is_some() {
        return Err(ClientError::new(400, "ambiguous_query"));
    }
    if let Some(dns) = dns {
        if dns.is_empty() {
            return Err(ClientError::new(400, "invalid_dns_query"));
        }
        let payload = decode_base64url(dns)?;
        if payload.len() > MAX_DNS_MESSAGE_SIZE {
            return Err(ClientError::new(413, "dns_message_too_large"));
        }
        return Ok(payload);
    }
    let Some(name) = name.filter(|name| !name.is_empty()) else {
        return Err(ClientError::new(400, "missing_name_or_type"));
    };
    let qtype = parameters
        .iter()
        .find(|(key, _)| key == "type")
        .map(|(_, value)| value.as_ref());
    build_get_query(name, parse_qtype(qtype)?)
}

fn decode_base64url(value: &str) -> std::result::Result<Vec<u8>, ClientError> {
    if value.is_empty() {
        return Err(ClientError::new(400, "invalid_dns_query"));
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ClientError::new(400, "invalid_dns_query"))
}

fn build_get_query(name: &str, qtype: u16) -> std::result::Result<Vec<u8>, ClientError> {
    let encoded_name = encode_name(name).map_err(|_| ClientError::new(400, "invalid_dns_query"))?;
    let id = random_query_id().map_err(|_| ClientError::new(400, "invalid_dns_query"))?;
    let capacity = 12_usize
        .checked_add(encoded_name.len())
        .and_then(|length| length.checked_add(4))
        .ok_or_else(|| ClientError::new(400, "invalid_dns_query"))?;
    let mut wire = Vec::with_capacity(capacity);
    wire.extend_from_slice(&id.to_be_bytes());
    wire.extend_from_slice(&0x0100_u16.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&[0; 6]);
    wire.extend_from_slice(&encoded_name);
    wire.extend_from_slice(&qtype.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    Ok(wire)
}

fn parse_qtype(value: Option<&str>) -> std::result::Result<u16, ClientError> {
    let value = value.unwrap_or("A").to_ascii_uppercase();
    let named = match value.as_str() {
        "A" => Some(1),
        "AAAA" => Some(28),
        "TXT" => Some(16),
        "MX" => Some(15),
        "CNAME" => Some(5),
        "NS" => Some(2),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "HTTPS" => Some(65),
        "SVCB" => Some(64),
        _ => None,
    };
    named
        .or_else(|| {
            value
                .parse::<u16>()
                .ok()
                .filter(|type_code| *type_code != 0)
        })
        .ok_or_else(|| ClientError::new(400, "invalid_dns_query"))
}

fn random_query_id() -> Result<u16> {
    let crypto =
        worker::js_sys::Reflect::get(&worker::js_sys::global(), &JsValue::from_str("crypto"))?;
    let get_random_values =
        worker::js_sys::Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))?
            .dyn_into::<worker::js_sys::Function>()?;
    let bytes = worker::js_sys::Uint8Array::new_with_length(2);
    get_random_values.call1(&crypto, &bytes)?;
    Ok(u16::from_be_bytes([bytes.get_index(0), bytes.get_index(1)]))
}

fn validate_query(wire: &[u8]) -> std::result::Result<(u16, Question), ()> {
    let message = parse_message(wire).map_err(|_| ())?;
    let header = message.header;
    if header.flags & 0x8000 != 0
        || header.flags & 0x7800 != 0
        || header.qd_count != 1
        || header.an_count != 0
        || header.ns_count != 0
    {
        return Err(());
    }
    let question = message.questions.into_iter().next().ok_or(())?;
    if question.qclass != 1 || question.qtype == 0 {
        return Err(());
    }
    Ok((header.id, question))
}

fn wants_dns_json(headers: &Headers) -> Result<bool> {
    Ok(headers.get("Accept")?.is_some_and(|accept| {
        accept.split(',').any(|entry| {
            entry.split(';').next().is_some_and(|media_type| {
                media_type
                    .trim()
                    .eq_ignore_ascii_case("application/dns-json")
            })
        })
    }))
}

fn has_media_type(headers: &Headers, expected: &str) -> Result<bool> {
    Ok(headers.get("Content-Type")?.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
    }))
}

fn is_canary(question: &Question) -> bool {
    matches!(question.qtype, TYPE_A | TYPE_AAAA)
        && question
            .name
            .trim_end_matches('.')
            .eq_ignore_ascii_case("use-application-dns.net")
}

fn canary_response(id: u16, question: &Question) -> Result<Vec<u8>> {
    build_response(id, &question.name, question.qtype, &[], 60, 0x8183)
        .map_err(|error| Error::RustError(format!("failed to build canary response: {error}")))
}

fn client_error_response(error: ClientError) -> Result<Response> {
    let mut response = json_response(&json!({ "error": error.error }), error.status)?;
    if error.allow {
        response.headers_mut().set("Allow", "GET, POST")?;
    }
    Ok(response)
}

fn doh_response(wire: Vec<u8>, wants_json: bool) -> Result<Response> {
    if wants_json {
        return match wire_to_json(&wire) {
            Ok(value) => dns_json_response(&value),
            Err(_) => json_response(&json!({ "error": "invalid_dns_response" }), 502),
        };
    }
    let builder = Response::builder()
        .with_header("Content-Type", DNS_MEDIA_TYPE)?
        .with_header("Cache-Control", "no-store")?
        .with_header("Vary", "Accept")?;
    Ok(builder.fixed(wire))
}

fn dns_json_response(value: &Value) -> Result<Response> {
    let body = serde_json::to_vec(value)
        .map_err(|error| Error::RustError(format!("failed to serialize DNS JSON: {error}")))?;
    let builder = Response::builder()
        .with_header("Content-Type", DNS_JSON_MEDIA_TYPE)?
        .with_header("Cache-Control", "no-store")?
        .with_header("Vary", "Accept")?;
    Ok(builder.fixed(body))
}

/// Converts a validated DNS wire response into the `application/dns-json` shape.
///
/// # Errors
///
/// Returns a Worker error when the wire response is malformed.
pub fn wire_to_json(wire: &[u8]) -> std::result::Result<Value, Error> {
    let message = parse_message(wire)
        .map_err(|error| Error::RustError(format!("invalid DNS response: {error}")))?;
    let flags = message.header.flags;
    let questions: Vec<_> = message
        .questions
        .iter()
        .map(|question| json!({ "name": question.name, "type": question.qtype }))
        .collect();
    let answers: Vec<_> = message
        .answers
        .iter()
        .map(|answer| {
            json!({
                "name": answer.name,
                "type": answer.rr_type,
                "TTL": answer.ttl,
                "data": rdata_to_json(answer.rr_type, &answer.rdata),
            })
        })
        .collect();
    let mut value = json!({
        "Status": flags & 0x000f,
        "TC": flags & 0x0200 != 0,
        "RD": flags & 0x0100 != 0,
        "RA": flags & 0x0080 != 0,
        "AD": flags & 0x0020 != 0,
        "CD": flags & 0x0010 != 0,
        "Question": questions,
    });
    if !answers.is_empty() {
        value["Answer"] = Value::Array(answers);
    }
    Ok(value)
}

fn rdata_to_json(record_type: u16, rdata: &[u8]) -> String {
    match record_type {
        TYPE_A if rdata.len() == 4 => {
            format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
        }
        TYPE_AAAA if rdata.len() == 16 => rdata
            .chunks_exact(2)
            .map(|chunk| format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])))
            .collect::<Vec<_>>()
            .join(":"),
        _ => URL_SAFE_NO_PAD.encode(rdata),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_base64url, parse_qtype, validate_query, wire_to_json};
    use crate::dns::{build_response, encode_name, wire::TYPE_A};

    #[test]
    fn validates_base64url_wire_queries() {
        assert_eq!(decode_base64url("AAEC_w"), Ok(vec![0, 1, 2, 255]));
        assert!(decode_base64url("AA==").is_err());
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234_u16.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[0; 6]);
        let encoded_name = match encode_name("example.com") {
            Ok(name) => name,
            Err(error) => panic!("test name must encode: {error}"),
        };
        query.extend_from_slice(&encoded_name);
        query.extend_from_slice(&TYPE_A.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());

        let (id, question) = match validate_query(&query) {
            Ok(query) => query,
            Err(()) => panic!("test query must validate"),
        };
        assert_eq!(id, 0x1234);
        assert_eq!(question.name, "example.com");
        assert_eq!(parse_qtype(Some("HTTPS")), Ok(65));
        assert!(parse_qtype(Some("0")).is_err());
    }

    #[test]
    fn converts_a_answers_to_dns_json() {
        let wire = match build_response(1, "example.com", TYPE_A, &[vec![192, 0, 2, 1]], 60, 0x8180)
        {
            Ok(wire) => wire,
            Err(error) => panic!("test response must build: {error}"),
        };
        let json = match wire_to_json(&wire) {
            Ok(json) => json,
            Err(error) => panic!("test response must convert: {error}"),
        };
        assert_eq!(json["Status"], 0);
        assert_eq!(json["Question"][0]["name"], "example.com");
        assert_eq!(json["Answer"][0]["data"], "192.0.2.1");
    }
}
