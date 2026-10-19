use crate::rdata;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use domain::base::Name;
use domain::base::iana::SvcParamKey;
use domain::base::net::{Ipv4Addr, Ipv6Addr};
use domain::rdata::svcb::{SvcParams, SvcParamsBuilder, UnknownSvcParam};
use domain::rdata::{Https, Svcb};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Param {
    pub key: u16,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBinding {
    pub priority: u16,
    pub target: String,
    #[serde(default)]
    pub params: Vec<Param>,
}

pub fn decode(
    priority: u16,
    target: &Name<Vec<u8>>,
    params: &SvcParams<Vec<u8>>,
) -> Result<ServiceBinding, String> {
    for value in params.iter::<domain::rdata::svcb::value::AllValues<&[u8]>>() {
        value.map_err(|e| e.to_string())?;
    }
    let out = ServiceBinding {
        priority,
        target: crate::message::display_name(target),
        params: params
            .iter_raw()
            .map(|p| Param {
                key: p.key().to_int(),
                data: p.value().to_vec(),
            })
            .collect(),
    };
    validate(&out)?;
    Ok(out)
}

fn validate(svc: &ServiceBinding) -> Result<(), String> {
    let mut keys = std::collections::BTreeSet::new();
    for p in &svc.params {
        if p.key == 65535 || !keys.insert(p.key) {
            return Err("reserved or duplicate SvcParam key".into());
        }
        decode_param(p.key, &p.data)?;
    }
    // RFC 9460: clients ignore AliasMode parameters; preserve them without ServiceMode semantics.
    if svc.priority == 0 {
        return Ok(());
    }
    if keys.contains(&2) && !keys.contains(&1) {
        return Err("no-default-alpn requires alpn".into());
    }
    if let Some(p) = svc.params.iter().find(|p| p.key == 0) {
        for key in p
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_be_bytes([v[0], v[1]]))
        {
            if key == 0 || !keys.contains(&key) {
                return Err("mandatory references a missing/invalid key".into());
            }
        }
    }
    Ok(())
}

pub fn encode(rtype: u16, svc: &ServiceBinding) -> Result<Vec<u8>, String> {
    validate(svc)?;
    let target: Name<Vec<u8>> = svc
        .target
        .parse()
        .map_err(|e| format!("invalid SVCB target: {e}"))?;
    let mut builder = SvcParamsBuilder::<Vec<u8>>::empty();
    for p in &svc.params {
        let value = UnknownSvcParam::new(SvcParamKey::from_int(p.key), &p.data)
            .map_err(|e| e.to_string())?;
        builder.push(&value).map_err(|e| e.to_string())?;
    }
    let params = builder.freeze::<Vec<u8>>().map_err(|e| e.to_string())?;
    if rtype == 64 {
        rdata::compose(&Svcb::new(svc.priority, target, params).map_err(|e| e.to_string())?)
    } else {
        rdata::compose(&Https::new(svc.priority, target, params).map_err(|e| e.to_string())?)
    }
}

pub fn check_ech(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 6 || usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) != bytes.len() - 2 {
        return Err("invalid ECHConfigList length".into());
    }
    let mut p = 2;
    while p < bytes.len() {
        if p + 4 > bytes.len() {
            return Err("truncated ECHConfig".into());
        }
        let n = usize::from(u16::from_be_bytes([bytes[p + 2], bytes[p + 3]]));
        p += 4 + n;
        if p > bytes.len() {
            return Err("truncated ECHConfig contents".into());
        }
    }
    Ok(())
}

pub fn decode_param(key: u16, bytes: &[u8]) -> Result<Value, String> {
    match key {
        0 => {
            if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
                return Err("invalid mandatory parameter".into());
            }
            let keys: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .collect();
            if keys.contains(&0) || keys.windows(2).any(|v| v[0] >= v[1]) {
                return Err("mandatory keys must be nonzero, sorted and unique".into());
            }
            Ok(json!(keys))
        }
        1 => {
            let mut values = Vec::new();
            let mut p = 0;
            while p < bytes.len() {
                let n = usize::from(bytes[p]);
                p += 1;
                if n == 0 || p + n > bytes.len() {
                    return Err("invalid ALPN parameter".into());
                }
                // ALPN IDs are opaque bytes. Return byte strings, never lossy UTF-8.
                values.push(bytes[p..p + n].to_vec());
                p += n;
            }
            if values.is_empty() {
                return Err("empty ALPN parameter".into());
            }
            Ok(json!(values))
        }
        2 => {
            if !bytes.is_empty() {
                return Err("no-default-alpn must be empty".into());
            }
            Ok(Value::Null)
        }
        3 => {
            if bytes.len() != 2 {
                return Err("port must be two bytes".into());
            }
            Ok(json!(u16::from_be_bytes([bytes[0], bytes[1]])))
        }
        4 => {
            if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
                return Err("invalid ipv4hint".into());
            }
            Ok(json!(
                bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())
                    .collect::<Vec<_>>()
            ))
        }
        5 => {
            check_ech(bytes)?;
            Ok(json!(STANDARD.encode(bytes)))
        }
        6 => {
            if bytes.is_empty() || !bytes.len().is_multiple_of(16) {
                return Err("invalid ipv6hint".into());
            }
            Ok(json!(
                bytes
                    .as_chunks::<16>()
                    .0
                    .iter()
                    .map(|b| {
                        let mut a = [0; 16];
                        a.copy_from_slice(b);
                        Ipv6Addr::from(a).to_string()
                    })
                    .collect::<Vec<_>>()
            ))
        }
        65535 => Err("reserved SvcParam key".into()),
        _ => Ok(json!(bytes)),
    }
}

pub fn encode_param(key: u16, value: Value) -> Result<Vec<u8>, String> {
    let bytes = match key {
        0 => {
            let mut keys: Vec<u16> = serde_json::from_value(value).map_err(|e| e.to_string())?;
            keys.sort_unstable();
            keys.iter().flat_map(|k| k.to_be_bytes()).collect()
        }
        1 => {
            let items = value
                .as_array()
                .ok_or("ALPN must be an array of strings or byte arrays")?;
            let mut out = Vec::new();
            for v in items {
                let bytes = if let Some(s) = v.as_str() {
                    s.as_bytes().to_vec()
                } else {
                    serde_json::from_value::<Vec<u8>>(v.clone()).map_err(|e| e.to_string())?
                };
                if bytes.is_empty() || bytes.len() > 255 {
                    return Err("ALPN ID length must be 1..255".into());
                }
                out.push(bytes.len() as u8);
                out.extend(bytes);
            }
            out
        }
        2 => {
            if !value.is_null() {
                return Err("no-default-alpn value must be null".into());
            }
            Vec::new()
        }
        3 => serde_json::from_value::<u16>(value)
            .map_err(|e| e.to_string())?
            .to_be_bytes()
            .to_vec(),
        4 => {
            let items: Vec<String> = serde_json::from_value(value).map_err(|e| e.to_string())?;
            let mut out = Vec::new();
            for v in items {
                out.extend(
                    v.parse::<Ipv4Addr>()
                        .map_err(|_| "invalid IPv4 hint")?
                        .octets(),
                );
            }
            out
        }
        5 => {
            let s = value.as_str().ok_or("ECH must be a Base64 string")?;
            STANDARD
                .decode(s)
                .or_else(|_| URL_SAFE_NO_PAD.decode(s))
                .map_err(|e| e.to_string())?
        }
        6 => {
            let items: Vec<String> = serde_json::from_value(value).map_err(|e| e.to_string())?;
            let mut out = Vec::new();
            for v in items {
                out.extend(
                    v.parse::<Ipv6Addr>()
                        .map_err(|_| "invalid IPv6 hint")?
                        .octets(),
                );
            }
            out
        }
        _ => serde_json::from_value::<Vec<u8>>(value).map_err(|e| e.to_string())?,
    };
    if bytes.len() > 65535 {
        return Err("SvcParam value exceeds 65535 bytes".into());
    }
    decode_param(key, &bytes)?;
    Ok(bytes)
}
