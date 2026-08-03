use core::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::RequestCtx;

static NEXT_REQUEST_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    None,
}

impl LogLevel {
    const fn priority(self) -> u8 {
        match self {
            Self::Debug => 0,
            Self::Info => 1,
            Self::Warn => 2,
            Self::Error => 3,
            Self::None => u8::MAX,
        }
    }

    pub(crate) fn from_config(value: &str) -> Self {
        match value {
            "debug" => Self::Debug,
            "warn" => Self::Warn,
            "error" => Self::Error,
            "none" => Self::None,
            _ => Self::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp_ms: f64,
    pub elapsed_ms: f64,
    pub level: LogLevel,
    pub event: String,
    pub request_id: String,
    pub qname: String,
    pub qtype: u16,
    pub data: Value,
}

#[must_use]
pub(crate) fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        worker::js_sys::Date::now()
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |duration| duration.as_secs_f64() * 1_000.0)
    }
}

#[must_use]
pub(crate) fn request_id() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        use worker::wasm_bindgen::{JsCast, JsValue};

        let global = worker::js_sys::global();
        let crypto = worker::js_sys::Reflect::get(&global, &JsValue::from_str("crypto"));
        let uuid = crypto.as_ref().ok().and_then(|crypto| {
            worker::js_sys::Reflect::get(crypto, &JsValue::from_str("randomUUID"))
                .ok()
                .and_then(|value| value.dyn_into::<worker::js_sys::Function>().ok())
                .and_then(|function| function.call0(crypto).ok())
                .and_then(|value| value.as_string())
        });
        if let Some(uuid) = uuid {
            return uuid;
        }
    }

    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", now_ms().to_bits(), sequence)
}

pub(crate) fn log_event(ctx: &mut RequestCtx, level: LogLevel, event: &str, data: Value) {
    let timestamp_ms = now_ms();
    let configured_level = LogLevel::from_config(crate::config::LOG_LEVEL);
    let entry = LogEvent {
        timestamp_ms,
        elapsed_ms: (timestamp_ms - ctx.started_at_ms).max(0.0),
        level,
        event: event.to_owned(),
        request_id: ctx.request_id.clone(),
        qname: logged_qname(&ctx.qname, configured_level),
        qtype: ctx.qtype,
        data,
    };
    ctx.events.push(entry.clone());

    if level.priority() < configured_level.priority() {
        return;
    }

    #[cfg(target_arch = "wasm32")]
    {
        let Ok(line) = serde_json::to_string(&entry) else {
            return;
        };
        match level {
            LogLevel::Error => worker::console_error!("{line}"),
            LogLevel::Warn => worker::console_warn!("{line}"),
            LogLevel::Debug | LogLevel::Info => worker::console_log!("{line}"),
            LogLevel::None => {}
        }
    }
}

fn logged_qname(qname: &str, configured_level: LogLevel) -> String {
    if configured_level == LogLevel::Debug {
        qname.to_owned()
    } else {
        "[redacted]".to_owned()
    }
}

pub(crate) fn request_end(ctx: &mut RequestCtx, result: &str) {
    log_event(
        ctx,
        LogLevel::Info,
        "request_end",
        serde_json::json!({
            "result": result,
            "upstreams": ctx.upstreams,
            "owner": ctx.owner,
            "optimizationApplied": ctx.optimization_applied,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qname_is_redacted_unless_debug_logging_is_enabled() {
        let qname = "private.user.example.com";
        let mut ctx = RequestCtx {
            request_id: "request".to_owned(),
            started_at_ms: now_ms(),
            qname: qname.to_owned(),
            ..RequestCtx::default()
        };

        log_event(
            &mut ctx,
            LogLevel::Info,
            "request_start",
            serde_json::json!({}),
        );

        assert_eq!(ctx.events.len(), 1);
        assert_eq!(ctx.events[0].qname, "[redacted]");
        assert_eq!(logged_qname(qname, LogLevel::Debug), qname);
    }
}
