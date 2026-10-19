mod edns;
mod message;
mod rdata;
mod serde_bridge;
mod svcb;
#[cfg(test)]
mod tests;
mod validation;

use domain::base::iana::Rtype;
use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;

fn input<T: DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
}
fn output<T: Serialize>(value: Result<T, String>) -> Result<String, JsValue> {
    let value = value.map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&value).map_err(|e| JsValue::from_str(&e.to_string()))
}
fn binary(value: Result<Vec<u8>, String>) -> Result<Vec<u8>, JsValue> {
    value.map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen(js_name=parseMessageJson)]
pub fn parse_message(packet: &[u8]) -> Result<String, JsValue> {
    output(message::parse(packet))
}
#[wasm_bindgen(js_name=encodeMessageJson)]
pub fn encode_message(json: &str, options: &str) -> Result<Vec<u8>, JsValue> {
    binary(message::encode(input(json)?, input(options)?))
}
#[wasm_bindgen(js_name=buildQuery)]
pub fn build_query(name: &str, rtype: u16, id: u16) -> Result<Vec<u8>, JsValue> {
    binary(message::query(name, rtype, id))
}
#[wasm_bindgen(js_name=decodeRdataJson)]
pub fn decode_rdata(rtype: u16, bytes: &[u8]) -> Result<String, JsValue> {
    output(rdata::decode_bytes(rtype, bytes))
}
#[wasm_bindgen(js_name=encodeRdataJson)]
pub fn encode_rdata(rtype: u16, json: &str) -> Result<Vec<u8>, JsValue> {
    binary(rdata::encode(rtype, &input(json)?))
}
#[wasm_bindgen(js_name=encodeEcsJson)]
pub fn encode_ecs(json: &str) -> Result<Vec<u8>, JsValue> {
    binary(edns::encode_ecs(input(json)?))
}
#[wasm_bindgen(js_name=decodeEcsJson)]
pub fn decode_ecs(bytes: &[u8]) -> Result<String, JsValue> {
    output(edns::decode_ecs(bytes))
}
#[wasm_bindgen(js_name=encodeEdeJson)]
pub fn encode_ede(json: &str) -> Result<Vec<u8>, JsValue> {
    binary(edns::encode_ede(input(json)?))
}
#[wasm_bindgen(js_name=decodeEdeJson)]
pub fn decode_ede(bytes: &[u8]) -> Result<String, JsValue> {
    output(edns::decode_ede(bytes))
}
#[wasm_bindgen(js_name=encodeSvcParamJson)]
pub fn encode_svc_param(key: u16, json: &str) -> Result<Vec<u8>, JsValue> {
    binary(svcb::encode_param(key, input(json)?))
}
#[wasm_bindgen(js_name=decodeSvcParamJson)]
pub fn decode_svc_param(key: u16, bytes: &[u8]) -> Result<String, JsValue> {
    output(svcb::decode_param(key, bytes))
}
#[wasm_bindgen(js_name=validateMessageJson)]
pub fn validate_message(bytes: &[u8]) -> Result<String, JsValue> {
    output(validation::validate(bytes, None))
}
#[wasm_bindgen(js_name=matchResponseJson)]
pub fn match_response(bytes: &[u8], query: &[u8]) -> Result<String, JsValue> {
    output(validation::validate(bytes, Some(query)))
}
#[wasm_bindgen(js_name=extractIpsJson)]
pub fn extract_ips(bytes: &[u8]) -> Result<String, JsValue> {
    output(validation::extract_ips(bytes, None))
}
#[wasm_bindgen(js_name=toDnsJson)]
pub fn to_dns_json(bytes: &[u8]) -> Result<String, JsValue> {
    output(validation::dns_json(bytes))
}
#[wasm_bindgen(js_name=typeCode)]
pub fn type_code(name: &str) -> Result<u16, JsValue> {
    name.parse::<Rtype>()
        .map(|t| t.to_int())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen(js_name=typeName)]
pub fn type_name(code: u16) -> String {
    Rtype::from_int(code).to_string()
}
