use crate::{edns, svcb};
use domain::base::iana::Rtype;
use domain::base::name::ParsedName;
use domain::base::rdata::{ComposeRecordData, ParseAnyRecordData};
use domain::base::{Name, RecordData};
use domain::rdata::{AllRecordData, ZoneRecordData};
use octseq::parse::Parser;
use serde_json::{Value, json};

pub type OwnedData = AllRecordData<Vec<u8>, Name<Vec<u8>>>;
pub type ZoneData = ZoneRecordData<Vec<u8>, Name<Vec<u8>>>;

pub fn compose(data: &impl ComposeRecordData) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    data.compose_rdata(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > 65535 {
        return Err("RDATA exceeds 65535 bytes".into());
    }
    Ok(bytes)
}

pub fn normalize(rtype: u16, bytes: &[u8]) -> Result<(Vec<u8>, String), String> {
    if bytes.len() > 65535 {
        return Err("RDATA exceeds 65535 bytes".into());
    }
    let mut parser = Parser::from_ref(bytes);
    let data =
        AllRecordData::<_, ParsedName<_>>::parse_any_rdata(Rtype::from_int(rtype), &mut parser)
            .map_err(|e| e.to_string())?;
    if parser.remaining() != 0 {
        return Err("trailing bytes in RDATA".into());
    }
    Ok((compose(&data)?, data.to_string()))
}

pub fn decode(data: OwnedData) -> Result<Value, String> {
    match data {
        AllRecordData::Opt(opt) => Ok(json!({"Opt": {"options": edns::decode_options(&opt)?}})),
        AllRecordData::Svcb(data) => {
            Ok(json!({"Svcb": svcb::decode(data.priority(), data.target(), data.params())?}))
        }
        AllRecordData::Https(data) => {
            Ok(json!({"Https": svcb::decode(data.priority(), data.target(), data.params())?}))
        }
        AllRecordData::Unknown(data) => Ok(json!({"Raw": data.data()})),
        other => {
            let zone: Result<ZoneData, OwnedData> = other.into();
            match zone {
                Ok(zone) => serde_json::to_value(zone).map_err(|e| e.to_string()),
                Err(pseudo) => Ok(json!({"Raw": compose(&pseudo)?})),
            }
        }
    }
}

pub fn decode_bytes(rtype: u16, bytes: &[u8]) -> Result<Value, String> {
    use domain::base::name::FlattenInto;
    let (normal, _) = normalize(rtype, bytes)?;
    if normal != bytes {
        return Err("standalone RDATA must not contain compressed names".into());
    }
    let mut parser = Parser::from_ref(bytes);
    let data =
        AllRecordData::<_, ParsedName<_>>::parse_any_rdata(Rtype::from_int(rtype), &mut parser)
            .map_err(|e| e.to_string())?;
    let owned: OwnedData = data.try_flatten_into().map_err(|e| format!("{e:?}"))?;
    decode(owned)
}

pub fn encode(rtype: u16, value: &Value) -> Result<Vec<u8>, String> {
    if value.as_object().map(|v| v.len()) != Some(1) {
        return Err("RDATA must contain exactly one variant".into());
    }
    let bytes = if let Some(raw) = value.get("Raw") {
        serde_json::from_value::<Vec<u8>>(raw.clone()).map_err(|e| e.to_string())?
    } else if let Some(opt) = value.get("Opt") {
        if rtype != 41 {
            return Err("Opt RDATA requires type 41".into());
        }
        let options =
            serde_json::from_value::<edns::OptData>(opt.clone()).map_err(|e| e.to_string())?;
        edns::encode_options(&options.options)?
    } else if let Some(svc) = value.get("Svcb").or_else(|| value.get("Https")) {
        let expected = if value.get("Svcb").is_some() { 64 } else { 65 };
        if rtype != expected {
            return Err("SVCB/HTTPS RDATA type mismatch".into());
        }
        let svc = serde_json::from_value::<svcb::ServiceBinding>(svc.clone())
            .map_err(|e| e.to_string())?;
        svcb::encode(rtype, &svc)?
    } else {
        let data: ZoneData = crate::serde_bridge::from_value(value.clone())
            .map_err(|e| format!("invalid native RDATA: {e}"))?;
        if RecordData::rtype(&data).to_int() != rtype {
            return Err("record type and RDATA variant do not match".into());
        }
        if let ZoneData::Ipseckey(key) = &data
            && !key.gateway().is_correct_gateway_type(key.gateway_type())
        {
            return Err("IPSECKEY gateway and gateway_type do not match".into());
        }
        compose(&data)?
    };
    let (normal, _) = normalize(rtype, &bytes)?;
    if normal != bytes {
        return Err("standalone RDATA must not contain compressed names".into());
    }
    if rtype == 41 || rtype == 64 || rtype == 65 {
        let _ = decode_bytes(rtype, &bytes)?;
    }
    Ok(bytes)
}
