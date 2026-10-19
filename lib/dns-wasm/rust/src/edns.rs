use domain::base::iana::{ExtendedErrorCode, OptionCode};
use domain::base::net::IpAddr;
use domain::base::opt::{ClientSubnet, ComposeOptData, ExtendedError, Opt, UnknownOptData};
use octseq::parse::Parser;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OptData {
    #[serde(default)]
    pub options: Vec<EdnsOption>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ecs {
    pub address: String,
    pub source_prefix: u8,
    #[serde(default)]
    pub scope_prefix: u8,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ede {
    pub code: u16,
    #[serde(default)]
    pub text: String,
}

pub fn decode_ecs(bytes: &[u8]) -> Result<Ecs, String> {
    let mut parser = Parser::from_ref(&bytes);
    let ecs = ClientSubnet::parse(&mut parser).map_err(|e| e.to_string())?;
    if parser.remaining() != 0 {
        return Err("trailing bytes in ECS".into());
    }
    let width = if ecs.addr().is_ipv4() { 32 } else { 128 };
    if ecs.source_prefix_len() > width || ecs.scope_prefix_len() > width {
        return Err("ECS prefix exceeds address width".into());
    }
    Ok(Ecs {
        address: ecs.addr().to_string(),
        source_prefix: ecs.source_prefix_len(),
        scope_prefix: ecs.scope_prefix_len(),
    })
}

pub fn encode_ecs(value: Ecs) -> Result<Vec<u8>, String> {
    let addr: IpAddr = value
        .address
        .parse()
        .map_err(|_| "invalid ECS IP address")?;
    let width = if addr.is_ipv4() { 32 } else { 128 };
    if value.source_prefix > width || value.scope_prefix > width {
        return Err("ECS prefix exceeds address width".into());
    }
    let ecs = ClientSubnet::new(value.source_prefix, value.scope_prefix, addr);
    let mut out = Vec::new();
    ecs.compose_option(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn decode_ede(bytes: &[u8]) -> Result<Ede, String> {
    let mut parser = Parser::from_ref(&bytes);
    let ede = ExtendedError::<&[u8]>::parse(&mut parser).map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(ede.text_slice().unwrap_or_default())
        .map_err(|_| "invalid UTF-8 in EDE text")?;
    Ok(Ede {
        code: ede.code().to_int(),
        text: text.into(),
    })
}

pub fn encode_ede(value: Ede) -> Result<Vec<u8>, String> {
    let ede = ExtendedError::<Vec<u8>>::new_with_str(
        ExtendedErrorCode::from_int(value.code),
        &value.text,
    )
    .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    ede.compose_option(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn validate_option(option: &EdnsOption) -> Result<(), String> {
    match option.code {
        8 => {
            decode_ecs(&option.data)?;
        }
        15 if option.data.len() < 2 => return Err("short EDE option".into()),
        _ => (),
    }
    Ok(())
}

pub fn decode_options(opt: &Opt<Vec<u8>>) -> Result<Vec<EdnsOption>, String> {
    let mut options = Vec::new();
    for item in opt.iter::<UnknownOptData<_>>() {
        let item = item.map_err(|e| e.to_string())?;
        let option = EdnsOption {
            code: item.code().to_int(),
            data: item.data().to_vec(),
        };
        validate_option(&option)?;
        options.push(option);
    }
    Ok(options)
}

pub fn encode_options(options: &[EdnsOption]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for option in options {
        validate_option(option)?;
        let item = UnknownOptData::new(OptionCode::from_int(option.code), &option.data)
            .map_err(|e| e.to_string())?;
        out.extend_from_slice(&option.code.to_be_bytes());
        out.extend_from_slice(&item.compose_len().to_be_bytes());
        item.compose_option(&mut out).map_err(|e| e.to_string())?;
        if out.len() > 65535 {
            return Err("EDNS options exceed 65535 bytes".into());
        }
    }
    Ok(out)
}
