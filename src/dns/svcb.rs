use super::wire::{self, DnsError, Result};

pub const PARAM_MANDATORY: u16 = 0;
pub const PARAM_ALPN: u16 = 1;
pub const PARAM_NO_DEFAULT_ALPN: u16 = 2;
pub const PARAM_PORT: u16 = 3;
pub const PARAM_IPV4_HINT: u16 = 4;
pub const PARAM_ECH: u16 = 5;
pub const PARAM_IPV6_HINT: u16 = 6;
pub const PARAM_DOH_PATH: u16 = 7;
pub const PARAM_OHTTP: u16 = 8;
pub const PARAM_TLS_SUPPORTED_GROUPS: u16 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcbMode {
    AliasMode,
    ServiceMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcParamKey {
    Mandatory,
    Alpn,
    NoDefaultAlpn,
    Port,
    Ipv4Hint,
    Ech,
    Ipv6Hint,
    DohPath,
    Ohttp,
    TlsSupportedGroups,
    Unknown(u16),
}

impl SvcParamKey {
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            PARAM_MANDATORY => Self::Mandatory,
            PARAM_ALPN => Self::Alpn,
            PARAM_NO_DEFAULT_ALPN => Self::NoDefaultAlpn,
            PARAM_PORT => Self::Port,
            PARAM_IPV4_HINT => Self::Ipv4Hint,
            PARAM_ECH => Self::Ech,
            PARAM_IPV6_HINT => Self::Ipv6Hint,
            PARAM_DOH_PATH => Self::DohPath,
            PARAM_OHTTP => Self::Ohttp,
            PARAM_TLS_SUPPORTED_GROUPS => Self::TlsSupportedGroups,
            _ => Self::Unknown(code),
        }
    }

    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Mandatory => PARAM_MANDATORY,
            Self::Alpn => PARAM_ALPN,
            Self::NoDefaultAlpn => PARAM_NO_DEFAULT_ALPN,
            Self::Port => PARAM_PORT,
            Self::Ipv4Hint => PARAM_IPV4_HINT,
            Self::Ech => PARAM_ECH,
            Self::Ipv6Hint => PARAM_IPV6_HINT,
            Self::DohPath => PARAM_DOH_PATH,
            Self::Ohttp => PARAM_OHTTP,
            Self::TlsSupportedGroups => PARAM_TLS_SUPPORTED_GROUPS,
            Self::Unknown(code) => code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcParam {
    pub key: SvcParamKey,
    pub value: Vec<u8>,
}

impl SvcParam {
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.key.code()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcbRecord {
    pub priority: u16,
    pub target: String,
    pub params: Vec<SvcParam>,
}

impl SvcbRecord {
    #[must_use]
    pub const fn mode(&self) -> SvcbMode {
        if self.priority == 0 {
            SvcbMode::AliasMode
        } else {
            SvcbMode::ServiceMode
        }
    }

    #[must_use]
    pub fn param(&self, key: u16) -> Option<&[u8]> {
        self.params
            .iter()
            .find(|param| param.code() == key)
            .map(|param| param.value.as_slice())
    }

    /// # Errors
    ///
    /// Returns an error when the resulting parameter set is invalid.
    pub fn replace_param(&mut self, key: u16, value: Vec<u8>) -> Result<bool> {
        if self.mode() == SvcbMode::AliasMode {
            return Ok(false);
        }
        let mut params = self.params.clone();
        params.retain(|param| param.code() != key);
        params.push(SvcParam {
            key: SvcParamKey::from_code(key),
            value,
        });
        params.sort_by_key(SvcParam::code);
        validate_params(&params)?;
        self.params = params;
        Ok(true)
    }

    /// # Errors
    ///
    /// Returns an error when the resulting parameter set is invalid.
    pub fn remove_param(&mut self, key: u16) -> Result<bool> {
        if self.mode() == SvcbMode::AliasMode {
            return Ok(false);
        }
        if self.param(key).is_none() {
            return Ok(false);
        }
        let mut params = self.params.clone();
        params.retain(|param| param.code() != key);
        if key != PARAM_MANDATORY {
            remove_from_mandatory(&mut params, key)?;
        }
        validate_params(&params)?;
        self.params = params;
        Ok(true)
    }

    /// # Errors
    ///
    /// Returns an error when the record is invalid or too large to encode.
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        if self.mode() == SvcbMode::AliasMode && (self.target.is_empty() || !self.params.is_empty())
        {
            return Err(DnsError::new("invalid SVCB alias-mode record"));
        }
        validate_params(&self.params)?;
        let target = wire::encode_name(&self.target)?;
        let mut output = Vec::with_capacity(
            2_usize
                .checked_add(target.len())
                .ok_or(DnsError::new("SVCB RDATA exceeds 65535 octets"))?,
        );
        output.extend_from_slice(&self.priority.to_be_bytes());
        output.extend_from_slice(&target);
        for param in &self.params {
            let length = u16::try_from(param.value.len())
                .map_err(|_| DnsError::new("SVCB parameter exceeds 65535 octets"))?;
            output.extend_from_slice(&param.code().to_be_bytes());
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(&param.value);
        }
        if output.len() > usize::from(u16::MAX) {
            return Err(DnsError::new("SVCB RDATA exceeds 65535 octets"));
        }
        Ok(output)
    }
}

/// # Errors
///
/// Returns an error when SVCB RDATA is malformed.
pub fn parse_rdata(rdata: &[u8]) -> Result<SvcbRecord> {
    parse_rdata_in_message(rdata, 0, rdata.len())
}

/// # Errors
///
/// Returns an error when the message bounds or SVCB RDATA are malformed.
pub fn parse_rdata_in_message(
    message: &[u8],
    rdata_start: usize,
    rdata_end: usize,
) -> Result<SvcbRecord> {
    if rdata_start > rdata_end || rdata_end > message.len() {
        return Err(DnsError::new("invalid SVCB RDATA bounds"));
    }
    let priority_end = rdata_start
        .checked_add(2)
        .ok_or(DnsError::new("SVCB offset overflow"))?;
    let priority_bytes = message
        .get(rdata_start..priority_end)
        .filter(|_| priority_end <= rdata_end)
        .ok_or(DnsError::new("truncated SVCB RDATA"))?;
    let priority = u16::from_be_bytes([priority_bytes[0], priority_bytes[1]]);
    let mut cursor = priority_end;
    let target = wire::decode_name(message, &mut cursor)?;
    if cursor > rdata_end {
        return Err(DnsError::new("SVCB target exceeds RDATA"));
    }
    let mut params = Vec::new();
    let mut previous = None;
    while cursor < rdata_end {
        let key = read_u16(message, &mut cursor, rdata_end)?;
        if previous.is_some_and(|previous| key <= previous) {
            return Err(DnsError::new("SVCB parameters are not strictly ordered"));
        }
        previous = Some(key);
        let length = usize::from(read_u16(message, &mut cursor, rdata_end)?);
        let end = cursor
            .checked_add(length)
            .ok_or(DnsError::new("SVCB offset overflow"))?;
        let value = message
            .get(cursor..end)
            .filter(|_| end <= rdata_end)
            .ok_or(DnsError::new("truncated SVCB parameter"))?
            .to_vec();
        params.push(SvcParam {
            key: SvcParamKey::from_code(key),
            value,
        });
        cursor = end;
    }
    Ok(SvcbRecord {
        priority,
        target,
        params,
    })
}

/// # Errors
///
/// Returns an error when the ECH value or SVCB RDATA is invalid.
pub fn replace_ech(rdata: &[u8], ech: &[u8]) -> Result<Option<Vec<u8>>> {
    if ech.is_empty() {
        return Err(DnsError::new("SVCB ECH parameter is empty"));
    }
    let mut record = parse_rdata(rdata)?;
    if !record.replace_param(PARAM_ECH, ech.to_vec())? {
        return Ok(None);
    }
    record.to_wire().map(Some)
}

fn read_u16(data: &[u8], cursor: &mut usize, end: usize) -> Result<u16> {
    let next = cursor
        .checked_add(2)
        .ok_or(DnsError::new("SVCB offset overflow"))?;
    let bytes = data
        .get(*cursor..next)
        .filter(|_| next <= end)
        .ok_or(DnsError::new("truncated SVCB parameter"))?;
    *cursor = next;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn remove_from_mandatory(params: &mut Vec<SvcParam>, key: u16) -> Result<()> {
    let Some(index) = params
        .iter()
        .position(|param| param.code() == PARAM_MANDATORY)
    else {
        return Ok(());
    };
    let mut mandatory = mandatory_keys(&params[index].value)?;
    mandatory.retain(|mandatory_key| *mandatory_key != key);
    if mandatory.is_empty() {
        params.remove(index);
    } else {
        params[index].value = encode_mandatory(&mandatory);
    }
    Ok(())
}

fn validate_params(params: &[SvcParam]) -> Result<()> {
    for pair in params.windows(2) {
        if pair[0].code() >= pair[1].code() {
            return Err(DnsError::new("SVCB parameters are not strictly ordered"));
        }
    }
    if let Some(mandatory) = params.iter().find(|param| param.code() == PARAM_MANDATORY) {
        for key in mandatory_keys(&mandatory.value)? {
            if !params.iter().any(|param| param.code() == key) {
                return Err(DnsError::new("SVCB mandatory parameter is missing"));
            }
        }
    }
    Ok(())
}

fn mandatory_keys(value: &[u8]) -> Result<Vec<u16>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(DnsError::new("invalid SVCB mandatory parameter"));
    }
    let mut keys = Vec::with_capacity(value.len() / 2);
    let mut previous = None;
    for item in value.chunks_exact(2) {
        let key = u16::from_be_bytes([item[0], item[1]]);
        if key == PARAM_MANDATORY || previous.is_some_and(|previous| key <= previous) {
            return Err(DnsError::new("invalid SVCB mandatory parameter"));
        }
        previous = Some(key);
        keys.push(key);
    }
    Ok(keys)
}

fn encode_mandatory(keys: &[u16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(keys.len() * 2);
    for key in keys {
        output.extend_from_slice(&key.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn must<T>(result: Result<T>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("test operation must succeed: {error}"),
        }
    }

    fn service_record(params: Vec<SvcParam>) -> SvcbRecord {
        SvcbRecord {
            priority: 1,
            target: String::new(),
            params,
        }
    }

    fn mandatory_value(keys: &[u16]) -> Vec<u8> {
        keys.iter().flat_map(|key| key.to_be_bytes()).collect()
    }

    #[test]
    fn round_trips_alias_and_service_modes() {
        let alias = SvcbRecord {
            priority: 0,
            target: "alias.example".to_owned(),
            params: vec![],
        };
        let alias_wire = must(alias.to_wire());
        assert_eq!(must(parse_rdata(&alias_wire)), alias);

        let service = service_record(vec![
            SvcParam {
                key: SvcParamKey::Mandatory,
                value: mandatory_value(&[PARAM_ALPN, PARAM_IPV4_HINT, PARAM_ECH, PARAM_IPV6_HINT]),
            },
            SvcParam {
                key: SvcParamKey::Alpn,
                value: b"\x02h2".to_vec(),
            },
            SvcParam {
                key: SvcParamKey::Ipv4Hint,
                value: vec![192, 0, 2, 1],
            },
            SvcParam {
                key: SvcParamKey::Ech,
                value: b"ech".to_vec(),
            },
            SvcParam {
                key: SvcParamKey::Ipv6Hint,
                value: vec![0; 16],
            },
        ]);
        let service_wire = must(service.to_wire());
        let parsed = must(parse_rdata(&service_wire));
        assert_eq!(parsed.mode(), SvcbMode::ServiceMode);
        assert_eq!(parsed.param(PARAM_ECH), Some(&b"ech"[..]));
        assert_eq!(must(parsed.to_wire()), service_wire);
    }

    #[test]
    fn parses_a_compressed_target_from_message_wire() {
        let mut message = must(wire::encode_name("target.example"));
        let rdata_start = message.len();
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0]);
        let record = must(parse_rdata_in_message(&message, rdata_start, message.len()));
        assert_eq!(record.target, "target.example");
        assert_eq!(
            must(record.to_wire()),
            vec![
                0, 1, 6, b't', b'a', b'r', b'g', b'e', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l',
                b'e', 0
            ]
        );
    }

    #[test]
    fn replacing_ech_preserves_mandatory_consistency() {
        let record = service_record(vec![
            SvcParam {
                key: SvcParamKey::Mandatory,
                value: mandatory_value(&[PARAM_ECH]),
            },
            SvcParam {
                key: SvcParamKey::Ech,
                value: b"old".to_vec(),
            },
        ]);
        let updated = match replace_ech(&must(record.to_wire()), b"new") {
            Ok(Some(value)) => value,
            Ok(None) => panic!("service-mode record must be modified"),
            Err(error) => panic!("ECH replacement must succeed: {error}"),
        };
        let parsed = must(parse_rdata(&updated));
        assert_eq!(parsed.param(PARAM_ECH), Some(&b"new"[..]));
        let mandatory = mandatory_value(&[PARAM_ECH]);
        assert_eq!(parsed.param(PARAM_MANDATORY), Some(mandatory.as_slice()));
    }

    #[test]
    fn removing_a_hint_removes_its_mandatory_reference() {
        let mut record = service_record(vec![
            SvcParam {
                key: SvcParamKey::Mandatory,
                value: mandatory_value(&[PARAM_IPV4_HINT, PARAM_ECH]),
            },
            SvcParam {
                key: SvcParamKey::Ipv4Hint,
                value: vec![192, 0, 2, 1],
            },
            SvcParam {
                key: SvcParamKey::Ech,
                value: b"ech".to_vec(),
            },
        ]);
        assert_eq!(must(record.remove_param(PARAM_IPV4_HINT)), true);
        assert_eq!(record.param(PARAM_IPV4_HINT), None);
        let mandatory = mandatory_value(&[PARAM_ECH]);
        assert_eq!(record.param(PARAM_MANDATORY), Some(mandatory.as_slice()));
        assert!(record.to_wire().is_ok());
    }

    #[test]
    fn replacement_sorts_parameter_keys() {
        let mut record = service_record(vec![
            SvcParam {
                key: SvcParamKey::Ech,
                value: b"old".to_vec(),
            },
            SvcParam {
                key: SvcParamKey::Alpn,
                value: b"\x02h2".to_vec(),
            },
        ]);
        assert_eq!(
            must(record.replace_param(PARAM_IPV4_HINT, vec![192, 0, 2, 1])),
            true
        );
        assert_eq!(
            record.params.iter().map(SvcParam::code).collect::<Vec<_>>(),
            vec![PARAM_ALPN, PARAM_IPV4_HINT, PARAM_ECH]
        );
    }

    #[test]
    fn replacement_preserves_unknown_parameters() {
        let record = service_record(vec![
            SvcParam {
                key: SvcParamKey::Alpn,
                value: b"\x02h2".to_vec(),
            },
            SvcParam {
                key: SvcParamKey::Unknown(65_000),
                value: vec![1, 2, 3],
            },
        ]);
        let updated = match replace_ech(&must(record.to_wire()), b"ech") {
            Ok(Some(value)) => value,
            Ok(None) => panic!("service-mode record must be modified"),
            Err(error) => panic!("ECH replacement must succeed: {error}"),
        };
        let parsed = must(parse_rdata(&updated));
        assert_eq!(parsed.param(65_000), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn does_not_modify_alias_mode() {
        let alias = SvcbRecord {
            priority: 0,
            target: "alias.example".to_owned(),
            params: vec![],
        };
        assert_eq!(replace_ech(&must(alias.to_wire()), b"ech"), Ok(None));
    }

    #[test]
    fn removing_ech_synchronizes_the_mandatory_list() {
        let mut record = service_record(vec![
            SvcParam {
                key: SvcParamKey::Mandatory,
                value: mandatory_value(&[PARAM_ALPN, PARAM_ECH]),
            },
            SvcParam {
                key: SvcParamKey::Alpn,
                value: b"\x02h2".to_vec(),
            },
            SvcParam {
                key: SvcParamKey::Ech,
                value: b"ech".to_vec(),
            },
        ]);
        assert_eq!(must(record.remove_param(PARAM_ECH)), true);
        assert_eq!(record.param(PARAM_ECH), None);
        let mandatory = mandatory_value(&[PARAM_ALPN]);
        assert_eq!(record.param(PARAM_MANDATORY), Some(mandatory.as_slice()));
        assert!(record.to_wire().is_ok());

        let mut record = service_record(vec![
            SvcParam {
                key: SvcParamKey::Mandatory,
                value: mandatory_value(&[PARAM_ECH]),
            },
            SvcParam {
                key: SvcParamKey::Ech,
                value: b"ech".to_vec(),
            },
        ]);
        assert_eq!(must(record.remove_param(PARAM_ECH)), true);
        assert_eq!(record.param(PARAM_ECH), None);
        assert_eq!(record.param(PARAM_MANDATORY), None);
        assert!(record.to_wire().is_ok());
    }
}
