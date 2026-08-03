//! DNS message parsing and serialization (RFC 1035).

use core::fmt;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;
pub const MAX_JUMPS: usize = 128;
const MAX_WIRE_SIZE: usize = u16::MAX as usize;
const MAX_QUERY_ADDITIONAL_RECORDS: u16 = 32;
const MAX_RESPONSE_SECTION_RECORDS: u16 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsError {
    message: &'static str,
}

impl DnsError {
    pub(crate) const fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for DnsError {}

pub type Result<T> = std::result::Result<T, DnsError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcbRecord {
    pub priority: u16,
    pub target: String,
    pub params: Vec<(u16, Vec<u8>)>,
}

fn read_u16(data: &[u8], cursor: &mut usize) -> Result<u16> {
    let bytes = data
        .get(
            *cursor
                ..cursor
                    .checked_add(2)
                    .ok_or(DnsError::new("DNS offset overflow"))?,
        )
        .ok_or(DnsError::new("truncated DNS field"))?;
    *cursor = cursor
        .checked_add(2)
        .ok_or(DnsError::new("DNS offset overflow"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32> {
    let bytes = data
        .get(
            *cursor
                ..cursor
                    .checked_add(4)
                    .ok_or(DnsError::new("DNS offset overflow"))?,
        )
        .ok_or(DnsError::new("truncated DNS field"))?;
    *cursor = cursor
        .checked_add(4)
        .ok_or(DnsError::new("DNS offset overflow"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// Decodes a possibly compressed DNS name and advances `cursor` past its wire form.
///
/// # Errors
///
/// Returns an error for truncated, malformed, or cyclic DNS names.
pub fn decode_name(data: &[u8], cursor: &mut usize) -> Result<String> {
    let mut labels = Vec::new();
    let mut position = *cursor;
    let mut jumped = false;
    let mut jumps = 0_usize;
    let mut seen = [u16::MAX; MAX_JUMPS];
    let mut wire_length = 1_usize;

    loop {
        let length = *data
            .get(position)
            .ok_or(DnsError::new("truncated DNS name"))?;
        if length & 0xc0 == 0xc0 {
            let low = *data
                .get(
                    position
                        .checked_add(1)
                        .ok_or(DnsError::new("DNS offset overflow"))?,
                )
                .ok_or(DnsError::new("truncated DNS pointer"))?;
            let target = usize::from((u16::from(length & 0x3f) << 8) | u16::from(low));
            let target = u16::try_from(target)
                .map_err(|_| DnsError::new("DNS pointer exceeds wire range"))?;
            if usize::from(target) >= data.len()
                || seen[..jumps].contains(&target)
                || jumps >= MAX_JUMPS
            {
                return Err(DnsError::new("invalid DNS compression pointer"));
            }
            seen[jumps] = target;
            if !jumped {
                *cursor = position
                    .checked_add(2)
                    .ok_or(DnsError::new("DNS offset overflow"))?;
                jumped = true;
            }
            position = usize::from(target);
            jumps = jumps
                .checked_add(1)
                .ok_or(DnsError::new("DNS jump overflow"))?;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::new("unsupported DNS label type"));
        }
        position = position
            .checked_add(1)
            .ok_or(DnsError::new("DNS offset overflow"))?;
        if length == 0 {
            if !jumped {
                *cursor = position;
            }
            break;
        }
        let label_length = usize::from(length);
        wire_length = wire_length
            .checked_add(
                label_length
                    .checked_add(1)
                    .ok_or(DnsError::new("DNS name too long"))?,
            )
            .ok_or(DnsError::new("DNS name too long"))?;
        if wire_length > 255 {
            return Err(DnsError::new("DNS name exceeds 255 octets"));
        }
        let end = position
            .checked_add(label_length)
            .ok_or(DnsError::new("DNS offset overflow"))?;
        let label = data
            .get(position..end)
            .ok_or(DnsError::new("truncated DNS label"))?;
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| DnsError::new("non-UTF8 DNS label"))?
                .to_owned(),
        );
        position = end;
        if !jumped {
            *cursor = position;
        }
    }
    Ok(labels.join("."))
}

/// Validates and encodes a DNS presentation name, including the root name (`""`).
///
/// # Errors
///
/// Returns an error when the name cannot be encoded as DNS labels.
pub fn encode_name(name: &str) -> Result<Vec<u8>> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Ok(vec![0]);
    }
    let mut output = Vec::with_capacity(
        trimmed
            .len()
            .checked_add(2)
            .ok_or(DnsError::new("DNS name too long"))?,
    );
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(DnsError::new("invalid DNS label length"));
        }
        output.push(
            u8::try_from(bytes.len()).map_err(|_| DnsError::new("invalid DNS label length"))?,
        );
        output.extend_from_slice(bytes);
    }
    output.push(0);
    if output.len() > 255 {
        return Err(DnsError::new("DNS name exceeds 255 octets"));
    }
    Ok(output)
}

fn decode_uncompressed_name(data: &[u8], cursor: &mut usize, end: usize) -> Result<String> {
    let mut labels = Vec::new();
    let mut wire_length = 1_usize;
    loop {
        let length = *data
            .get(*cursor)
            .filter(|_| *cursor < end)
            .ok_or(DnsError::new("truncated DNS name"))?;
        if length & 0xc0 != 0 {
            return Err(DnsError::new("compressed DNS name is not permitted here"));
        }
        *cursor = cursor
            .checked_add(1)
            .ok_or(DnsError::new("DNS offset overflow"))?;
        if length == 0 {
            return Ok(labels.join("."));
        }
        let label_length = usize::from(length);
        wire_length = wire_length
            .checked_add(
                label_length
                    .checked_add(1)
                    .ok_or(DnsError::new("DNS name too long"))?,
            )
            .ok_or(DnsError::new("DNS name too long"))?;
        if wire_length > 255 {
            return Err(DnsError::new("DNS name exceeds 255 octets"));
        }
        let label_end = cursor
            .checked_add(label_length)
            .ok_or(DnsError::new("DNS offset overflow"))?;
        let label = data
            .get(*cursor..label_end)
            .filter(|_| label_end <= end)
            .ok_or(DnsError::new("truncated DNS label"))?;
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| DnsError::new("non-UTF8 DNS label"))?
                .to_owned(),
        );
        *cursor = label_end;
    }
}

fn canonical_name(data: &[u8], cursor: &mut usize, end: usize) -> Result<Vec<u8>> {
    let name = decode_name(data, cursor)?;
    if *cursor > end {
        return Err(DnsError::new("DNS name exceeds RDATA"));
    }
    encode_name(&name)
}

fn canonical_rdata(data: &[u8], start: usize, end: usize, rr_type: u16) -> Result<Vec<u8>> {
    let mut cursor = start;
    match rr_type {
        TYPE_CNAME | TYPE_NS | TYPE_PTR => {
            let output = canonical_name(data, &mut cursor, end)?;
            if cursor != end {
                return Err(DnsError::new("trailing domain-name RDATA"));
            }
            Ok(output)
        }
        TYPE_MX => {
            let prefix_end = start
                .checked_add(2)
                .ok_or(DnsError::new("DNS offset overflow"))?;
            let mut output = data
                .get(start..prefix_end)
                .filter(|_| prefix_end <= end)
                .ok_or(DnsError::new("truncated MX RDATA"))?
                .to_vec();
            cursor = prefix_end;
            output.extend_from_slice(&canonical_name(data, &mut cursor, end)?);
            if cursor != end {
                return Err(DnsError::new("trailing MX RDATA"));
            }
            Ok(output)
        }
        TYPE_SRV => {
            let prefix_end = start
                .checked_add(6)
                .ok_or(DnsError::new("DNS offset overflow"))?;
            let mut output = data
                .get(start..prefix_end)
                .filter(|_| prefix_end <= end)
                .ok_or(DnsError::new("truncated SRV RDATA"))?
                .to_vec();
            cursor = prefix_end;
            output.extend_from_slice(&canonical_name(data, &mut cursor, end)?);
            if cursor != end {
                return Err(DnsError::new("trailing SRV RDATA"));
            }
            Ok(output)
        }
        TYPE_SOA => {
            let mut output = canonical_name(data, &mut cursor, end)?;
            output.extend_from_slice(&canonical_name(data, &mut cursor, end)?);
            let numeric_end = cursor
                .checked_add(20)
                .ok_or(DnsError::new("DNS offset overflow"))?;
            output.extend_from_slice(
                data.get(cursor..numeric_end)
                    .filter(|_| numeric_end == end)
                    .ok_or(DnsError::new("invalid SOA RDATA"))?,
            );
            Ok(output)
        }
        TYPE_SVCB | TYPE_HTTPS => {
            let priority_end = start
                .checked_add(2)
                .ok_or(DnsError::new("DNS offset overflow"))?;
            let mut output = data
                .get(start..priority_end)
                .filter(|_| priority_end <= end)
                .ok_or(DnsError::new("truncated SVCB RDATA"))?
                .to_vec();
            cursor = priority_end;
            output.extend_from_slice(&encode_name(&decode_uncompressed_name(
                data,
                &mut cursor,
                end,
            )?)?);
            output.extend_from_slice(
                data.get(cursor..end)
                    .ok_or(DnsError::new("truncated SVCB parameter"))?,
            );
            parse_svcb_rdata(&output)?;
            Ok(output)
        }
        _ => data
            .get(start..end)
            .ok_or(DnsError::new("truncated DNS RDATA"))
            .map(ToOwned::to_owned),
    }
}

/// Parses canonical SVCB/HTTPS RDATA into priority, target, and ordered parameters.
///
/// # Errors
///
/// Returns an error for a truncated, compressed, or unordered SVCB RDATA value.
pub fn parse_svcb_rdata(rdata: &[u8]) -> Result<SvcbRecord> {
    if rdata.len() < 3 {
        return Err(DnsError::new("truncated SVCB RDATA"));
    }
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let mut cursor = 2;
    let target = decode_uncompressed_name(rdata, &mut cursor, rdata.len())?;
    let mut params = Vec::new();
    let mut previous = None;
    while cursor < rdata.len() {
        let key = read_u16(rdata, &mut cursor)?;
        if previous.is_some_and(|previous| key <= previous) {
            return Err(DnsError::new("SVCB parameters are not strictly ordered"));
        }
        previous = Some(key);
        let length = usize::from(read_u16(rdata, &mut cursor)?);
        let end = cursor
            .checked_add(length)
            .ok_or(DnsError::new("SVCB offset overflow"))?;
        params.push((
            key,
            rdata
                .get(cursor..end)
                .ok_or(DnsError::new("truncated SVCB parameter"))?
                .to_vec(),
        ));
        cursor = end;
    }
    Ok(SvcbRecord {
        priority,
        target,
        params,
    })
}

/// Rebuilds SVCB/HTTPS RDATA after replacing a parameter, rejecting `AliasMode` and invalid mandatory lists.
///
/// # Errors
///
/// Returns an error for malformed SVCB RDATA, invalid mandatory semantics, or an oversized value.
pub fn replace_svcb_param(rdata: &[u8], key: u16, value: &[u8]) -> Result<Option<Vec<u8>>> {
    if value.is_empty() {
        return Err(DnsError::new("SVCB parameter value is empty"));
    }
    let mut record = parse_svcb_rdata(rdata)?;
    if record.priority == 0 {
        return Ok(None);
    }
    record.params.retain(|(existing, _)| *existing != key);
    record.params.push((key, value.to_vec()));
    record.params.sort_by_key(|(existing, _)| *existing);
    if let Some((_, mandatory)) = record.params.iter().find(|(existing, _)| *existing == 0) {
        if mandatory.len() % 2 != 0 {
            return Err(DnsError::new("invalid SVCB mandatory parameter"));
        }
        for mandatory_key in mandatory
            .chunks_exact(2)
            .map(|item| u16::from_be_bytes([item[0], item[1]]))
        {
            if mandatory_key == 0
                || !record
                    .params
                    .iter()
                    .any(|(existing, _)| *existing == mandatory_key)
            {
                return Err(DnsError::new("SVCB mandatory parameter is missing"));
            }
        }
    }
    let mut output = Vec::new();
    output.extend_from_slice(&record.priority.to_be_bytes());
    output.extend_from_slice(&encode_name(&record.target)?);
    for (parameter_key, parameter_value) in record.params {
        write_u16(&mut output, parameter_key);
        write_u16(
            &mut output,
            u16::try_from(parameter_value.len())
                .map_err(|_| DnsError::new("SVCB parameter exceeds 65535 octets"))?,
        );
        output.extend_from_slice(&parameter_value);
    }
    Ok(Some(output))
}

/// Expands domain-bearing RDATA into its canonical, uncompressed form.
///
/// # Errors
///
/// Returns an error when a structured RDATA value is malformed or contains a
/// compression pointer that cannot be resolved within `rdata`.
pub fn expand_rdata_names(rdata: &[u8], rr_type: u16) -> Result<Vec<u8>> {
    canonical_rdata(rdata, 0, rdata.len(), rr_type)
}

/// Re-encodes domain-bearing RDATA in its canonical, uncompressed form.
///
/// # Errors
///
/// Returns an error when a structured RDATA value is malformed.
pub fn reencode_rdata(rr_type: u16, rdata: &[u8]) -> Result<Vec<u8>> {
    expand_rdata_names(rdata, rr_type)
}

fn parse_question(data: &[u8], cursor: &mut usize) -> Result<Question> {
    Ok(Question {
        name: decode_name(data, cursor)?,
        qtype: read_u16(data, cursor)?,
        qclass: read_u16(data, cursor)?,
    })
}

fn parse_rr(data: &[u8], cursor: &mut usize) -> Result<ResourceRecord> {
    let name = decode_name(data, cursor)?;
    let rr_type = read_u16(data, cursor)?;
    let class = read_u16(data, cursor)?;
    let ttl = read_u32(data, cursor)?;
    let length = usize::from(read_u16(data, cursor)?);
    let end = cursor
        .checked_add(length)
        .ok_or(DnsError::new("DNS offset overflow"))?;
    let rdata_start = *cursor;
    data.get(rdata_start..end)
        .ok_or(DnsError::new("truncated DNS RDATA"))?;
    let rdata = canonical_rdata(data, rdata_start, end, rr_type)?;
    *cursor = end;
    Ok(ResourceRecord {
        name,
        rr_type,
        class,
        ttl,
        rdata,
    })
}

fn parse_records(data: &[u8], cursor: &mut usize, count: u16) -> Result<Vec<ResourceRecord>> {
    (0..usize::from(count))
        .map(|_| parse_rr(data, cursor))
        .collect()
}

/// Parses all DNS message sections, resolving compressed owner names safely.
///
/// # Errors
///
/// Returns an error when the wire message is truncated or malformed.
pub fn parse_message(data: &[u8]) -> Result<Message> {
    if data.len() < 12 {
        return Err(DnsError::new("truncated DNS header"));
    }
    let mut cursor = 0;
    let header = Header {
        id: read_u16(data, &mut cursor)?,
        flags: read_u16(data, &mut cursor)?,
        qd_count: read_u16(data, &mut cursor)?,
        an_count: read_u16(data, &mut cursor)?,
        ns_count: read_u16(data, &mut cursor)?,
        ar_count: read_u16(data, &mut cursor)?,
    };
    let response = header.flags & 0x8000 != 0;
    let unreasonable_counts = if response {
        header.qd_count > 1
            || header.an_count > MAX_RESPONSE_SECTION_RECORDS
            || header.ns_count > MAX_RESPONSE_SECTION_RECORDS
            || header.ar_count > MAX_RESPONSE_SECTION_RECORDS
    } else {
        header.qd_count != 1
            || header.an_count != 0
            || header.ns_count != 0
            || header.ar_count > MAX_QUERY_ADDITIONAL_RECORDS
    };
    if unreasonable_counts {
        return Err(DnsError::new("unreasonable DNS section counts"));
    }
    let questions = (0..usize::from(header.qd_count))
        .map(|_| parse_question(data, &mut cursor))
        .collect::<Result<Vec<_>>>()?;
    let answers = parse_records(data, &mut cursor, header.an_count)?;
    let authorities = parse_records(data, &mut cursor, header.ns_count)?;
    let additionals = parse_records(data, &mut cursor, header.ar_count)?;
    if cursor != data.len() {
        return Err(DnsError::new("trailing DNS bytes"));
    }
    Ok(Message {
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

/// Parses the answer section of a DNS wire message.
///
/// # Errors
///
/// Returns an error when the wire message is truncated or malformed.
pub fn parse_answers(data: &[u8]) -> Result<Vec<ResourceRecord>> {
    Ok(parse_message(data)?.answers)
}

/// Returns raw IPv4 or IPv6 bytes when `record` is a well-formed A or AAAA RR.
#[must_use]
pub fn extract_ip_bytes(record: &ResourceRecord) -> Option<&[u8]> {
    match record.rr_type {
        TYPE_A if record.rdata.len() == 4 => Some(&record.rdata),
        TYPE_AAAA if record.rdata.len() == 16 => Some(&record.rdata),
        _ => None,
    }
}

/// Finds the first RR of `rr_type` across all response sections.
#[must_use]
pub fn find_rr_by_type(message: &Message, rr_type: u16) -> Option<&ResourceRecord> {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .find(|record| record.rr_type == rr_type)
}

fn push_question(output: &mut Vec<u8>, question: &Question) -> Result<()> {
    output.extend_from_slice(&encode_name(&question.name)?);
    write_u16(output, question.qtype);
    write_u16(output, question.qclass);
    Ok(())
}

fn push_rr(output: &mut Vec<u8>, record: &ResourceRecord) -> Result<()> {
    output.extend_from_slice(&encode_name(&record.name)?);
    write_u16(output, record.rr_type);
    write_u16(output, record.class);
    write_u32(output, record.ttl);
    let rdata = expand_rdata_names(&record.rdata, record.rr_type)?;
    write_u16(
        output,
        u16::try_from(rdata.len()).map_err(|_| DnsError::new("RDATA exceeds 65535 octets"))?,
    );
    output.extend_from_slice(&rdata);
    Ok(())
}

pub(crate) fn serialize_message(message: &Message) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for value in [
        message.header.id,
        message.header.flags,
        u16::try_from(message.questions.len()).map_err(|_| DnsError::new("too many questions"))?,
        u16::try_from(message.answers.len()).map_err(|_| DnsError::new("too many answers"))?,
        u16::try_from(message.authorities.len())
            .map_err(|_| DnsError::new("too many authorities"))?,
        u16::try_from(message.additionals.len())
            .map_err(|_| DnsError::new("too many additionals"))?,
    ] {
        write_u16(&mut output, value);
    }
    for question in &message.questions {
        push_question(&mut output, question)?;
    }
    for section in [&message.answers, &message.authorities, &message.additionals] {
        for record in section {
            push_rr(&mut output, record)?;
        }
    }
    if output.len() > MAX_WIRE_SIZE {
        return Err(DnsError::new("DNS message exceeds 65535 octets"));
    }
    Ok(output)
}

/// Builds a standard DNS response.  Answer names use the question-at-offset-12 pointer.
///
/// # Errors
///
/// Returns an error when the supplied DNS data exceeds wire-format limits.
pub fn build_response(
    id: u16,
    qname: &str,
    qtype: u16,
    rdata_list: &[Vec<u8>],
    ttl: u32,
    flags: u16,
) -> Result<Vec<u8>> {
    let question = Question {
        name: qname.to_owned(),
        qtype,
        qclass: CLASS_IN,
    };
    let mut output = Vec::new();
    for value in [
        id,
        flags,
        1,
        u16::try_from(rdata_list.len()).map_err(|_| DnsError::new("too many answers"))?,
        0,
        0,
    ] {
        write_u16(&mut output, value);
    }
    push_question(&mut output, &question)?;
    for rdata in rdata_list {
        let rdata = expand_rdata_names(rdata, qtype)?;
        write_u16(&mut output, 0xc00c);
        write_u16(&mut output, qtype);
        write_u16(&mut output, CLASS_IN);
        write_u32(&mut output, ttl);
        write_u16(
            &mut output,
            u16::try_from(rdata.len()).map_err(|_| DnsError::new("RDATA exceeds 65535 octets"))?,
        );
        output.extend_from_slice(&rdata);
    }
    if output.len() > MAX_WIRE_SIZE {
        return Err(DnsError::new("DNS message exceeds 65535 octets"));
    }
    Ok(output)
}

/// Builds a SERVFAIL response with an OPT Extended DNS Error (RFC 8914) option.
///
/// # Errors
///
/// Returns an error when the supplied DNS data exceeds wire-format limits.
pub fn servfail(id: u16, question: &Question, ede_code: u16, ede_text: &str) -> Result<Vec<u8>> {
    let mut ede = Vec::new();
    write_u16(&mut ede, ede_code);
    ede.extend_from_slice(ede_text.as_bytes());
    let mut option = Vec::new();
    write_u16(&mut option, 15);
    write_u16(
        &mut option,
        u16::try_from(ede.len()).map_err(|_| DnsError::new("EDE text too long"))?,
    );
    option.extend_from_slice(&ede);
    let message = Message {
        header: Header {
            id,
            flags: 0x8182,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 1,
        },
        questions: vec![question.clone()],
        answers: vec![],
        authorities: vec![],
        additionals: vec![ResourceRecord {
            name: String::new(),
            rr_type: TYPE_OPT,
            class: 4096,
            ttl: 0,
            rdata: option,
        }],
    };
    serialize_message(&message)
}

/// Parses SVCB/HTTPS parameters after the two-octet priority and target name.
///
/// # Errors
///
/// Returns an error when the SVCB RDATA is malformed.
pub fn parse_svcb_params(rdata: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    Ok(parse_svcb_rdata(rdata)?.params)
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

    fn wire_header(
        flags: u16,
        qd_count: u16,
        an_count: u16,
        ns_count: u16,
        ar_count: u16,
    ) -> Vec<u8> {
        let mut wire = Vec::with_capacity(12);
        for field in [0, flags, qd_count, an_count, ns_count, ar_count] {
            wire.extend_from_slice(&field.to_be_bytes());
        }
        wire
    }

    #[test]
    fn name_round_trip() {
        let encoded = must(encode_name("www.example.com."));
        let mut cursor = 0;
        assert_eq!(must(decode_name(&encoded, &mut cursor)), "www.example.com");
        assert_eq!(cursor, encoded.len());
    }

    #[test]
    fn compressed_name_and_loop_detection() {
        let data = [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0xc0, 0,
        ];
        let mut cursor = 13;
        assert_eq!(must(decode_name(&data, &mut cursor)), "www.example");
        let looped = [0xc0, 0x00];
        let mut loop_cursor = 0;
        assert!(decode_name(&looped, &mut loop_cursor).is_err());
    }

    #[test]
    fn response_and_servfail_structure() {
        let response = build_response(
            0x1234,
            "example.com",
            TYPE_A,
            &[vec![1, 2, 3, 4]],
            60,
            0x8180,
        );
        let response = must(response);
        let parsed = must(parse_message(&response));
        assert_eq!(parsed.header.flags, 0x8180);
        assert_eq!(parsed.answers[0].rdata, [1, 2, 3, 4]);
        let failure = must(servfail(
            0x1234,
            &parsed.questions[0],
            22,
            "No Reachable Authority",
        ));
        let failure = must(parse_message(&failure));
        assert_eq!(failure.header.flags, 0x8182);
        assert_eq!(failure.additionals[0].rr_type, TYPE_OPT);
    }

    #[test]
    fn canonicalizes_compressed_domain_rdata_before_reordering() {
        let mut wire = vec![0, 9, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        let question_name = match encode_name("example.com") {
            Ok(value) => value,
            Err(error) => panic!("test name must encode: {error}"),
        };
        wire.extend_from_slice(&question_name);
        wire.extend_from_slice(&TYPE_A.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (rr_type, rdata) in [
            (TYPE_CNAME, vec![3, b'w', b'w', b'w', 0xc0, 12]),
            (TYPE_MX, vec![0, 10, 0xc0, 12]),
            (
                TYPE_SOA,
                [vec![0xc0, 12], vec![0xc0, 12], vec![0; 20]].concat(),
            ),
        ] {
            wire.extend_from_slice(&[0xc0, 12]);
            wire.extend_from_slice(&rr_type.to_be_bytes());
            wire.extend_from_slice(&CLASS_IN.to_be_bytes());
            wire.extend_from_slice(&60_u32.to_be_bytes());
            let rdata_length = match u16::try_from(rdata.len()) {
                Ok(value) => value,
                Err(_) => panic!("test RDATA fits u16"),
            };
            wire.extend_from_slice(&rdata_length.to_be_bytes());
            wire.extend_from_slice(&rdata);
        }
        let mut parsed = match parse_message(&wire) {
            Ok(message) => message,
            Err(error) => panic!("compressed RDATA must parse: {error}"),
        };
        for record in &mut parsed.answers {
            let expanded = match expand_rdata_names(&record.rdata, record.rr_type) {
                Ok(value) => value,
                Err(error) => panic!("parsed RDATA must expand: {error}"),
            };
            assert_eq!(expanded, record.rdata);
            record.rdata = match reencode_rdata(record.rr_type, &expanded) {
                Ok(value) => value,
                Err(error) => panic!("expanded RDATA must reencode: {error}"),
            };
        }
        parsed.answers.swap(0, 2);
        let rebuilt = match serialize_message(&parsed) {
            Ok(message) => message,
            Err(error) => panic!("canonical RDATA must serialize: {error}"),
        };
        let reparsed = match parse_message(&rebuilt) {
            Ok(message) => message,
            Err(error) => panic!("rebuilt response must parse: {error}"),
        };
        assert_eq!(reparsed.answers, parsed.answers);
    }

    #[test]
    fn rejects_unreasonable_counts_and_overlong_names() {
        for (qd_count, an_count, ns_count, ar_count) in [
            (0, 0, 0, 0),
            (1, 1, 0, 0),
            (1, 0, 1, 0),
            (1, 0, 0, MAX_QUERY_ADDITIONAL_RECORDS + 1),
        ] {
            assert!(
                parse_message(&wire_header(0x0100, qd_count, an_count, ns_count, ar_count))
                    .is_err()
            );
        }
        for (an_count, ns_count, ar_count) in [
            (MAX_RESPONSE_SECTION_RECORDS + 1, 0, 0),
            (0, MAX_RESPONSE_SECTION_RECORDS + 1, 0),
            (0, 0, MAX_RESPONSE_SECTION_RECORDS + 1),
        ] {
            assert!(parse_message(&wire_header(0x8000, 1, an_count, ns_count, ar_count)).is_err());
        }
        let mut overlong = Vec::new();
        for _ in 0..4 {
            overlong.push(63);
            overlong.extend_from_slice(&[b'a'; 63]);
        }
        overlong.push(0);
        let mut cursor = 0;
        assert!(decode_name(&overlong, &mut cursor).is_err());
    }

    #[test]
    fn edits_service_mode_and_preserves_mandatory_consistency() {
        let rdata = [0, 1, 0, 0, 0, 0, 2, 0, 5, 0, 5, 0, 3, b'o', b'l', b'd'];
        let updated = match replace_svcb_param(&rdata, 5, b"new") {
            Ok(Some(value)) => value,
            Ok(None) => panic!("service mode must be editable"),
            Err(error) => panic!("valid service record must edit: {error}"),
        };
        let parsed = match parse_svcb_rdata(&updated) {
            Ok(value) => value,
            Err(error) => panic!("updated SVCB must parse: {error}"),
        };
        assert_eq!(parsed.params, vec![(0, vec![0, 5]), (5, b"new".to_vec())]);
        assert_eq!(replace_svcb_param(&[0, 0, 0], 5, b"new"), Ok(None));
    }
}
