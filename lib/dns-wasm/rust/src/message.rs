use crate::rdata;
use domain::base::iana::{Class, Rtype};
use domain::base::name::FlattenInto;
use domain::base::{Message, MessageBuilder, Name, ParsedName, Ttl, UnknownRecordData};
use domain::rdata::AllRecordData;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Question {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Value,
    #[serde(default)]
    pub data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Packet {
    pub id: u16,
    pub flags: u16,
    #[serde(default)]
    pub questions: Vec<Question>,
    #[serde(default)]
    pub answers: Vec<Record>,
    #[serde(default)]
    pub authority: Vec<Record>,
    #[serde(default)]
    pub additional: Vec<Record>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodeOptions {
    #[serde(default)]
    pub strip_message_authentication: bool,
    #[serde(default)]
    pub invalidate_rrsets: Vec<Question>,
}

pub fn name(value: &str) -> Result<Name<Vec<u8>>, String> {
    value.parse().map_err(|e| format!("invalid DNS name: {e}"))
}

pub fn display_name(value: impl std::fmt::Display) -> String {
    let text = value.to_string();
    if text.is_empty() { ".".into() } else { text }
}

pub fn parse(bytes: &[u8]) -> Result<Packet, String> {
    if bytes.len() > 65535 {
        return Err("DNS message exceeds 65535 bytes".into());
    }
    let msg = Message::from_slice(bytes).map_err(|e| e.to_string())?;
    let questions = msg
        .question()
        .map(|q| {
            let q = q.map_err(|e| e.to_string())?;
            Ok(Question {
                name: display_name(q.qname()),
                rtype: q.qtype().to_int(),
                class: q.qclass().to_int(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut groups = Vec::new();
    let mut end = 12;
    for group in [msg.answer(), msg.authority(), msg.additional()] {
        let mut group = group.map_err(|e| e.to_string())?;
        let mut records = Vec::new();
        for raw in group.by_ref() {
            let rr = raw
                .map_err(|e| e.to_string())?
                .into_any_record::<AllRecordData<_, ParsedName<_>>>()
                .map_err(|e| e.to_string())?;
            let owned: rdata::OwnedData = rr
                .data()
                .clone()
                .try_flatten_into()
                .map_err(|e| format!("{e:?}"))?;
            records.push(Record {
                name: display_name(rr.owner()),
                rtype: rr.rtype().to_int(),
                class: rr.class().to_int(),
                ttl: rr.ttl().as_secs(),
                data: rr.data().to_string(),
                rdata: rdata::decode(owned)?,
            });
        }
        end = group.pos();
        groups.push(records);
    }
    if end != bytes.len() {
        return Err("trailing bytes after DNS message".into());
    }
    let mut groups = groups.into_iter();
    let packet = Packet {
        id: msg.header().id(),
        flags: u16::from_be_bytes([bytes[2], bytes[3]]),
        questions,
        answers: groups.next().unwrap_or_default(),
        authority: groups.next().unwrap_or_default(),
        additional: groups.next().unwrap_or_default(),
    };
    validate_opt(&packet)?;
    Ok(packet)
}

fn validate_opt(packet: &Packet) -> Result<(), String> {
    if packet
        .answers
        .iter()
        .chain(&packet.authority)
        .any(|r| r.rtype == 41)
    {
        return Err("OPT only allowed in additional section".into());
    }
    let opts: Vec<_> = packet.additional.iter().filter(|r| r.rtype == 41).collect();
    if opts.len() > 1 {
        return Err("multiple OPT records".into());
    }
    for opt in opts {
        if name(&opt.name)? != Name::root_vec() {
            return Err("OPT owner must be root".into());
        }
    }
    Ok(())
}

fn message_auth(rr: &Record) -> Result<bool, String> {
    if rr.rtype == 250 {
        return Ok(true);
    }
    if rr.rtype == 24 {
        let bytes = rdata::encode(rr.rtype, &rr.rdata)?;
        return Ok(bytes.starts_with(&[0, 0]));
    }
    Ok(false)
}

fn prepare(mut p: Packet, options: &EncodeOptions) -> Result<Packet, String> {
    validate_opt(&p)?;
    for section in [&mut p.answers, &mut p.authority, &mut p.additional] {
        let mut keep = Vec::new();
        for rr in section.drain(..) {
            if message_auth(&rr)? {
                if !options.strip_message_authentication {
                    return Err("cannot re-encode TSIG/SIG(0) without explicit removal".into());
                }
                continue;
            }
            let mut remove = false;
            if rr.rtype == 46 && !options.invalidate_rrsets.is_empty() {
                let bytes = rdata::encode(rr.rtype, &rr.rdata)?;
                let covered = u16::from_be_bytes([bytes[0], bytes[1]]);
                for key in &options.invalidate_rrsets {
                    if covered == key.rtype
                        && rr.class == key.class
                        && name(&rr.name)? == name(&key.name)?
                    {
                        remove = true;
                    }
                }
            }
            if !remove {
                keep.push(rr);
            }
        }
        *section = keep;
    }
    if !options.invalidate_rrsets.is_empty() {
        p.flags &= !0x0020;
    }
    Ok(p)
}

pub fn encode(packet: Packet, options: EncodeOptions) -> Result<Vec<u8>, String> {
    encode_parsed(packet, options).map(|(wire, _)| wire)
}

pub fn encode_parsed(packet: Packet, options: EncodeOptions) -> Result<(Vec<u8>, Packet), String> {
    let p = prepare(packet, &options)?;
    let mut b = MessageBuilder::new_vec();
    b.header_mut().set_id(p.id);
    b.set_push_limit(65535);
    let mut b = b.question();
    for q in &p.questions {
        let n = name(&q.name)?;
        b.push((&n, Rtype::from_int(q.rtype), Class::from_int(q.class)))
            .map_err(|e| e.to_string())?;
    }
    macro_rules! push_records {
        ($builder:ident, $records:expr) => {
            for rr in $records {
                let owner = name(&rr.name)?;
                let bytes = rdata::encode(rr.rtype, &rr.rdata)?;
                let data = UnknownRecordData::from_octets(Rtype::from_int(rr.rtype), bytes)
                    .map_err(|e| e.to_string())?;
                $builder
                    .push((
                        &owner,
                        Class::from_int(rr.class),
                        Ttl::from_secs(rr.ttl),
                        &data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
        };
    }
    let mut b = b.answer();
    push_records!(b, &p.answers);
    let mut b = b.authority();
    push_records!(b, &p.authority);
    let mut b = b.additional();
    push_records!(b, &p.additional);
    let mut out = b.finish();
    out[2..4].copy_from_slice(&p.flags.to_be_bytes());
    if out.len() > 65535 {
        return Err("DNS message exceeds 65535 bytes".into());
    }
    let parsed = parse(&out)?;
    Ok((out, parsed))
}

pub fn query(name_value: &str, rtype: u16, id: u16) -> Result<Vec<u8>, String> {
    encode(
        Packet {
            id,
            flags: 0x0100,
            questions: vec![Question {
                name: name_value.into(),
                rtype,
                class: 1,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        },
        EncodeOptions::default(),
    )
}
