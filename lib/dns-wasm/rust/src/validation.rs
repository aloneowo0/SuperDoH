use crate::{message, rdata};
use serde_json::{Value, json};

pub fn validate(bytes: &[u8], expected: Option<&[u8]>) -> Result<Value, String> {
    let p = message::parse(bytes)?;
    if let Some(query) = expected {
        let q = message::parse(query)?;
        match_packets(&p, &q)?;
    }
    let ext = p
        .additional
        .iter()
        .find(|r| r.rtype == 41)
        .map_or(0, |r| (r.ttl >> 24) as u16);
    Ok(
        json!({"valid":true,"id":p.id,"is_response":p.flags&0x8000!=0,"rcode":((p.flags&15)|(ext<<4)),"question_count":p.questions.len(),"answer_count":p.answers.len()}),
    )
}

pub fn extract_ips(bytes: &[u8], rtype: Option<u16>) -> Result<Value, String> {
    let p = message::parse(bytes)?;
    let mut result = Vec::new();
    for rr in &p.answers {
        if (rr.rtype == 1 || rr.rtype == 28) && rtype.is_none_or(|t| rr.rtype == t) {
            let bytes = rdata::encode(rr.rtype, &rr.rdata)?;
            result.push(json!({"name":rr.name,"rtype":rr.rtype,"address":rr.data,"bytes":bytes}));
        }
    }
    Ok(json!(result))
}

pub fn dns_json(bytes: &[u8]) -> Result<Value, String> {
    let p = message::parse(bytes)?;
    let ext = p
        .additional
        .iter()
        .find(|r| r.rtype == 41)
        .map_or(0, |r| (r.ttl >> 24) as u16);
    let records = |rrs: &[message::Record]| {
        rrs.iter()
            .filter(|r| r.rtype != 41)
            .map(
                |r| json!({"name":r.name,"type":r.rtype,"class":r.class,"TTL":r.ttl,"data":r.data}),
            )
            .collect::<Vec<_>>()
    };
    Ok(
        json!({"Status":(p.flags&15)|(ext<<4),"TC":p.flags&0x0200!=0,"RD":p.flags&0x0100!=0,"RA":p.flags&0x0080!=0,"AD":p.flags&0x0020!=0,"CD":p.flags&0x0010!=0,"Question":p.questions.iter().map(|q|json!({"name":q.name,"type":q.rtype,"class":q.class})).collect::<Vec<_>>(),"Answer":records(&p.answers),"Authority":records(&p.authority),"Additional":records(&p.additional)}),
    )
}

fn match_packets(p: &message::Packet, q: &message::Packet) -> Result<(), String> {
    if p.flags & 0x8000 == 0 || q.flags & 0x8000 != 0 {
        return Err("response/query QR mismatch".into());
    }
    if p.id != q.id
        || p.flags & 0x7800 != q.flags & 0x7800
        || p.questions.len() != q.questions.len()
    {
        return Err("query identity mismatch".into());
    }
    for (a, b) in p.questions.iter().zip(&q.questions) {
        if a.rtype != b.rtype
            || a.class != b.class
            || message::name(&a.name)? != message::name(&b.name)?
        {
            return Err("question mismatch".into());
        }
    }
    Ok(())
}

pub fn encode_response(
    packet: message::Packet,
    query: &[u8],
    maximum: usize,
    options: message::EncodeOptions,
) -> Result<Option<Vec<u8>>, String> {
    let (wire, parsed) = message::encode_parsed(packet, options)?;
    if wire.len() > maximum {
        return Ok(None);
    }
    match_packets(&parsed, &message::parse(query)?)?;
    Ok(Some(wire))
}
