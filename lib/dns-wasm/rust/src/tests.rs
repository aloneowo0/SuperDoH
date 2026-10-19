use crate::{edns, message, rdata, svcb, validation};
use serde_json::json;

fn packet() -> message::Packet {
    message::parse(&message::query("example.com", 1, 0x4242).unwrap()).unwrap()
}
fn record(name: &str, rtype: u16, rdata: serde_json::Value) -> message::Record {
    message::Record {
        name: name.into(),
        rtype,
        class: 1,
        ttl: 60,
        rdata,
        data: String::new(),
    }
}

#[test]
fn query_round_trip() {
    for rtype in [1, 28, 64, 65, 65280] {
        let wire = message::query("x.com.", rtype, 0x4242).unwrap();
        let p = message::parse(&wire).unwrap();
        assert_eq!(p.id, 0x4242);
        assert_eq!(p.questions[0].rtype, rtype);
        assert_eq!(p.questions[0].name, "x.com");
        assert_eq!(
            message::encode(p, message::EncodeOptions::default()).unwrap(),
            wire
        );
    }
}
#[test]
fn rejects_short_oversized_trailing_and_cycle() {
    for bytes in [
        vec![],
        vec![0; 11],
        vec![0; 65536],
        vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1],
    ] {
        assert!(message::parse(&bytes).is_err());
    }
    let mut q = message::query("x.com", 1, 1).unwrap();
    q.push(0);
    assert!(message::parse(&q).is_err());
    q.pop();
    q.pop();
    assert!(message::parse(&q).is_err());
}
#[test]
fn native_a_can_be_edited() {
    let mut p = packet();
    p.flags = 0x85b0;
    p.answers
        .push(record("example.com", 1, json!({"A":{"addr":"1.2.3.4"}})));
    let wire = message::encode(p, message::EncodeOptions::default()).unwrap();
    let mut p = message::parse(&wire).unwrap();
    assert_eq!(p.flags, 0x85b0);
    assert_eq!(p.answers[0].data, "1.2.3.4");
    p.answers[0].rdata["A"]["addr"] = json!("8.8.8.8");
    p.answers[0].ttl = 120;
    let p =
        message::parse(&message::encode(p, message::EncodeOptions::default()).unwrap()).unwrap();
    assert_eq!(p.answers[0].data, "8.8.8.8");
    assert_eq!(p.answers[0].ttl, 120);
}
#[test]
fn ecs_masks_network_and_rejects_overflow() {
    let b = edns::encode_ecs(edns::Ecs {
        address: "192.168.1.255".into(),
        source_prefix: 25,
        scope_prefix: 0,
    })
    .unwrap();
    assert_eq!(b, vec![0, 1, 25, 0, 192, 168, 1, 128]);
    assert_eq!(edns::decode_ecs(&b).unwrap().address, "192.168.1.128");
    assert!(
        edns::encode_ecs(edns::Ecs {
            address: "1.2.3.4".into(),
            source_prefix: 33,
            scope_prefix: 0
        })
        .is_err()
    );
}
#[test]
fn service_params_use_native_builder_and_sort() {
    let value = json!({"Https":{"priority":1,"target":".","params":[{"key":3,"data":[1,187]},{"key":1,"data":[2,104,50]}]}});
    let bytes = rdata::encode(65, &value).unwrap();
    let decoded = rdata::decode_bytes(65, &bytes).unwrap();
    assert_eq!(decoded["Https"]["params"][0]["key"], 1);
    assert_eq!(svcb::decode_param(3, &[1, 187]).unwrap(), 443);
}
#[test]
fn generic_responses_do_not_force_in_class_or_single_question() {
    let mut p = packet();
    p.questions.push(message::Question {
        name: "version.bind".into(),
        rtype: 16,
        class: 3,
    });
    let query = message::encode(p.clone(), message::EncodeOptions::default()).unwrap();
    p.flags = 0x8100;
    let wire = message::encode(p, message::EncodeOptions::default()).unwrap();
    assert!(validation::validate(&wire, Some(&query)).is_ok());
}

#[test]
fn native_record_matrix_round_trips() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("../../test/fixtures/records.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let rtype = row["rtype"].as_u64().unwrap() as u16;
        let bytes: Vec<u8> = serde_json::from_value(row["bytes"].clone()).unwrap();
        let decoded =
            rdata::decode_bytes(rtype, &bytes).unwrap_or_else(|e| panic!("{}: {e}", row["label"]));
        assert_eq!(
            rdata::encode(rtype, &decoded)
                .unwrap_or_else(|e| panic!("{}: {e}; {}", row["label"], decoded)),
            bytes,
            "{}",
            row["label"]
        );
        let mut p = packet();
        p.answers.push(record("example.com", rtype, decoded));
        p.flags |= 0x8000;
        let p = message::parse(&message::encode(p, message::EncodeOptions::default()).unwrap())
            .unwrap();
        assert_eq!(p.answers[0].rtype, rtype);
    }
}

#[test]
fn records_can_move_across_sections_and_change_owner() {
    let mut p = packet();
    p.flags = 0xffff;
    p.questions.push(message::Question {
        name: "_service.example".into(),
        rtype: 33,
        class: 3,
    });
    p.answers.push(record(
        "a.example",
        5,
        rdata::decode_bytes(
            5,
            &[1, b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0],
        )
        .unwrap(),
    ));
    p.authority.push(record(
        "example",
        2,
        rdata::decode_bytes(
            2,
            &[
                2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
            ],
        )
        .unwrap(),
    ));
    let mut raw = record("binary.example", 65280, json!({"Raw":[192,12,255]}));
    raw.class = 3;
    p.additional.push(raw);
    let mut decoded =
        message::parse(&message::encode(p, message::EncodeOptions::default()).unwrap()).unwrap();
    assert_eq!(decoded.flags, 0xffff);
    assert_eq!(decoded.questions.len(), 2);
    decoded.answers[0].name = "longer-owner.example".into();
    decoded.additional.push(decoded.authority.remove(0));
    let decoded =
        message::parse(&message::encode(decoded, message::EncodeOptions::default()).unwrap())
            .unwrap();
    assert_eq!(decoded.answers[0].name, "longer-owner.example");
    assert_eq!(decoded.additional.len(), 2);
}

#[test]
fn opt_preserves_unknown_options_and_metadata() {
    let mut p = packet();
    p.additional.push(message::Record {
        name: ".".into(),
        rtype: 41,
        class: 1232,
        ttl: 0xab078001,
        rdata: json!({"Opt":{"options":[{"code":65001,"data":[0,255]},{"code":12,"data":[0,0]}]}}),
        data: String::new(),
    });
    let p =
        message::parse(&message::encode(p, message::EncodeOptions::default()).unwrap()).unwrap();
    assert_eq!(p.additional[0].ttl, 0xab078001);
    assert_eq!(p.additional[0].class, 1232);
    assert_eq!(
        p.additional[0].rdata["Opt"]["options"][0]["data"],
        json!([0, 255])
    );
}

#[test]
fn rejects_duplicate_opt_bad_owner_and_bad_rdata_variant() {
    let mut p = packet();
    let mut opt = record(".", 41, json!({"Opt":{"options":[]}}));
    opt.class = 1232;
    p.additional.extend([opt.clone(), opt.clone()]);
    assert!(message::encode(p.clone(), message::EncodeOptions::default()).is_err());
    p.additional.pop();
    p.additional[0].name = "not.root".into();
    assert!(message::encode(p, message::EncodeOptions::default()).is_err());
    assert!(rdata::encode(28, &json!({"A":{"addr":"1.2.3.4"}})).is_err());
    assert!(rdata::decode_bytes(5, &[0xc0, 0]).is_err());
}

#[test]
fn ecs_ipv6_boundaries_and_malformed_options() {
    for prefix in [0, 1, 7, 56, 127, 128] {
        let b = edns::encode_ecs(edns::Ecs {
            address: "2001:db8::abcd".into(),
            source_prefix: prefix,
            scope_prefix: 0,
        })
        .unwrap();
        assert_eq!(b.len(), 4 + usize::from(prefix).div_ceil(8));
        assert_eq!(edns::encode_ecs(edns::decode_ecs(&b).unwrap()).unwrap(), b);
    }
    for bytes in [
        vec![0, 1, 33, 0, 1, 2, 3, 4, 5],
        vec![0, 1, 0, 33],
        vec![0, 2, 129, 0],
        vec![0, 1, 25, 0, 1, 2, 3, 255],
    ] {
        assert!(edns::decode_ecs(&bytes).is_err());
    }
}

#[test]
fn ede_unicode_round_trip() {
    let bytes = edns::encode_ede(edns::Ede {
        code: 22,
        text: "测试 DNS".into(),
    })
    .unwrap();
    assert_eq!(edns::decode_ede(&bytes).unwrap().text, "测试 DNS");
    assert!(edns::decode_ede(&[0]).is_err());
}

#[test]
fn svcb_rejects_duplicates_mandatory_and_bad_values() {
    for value in [
        json!({"Https":{"priority":1,"target":".","params":[{"key":3,"data":[1]}]}}),
        json!({"Https":{"priority":1,"target":".","params":[{"key":0,"data":[0,3]}]}}),
        json!({"Https":{"priority":1,"target":".","params":[{"key":1,"data":[1,104]},{"key":1,"data":[1,104]}]}}),
    ] {
        assert!(rdata::encode(65, &value).is_err());
    }
    let alias = json!({"Https":{"priority":0,"target":"alias.example","params":[{"key":3,"data":[1,187]}]}});
    assert_eq!(
        rdata::decode_bytes(65, &rdata::encode(65, &alias).unwrap()).unwrap(),
        alias
    );
}

#[test]
fn malformed_inputs_never_panic_and_parser_recovers() {
    let seeds: Vec<Vec<u8>> =
        serde_json::from_str::<serde_json::Value>(include_str!("../../test/fixtures/records.json"))
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let mut p = packet();
                let t = row["rtype"].as_u64().unwrap() as u16;
                let bytes: Vec<u8> = serde_json::from_value(row["bytes"].clone()).unwrap();
                p.answers.push(record(
                    "example.com",
                    t,
                    rdata::decode_bytes(t, &bytes).unwrap(),
                ));
                message::encode(p, message::EncodeOptions::default()).unwrap()
            })
            .collect();
    let mut state = 0x12345678u32;
    for n in 0..4000 {
        let mut bytes = seeds[n % seeds.len()].clone();
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        let pos = (state as usize) % bytes.len();
        bytes[pos] = (state >> 16) as u8;
        let _ = message::parse(&bytes);
    }
    assert!(message::query("still.works", 1, 1).is_ok());
}

#[test]
fn refuses_message_authentication_without_explicit_removal() {
    let mut p = packet();
    p.additional
        .push(record("example.com", 24, json!({"Raw":[0,0,1,2]})));
    assert!(message::encode(p.clone(), message::EncodeOptions::default()).is_err());
    let options = message::EncodeOptions {
        strip_message_authentication: true,
        ..Default::default()
    };
    let parsed = message::parse(&message::encode(p, options).unwrap()).unwrap();
    assert!(parsed.additional.is_empty());
}

#[test]
fn malformed_native_values_and_oversize_records_fail() {
    assert!(rdata::encode(1, &json!({"A":{"addr":"not.an.ip"}})).is_err());
    assert!(rdata::encode(5, &json!({"Cname":{"cname":"x".repeat(64)}})).is_err());
    assert!(rdata::encode(65280, &json!({"Raw":vec![0;65536]})).is_err());
    let mut p = packet();
    let rr = record("example.com", 65280, json!({"Raw":vec![0;1000]}));
    p.answers = vec![rr; 70];
    assert!(message::encode(p, message::EncodeOptions::default()).is_err());
}

#[test]
fn native_json_cannot_bypass_gateway_invariant() {
    let data = serde_json::json!({"Ipseckey":{"precedence":10,"gateway_type":1,"gateway":"None","algorithm":2,"key":[1,2,3,4]}});
    assert!(rdata::encode(45, &data).is_err());
}
