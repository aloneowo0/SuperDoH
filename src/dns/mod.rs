//! DNS protocol wire handling without runtime-specific dependencies.

pub mod classify;
pub mod edns;
pub mod svcb;
pub mod wire;

pub use classify::{Cidr, Classification, NegativeKind, classify_response};
pub use edns::{
    Ecs, OPTION_ECS, OptRecord, normalize_response, parse_ecs, parse_ecs_option, parse_opt,
    prepare_query, query_ecs, remove_ecs,
};
pub use wire::{
    DnsError, Header, Message, Question, ResourceRecord, build_response, decode_name, encode_name,
    extract_ip_bytes, find_rr_by_type, parse_answers, parse_message, parse_svcb_rdata,
    reencode_rdata, replace_svcb_param, servfail,
};
