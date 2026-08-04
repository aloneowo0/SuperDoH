use crate::{config, dns};

use super::{
    ParsedQuery, PolicyError, RequestCtx, RuntimeUpstream,
    classify::{self, Owner},
    fast_query,
    logger::{self, LogLevel},
    response,
    upstream::{self, UpstreamTrace},
};

#[expect(
    clippy::too_many_arguments,
    reason = "the policy call site keeps owner selection inputs explicit"
)]
pub(crate) async fn replace(
    original: &[u8],
    query: &ParsedQuery,
    preferred_domain: &str,
    expected_owner: Owner,
    client_ip: Option<std::net::IpAddr>,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
    ctx: &mut RequestCtx,
) -> Result<Vec<u8>, PolicyError> {
    if !matches!(
        query.question.qtype,
        dns::wire::TYPE_A | dns::wire::TYPE_AAAA
    ) || preferred_domain.is_empty()
    {
        return Ok(original.to_vec());
    }

    let preferred_query = upstream::build_query(preferred_domain, query.question.qtype, query.id)?;
    let mut preferred_question = query.clone();
    preferred_domain.clone_into(&mut preferred_question.question.name);
    let expected_owner_for_accept = expected_owner;
    let result = fast_query(
        &preferred_query,
        &preferred_question,
        client_ip,
        true,
        runtime_upstreams,
        trace,
        move |outcome| accepts_owner(outcome, query.question.qtype, expected_owner_for_accept),
    )
    .await;
    let Some(result) = result else {
        logger::log_event(
            ctx,
            LogLevel::Warn,
            "fallback",
            serde_json::json!({
                "stage": "preferred",
                "owner": expected_owner.label(),
                "reason": "no_accepted_preferred_response",
            }),
        );
        return Ok(original.to_vec());
    };
    let ips = classify::ips_for_type(&result.body, query.question.qtype);
    if ips.is_empty() {
        return Ok(original.to_vec());
    }
    let output = response::replace_ips(original, query, &ips, config::PREFERRED_TTL)?;
    ctx.optimization_applied = true;
    logger::log_event(
        ctx,
        LogLevel::Info,
        "preferred_replaced",
        serde_json::json!({
            "owner": expected_owner.label(),
            "candidateCount": ips.len(),
        }),
    );
    Ok(output)
}

fn accepts_owner(outcome: &crate::algo::QueryOutcome, qtype: u16, expected: Owner) -> bool {
    let ips = classify::ips_for_type(&outcome.body, qtype);
    !ips.is_empty()
        && ips.iter().all(|ip| {
            classify::ip_from_bytes(ip)
                .and_then(classify::owner_for_ip)
                .is_some_and(|owner| owner == expected)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{CLASS_IN, TYPE_A};
    use crate::dns::{Classification, Question, build_response};

    #[test]
    fn only_accepts_expected_owner_addresses() {
        let body = build_response(
            1,
            "preferred.example",
            TYPE_A,
            &[vec![1, 1, 1, 1]],
            60,
            0x8180,
        );
        let body = match body {
            Ok(body) => body,
            Err(error) => panic!("test response must build: {error}"),
        };
        let result = crate::algo::QueryOutcome::new(body, Classification::Positive);
        assert!(accepts_owner(&result, TYPE_A, Owner::Cf));
        let _question = Question {
            name: "preferred.example".to_owned(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
    }
}
