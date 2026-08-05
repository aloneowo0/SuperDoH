use crate::{config, dns};

use super::{
    ParsedQuery, PolicyError, RequestCtx, RuntimeUpstream,
    classify::{self, DomainMatch, Owner},
    ech, fast_query,
    logger::{self, LogLevel},
    upstream::{self, UpstreamTrace},
};

pub(crate) async fn synthesize_nodata(
    original: &[u8],
    query: &ParsedQuery,
    region: &config::RegionConfig,
    client_ip: Option<std::net::IpAddr>,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
    ctx: &mut RequestCtx,
) -> Result<Option<Vec<u8>>, PolicyError> {
    if query.question.qtype != dns::wire::TYPE_HTTPS || !region.ech {
        return Ok(None);
    }

    let owner_and_source =
        match classify::domain_match(&query.question.name, query.question.qtype, region) {
            Some(DomainMatch::Remap) => Some((Owner::Cf, "domain_remap")),
            Some(DomainMatch::Meta) => Some((Owner::Meta, "domain_meta")),
            Some(DomainMatch::Google(_)) => None,
            None => probe_owner(query, client_ip, runtime_upstreams, trace, ctx)
                .await
                .map(|owner| (owner, "side_address_probe")),
        };
    let Some((owner, source)) = owner_and_source else {
        return Ok(None);
    };
    if !matches!(owner, Owner::Cf | Owner::Meta) {
        return Ok(None);
    }

    ctx.owner = Some(owner.label().to_owned());
    logger::log_event(
        ctx,
        LogLevel::Info,
        "owner_classified",
        serde_json::json!({"owner": owner.label(), "source": source, "for": "https_synthesis"}),
    );

    let ttl = match owner {
        Owner::Cf => config::PREFERRED_TTL,
        Owner::Meta => config::MIX_TTL,
        Owner::Cft | Owner::Vercel | Owner::Google => return Ok(None),
    };
    let updated = ech::inject(
        original,
        query,
        ech::InjectionMode::Synthesize { owner, ttl },
        client_ip,
        runtime_upstreams,
        trace,
        ctx,
    )
    .await?;
    if updated == original {
        Ok(None)
    } else {
        Ok(Some(updated))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerEvidence {
    None,
    Owner(Owner),
    Ambiguous,
}

async fn probe_owner(
    query: &ParsedQuery,
    client_ip: Option<std::net::IpAddr>,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
    ctx: &mut RequestCtx,
) -> Option<Owner> {
    let mut owner = None;
    let mut saw_evidence = false;

    for qtype in [dns::wire::TYPE_A, dns::wire::TYPE_AAAA] {
        let evidence = probe_family_owner(query, qtype, client_ip, runtime_upstreams, trace).await;
        let candidate = match evidence {
            OwnerEvidence::None => continue,
            OwnerEvidence::Owner(candidate) => candidate,
            OwnerEvidence::Ambiguous => {
                logger::log_event(
                    ctx,
                    LogLevel::Debug,
                    "https_owner_probe_rejected",
                    serde_json::json!({"reason": "ambiguous_family_evidence"}),
                );
                return None;
            }
        };
        saw_evidence = true;
        if let Some(current) = owner
            && current != candidate
        {
            logger::log_event(
                ctx,
                LogLevel::Debug,
                "https_owner_probe_rejected",
                serde_json::json!({"reason": "mixed_owner_evidence"}),
            );
            return None;
        }
        owner = Some(candidate);
    }

    if !saw_evidence {
        logger::log_event(
            ctx,
            LogLevel::Debug,
            "https_owner_probe_rejected",
            serde_json::json!({"reason": "no_owner_evidence"}),
        );
        return None;
    }
    owner
}

async fn probe_family_owner(
    query: &ParsedQuery,
    qtype: u16,
    client_ip: Option<std::net::IpAddr>,
    runtime_upstreams: Option<&[RuntimeUpstream]>,
    trace: &UpstreamTrace,
) -> OwnerEvidence {
    let Ok(wire) = upstream::build_query(&query.question.name, qtype, query.id) else {
        return OwnerEvidence::None;
    };
    let side_query = ParsedQuery {
        id: query.id,
        flags: 0x0100,
        question: dns::Question {
            name: query.question.name.clone(),
            qtype,
            qclass: dns::wire::CLASS_IN,
        },
        client_sent_ecs: false,
        edns: None,
    };
    let result = fast_query(
        &wire,
        &side_query,
        client_ip,
        false,
        runtime_upstreams,
        trace,
        |outcome| outcome.classification == dns::Classification::Positive,
    )
    .await;
    let Some(result) = result else {
        return OwnerEvidence::None;
    };
    classify::owner_for_response(&result.body, qtype)
        .map_or(OwnerEvidence::Ambiguous, OwnerEvidence::Owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_evidence_distinguishes_absent_and_ambiguous() {
        assert_ne!(OwnerEvidence::None, OwnerEvidence::Ambiguous);
        assert_eq!(
            OwnerEvidence::Owner(Owner::Cf),
            OwnerEvidence::Owner(Owner::Cf)
        );
    }
}
