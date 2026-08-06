//! Positive-response IP collection.

use std::{collections::HashSet, time::Duration};

use futures_util::{
    future::{Either, select},
    pin_mut,
    stream::{FuturesUnordered, StreamExt},
};

use crate::{
    algo::{CancellationToken, DeadlineTimer, MAX_CONCURRENT_UPSTREAMS, QueryOutcome, Upstream},
    dns::{Classification, extract_ip_bytes, parse_answers},
};

pub const DEFAULT_DEADLINE: Duration = Duration::from_millis(200);

/// Runtime-independent settings for [`collect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MixOptions {
    pub deadline: Duration,
    pub max_concurrency: usize,
}

impl Default for MixOptions {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_DEADLINE,
            max_concurrency: MAX_CONCURRENT_UPSTREAMS,
        }
    }
}

/// Collects every IP from positive responses before the deadline.
///
/// The output preserves the first appearance of each IP in upstream completion order.  No address
/// filtering or output limit is applied.
pub async fn collect<U, T>(
    upstreams: &[U],
    body: &[u8],
    options: MixOptions,
    timer: &T,
) -> Vec<Vec<u8>>
where
    U: Upstream,
    T: DeadlineTimer,
{
    let cancellations: Vec<_> = (0..upstreams.len())
        .map(|_| CancellationToken::default())
        .collect();
    let mut pending = FuturesUnordered::new();
    let mut next_upstream = 0;
    let max_concurrency = concurrency_limit(options.max_concurrency, upstreams.len());
    while next_upstream < upstreams.len() && next_upstream < max_concurrency {
        pending.push(upstreams[next_upstream].query(body, cancellations[next_upstream].clone()));
        next_upstream += 1;
    }

    let deadline = timer.wait(options.deadline);
    pin_mut!(deadline);
    let mut ips = Vec::new();
    let mut seen = HashSet::new();

    while !pending.is_empty() {
        match select(pending.next(), deadline.as_mut()).await {
            Either::Left((Some(Ok(outcome)), _)) => append_ips(&outcome, &mut ips, &mut seen),
            Either::Left((Some(Err(_)) | None, _)) => {}
            Either::Right(((), next)) => {
                drop(next);
                cancel_all(&cancellations);
                drop(pending);
                break;
            }
        }

        if next_upstream < upstreams.len() {
            pending
                .push(upstreams[next_upstream].query(body, cancellations[next_upstream].clone()));
            next_upstream += 1;
        }
    }

    ips
}

fn concurrency_limit(configured: usize, upstream_count: usize) -> usize {
    let configured = if configured == 0 {
        upstream_count
    } else {
        configured
    };
    configured.min(MAX_CONCURRENT_UPSTREAMS).min(upstream_count)
}

fn append_ips(outcome: &QueryOutcome, ips: &mut Vec<Vec<u8>>, seen: &mut HashSet<Vec<u8>>) {
    if outcome.classification != Classification::Positive {
        return;
    }
    let Ok(answers) = parse_answers(&outcome.body) else {
        return;
    };
    for answer in answers {
        let Some(ip) = extract_ip_bytes(&answer) else {
            continue;
        };
        let ip = ip.to_vec();
        if seen.insert(ip.clone()) {
            ips.push(ip);
        }
    }
}

fn cancel_all(cancellations: &[CancellationToken]) {
    for cancellation in cancellations {
        cancellation.cancel();
    }
}
