//! First acceptable positive response racing.

use std::time::Duration;

use futures_util::{
    future::{Either, select},
    pin_mut,
    stream::{FuturesUnordered, StreamExt},
};

use crate::{
    algo::{CancellationToken, DeadlineTimer, MAX_CONCURRENT_UPSTREAMS, QueryOutcome, Upstream},
    dns::Classification,
};

pub const DEFAULT_DEADLINE: Duration = Duration::from_millis(200);

/// Runtime-independent settings for [`race`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastOptions {
    pub deadline: Duration,
}

impl Default for FastOptions {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_DEADLINE,
        }
    }
}

/// Concurrently queries all upstreams and returns the first accepted positive response.
///
/// The first accepted negative response is retained as a fallback.  `None` means the deadline
/// expired without an accepted response.  IP collection and any business-specific acceptance
/// rules belong to the caller.
pub async fn race<U, T, A>(
    upstreams: &[U],
    body: &[u8],
    options: FastOptions,
    timer: &T,
    accept: A,
) -> Option<QueryOutcome>
where
    U: Upstream,
    T: DeadlineTimer,
    A: Fn(&QueryOutcome) -> bool,
{
    let cancellations: Vec<_> = (0..upstreams.len())
        .map(|_| CancellationToken::default())
        .collect();
    let mut pending = FuturesUnordered::new();
    let mut next_upstream = 0;
    while next_upstream < upstreams.len() && next_upstream < MAX_CONCURRENT_UPSTREAMS {
        pending.push(upstreams[next_upstream].query(body, cancellations[next_upstream].clone()));
        next_upstream += 1;
    }

    let deadline = timer.wait(options.deadline);
    pin_mut!(deadline);
    let mut negative = None;

    while !pending.is_empty() {
        match select(pending.next(), deadline.as_mut()).await {
            Either::Left((Some(Ok(outcome)), _)) => match outcome.classification {
                Classification::Positive if accept(&outcome) => {
                    cancel_all(&cancellations);
                    drop(pending);
                    return Some(outcome);
                }
                Classification::Negative(_) if accept(&outcome) && negative.is_none() => {
                    negative = Some(outcome);
                }
                Classification::Positive
                | Classification::Negative(_)
                | Classification::Invalid => {}
            },
            Either::Left((Some(Err(_)), _)) => {}
            Either::Left((None, _)) => break,
            Either::Right(((), next)) => {
                drop(next);
                cancel_all(&cancellations);
                drop(pending);
                return negative;
            }
        }

        if next_upstream < upstreams.len() {
            pending
                .push(upstreams[next_upstream].query(body, cancellations[next_upstream].clone()));
            next_upstream += 1;
        }
    }

    negative
}

fn cancel_all(cancellations: &[CancellationToken]) {
    for cancellation in cancellations {
        cancellation.cancel();
    }
}
