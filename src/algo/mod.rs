//! Runtime-independent upstream query algorithms.

use core::future::Future;
use std::{
    cell::RefCell,
    mem,
    rc::Rc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crate::dns::Classification;

pub mod fast;
pub mod mix;

pub const MAX_CONCURRENT_UPSTREAMS: usize = 6;

/// A completed upstream response and its DNS semantic classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOutcome {
    pub body: Vec<u8>,
    pub classification: Classification,
}

impl QueryOutcome {
    #[must_use]
    pub const fn new(body: Vec<u8>, classification: Classification) -> Self {
        Self {
            body,
            classification,
        }
    }
}

/// Cooperative cancellation passed to every upstream query.
///
/// A transport implementation must race its operation against [`CancellationToken::cancelled`]
/// and invoke its native abort operation before it resolves the cancellation path.
#[derive(Clone, Default)]
pub struct CancellationToken {
    state: Rc<RefCell<CancellationState>>,
}

#[derive(Default)]
struct CancellationState {
    cancelled: bool,
    wakers: Vec<Waker>,
}

impl CancellationToken {
    /// Cancels the query and wakes transport code waiting on [`Self::cancelled`].
    pub fn cancel(&self) {
        let wakers = {
            let mut state = self.state.borrow_mut();
            if state.cancelled {
                return;
            }
            state.cancelled = true;
            mem::take(&mut state.wakers)
        };

        for waker in wakers {
            waker.wake();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.borrow().cancelled
    }

    /// Returns a future that resolves once this token has been cancelled.
    #[must_use]
    pub fn cancelled(&self) -> Cancelled {
        Cancelled {
            token: self.clone(),
        }
    }
}

/// Future returned by [`CancellationToken::cancelled`].
pub struct Cancelled {
    token: CancellationToken,
}

impl Future for Cancelled {
    type Output = ();

    fn poll(self: core::pin::Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.token.state.borrow_mut();
        if state.cancelled {
            return Poll::Ready(());
        }
        if !state
            .wakers
            .iter()
            .any(|waker| waker.will_wake(context.waker()))
        {
            state.wakers.push(context.waker().clone());
        }
        Poll::Pending
    }
}

/// Runtime-specific upstream query operation used by [`fast`] and [`mix`].
pub trait Upstream {
    type Error;
    type Query<'a>: Future<Output = Result<QueryOutcome, Self::Error>> + 'a
    where
        Self: 'a;

    /// Starts a query. Implementations must honor `cancellation` with a real transport abort.
    fn query<'a>(&'a self, body: &'a [u8], cancellation: CancellationToken) -> Self::Query<'a>;
}

/// Supplies a deadline future without coupling algorithms to an async runtime.
pub trait DeadlineTimer {
    type Wait: Future<Output = ()>;

    fn wait(&self, duration: Duration) -> Self::Wait;
}

#[cfg(test)]
mod tests {
    use core::{
        convert::Infallible,
        future::Future,
        pin::pin,
        task::{Context, Poll},
    };
    use std::{cell::RefCell, rc::Rc, time::Duration};

    use futures_util::task::noop_waker_ref;

    use super::{
        CancellationToken, DeadlineTimer, MAX_CONCURRENT_UPSTREAMS, QueryOutcome, Upstream,
        fast::{self, FastOptions},
        mix::{self, MixOptions},
    };
    use crate::dns::wire::{CLASS_IN, TYPE_A};
    use crate::dns::{Classification, Question, build_response, classify_response};

    #[derive(Clone)]
    struct MockUpstream {
        outcome: QueryOutcome,
        polls_before_ready: usize,
        cancellations: Rc<RefCell<Vec<CancellationToken>>>,
    }

    impl MockUpstream {
        fn new(outcome: QueryOutcome, polls_before_ready: usize) -> Self {
            Self {
                outcome,
                polls_before_ready,
                cancellations: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn was_cancelled(&self) -> bool {
            self.cancellations
                .borrow()
                .iter()
                .all(CancellationToken::is_cancelled)
        }
    }

    struct MockQuery {
        cancellation: CancellationToken,
        outcome: Option<QueryOutcome>,
        polls_before_ready: usize,
    }

    impl Future for MockQuery {
        type Output = Result<QueryOutcome, Infallible>;

        fn poll(
            mut self: core::pin::Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Self::Output> {
            if self.cancellation.is_cancelled() {
                unreachable!("cancelled mock query must be dropped by the algorithm")
            }
            if self.polls_before_ready == 0 {
                let Some(outcome) = self.outcome.take() else {
                    unreachable!("mock query polled after completion")
                };
                return Poll::Ready(Ok(outcome));
            }
            self.polls_before_ready -= 1;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }

    impl Upstream for MockUpstream {
        type Error = Infallible;
        type Query<'a> = MockQuery;

        fn query<'a>(
            &'a self,
            _body: &'a [u8],
            cancellation: CancellationToken,
        ) -> Self::Query<'a> {
            self.cancellations.borrow_mut().push(cancellation.clone());
            MockQuery {
                cancellation,
                outcome: Some(self.outcome.clone()),
                polls_before_ready: self.polls_before_ready,
            }
        }
    }

    #[derive(Clone, Copy)]
    struct PollTimer(usize);

    struct PollDeadline(usize);

    impl Future for PollDeadline {
        type Output = ();

        fn poll(
            mut self: core::pin::Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Self::Output> {
            if self.0 == 0 {
                return Poll::Ready(());
            }
            self.0 -= 1;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }

    impl DeadlineTimer for PollTimer {
        type Wait = PollDeadline;

        fn wait(&self, _duration: Duration) -> Self::Wait {
            PollDeadline(self.0)
        }
    }

    fn run<F: Future>(future: F) -> F::Output {
        let waker = noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    fn question() -> Question {
        Question {
            name: "example.com".to_owned(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        }
    }

    fn response(flags: u16, records: &[Vec<u8>]) -> QueryOutcome {
        let body = match build_response(7, "example.com", TYPE_A, records, 60, flags) {
            Ok(body) => body,
            Err(error) => panic!("test DNS response must be valid: {error}"),
        };
        let classification = classify_response(&body, 7, &question(), &[]);
        QueryOutcome::new(body, classification)
    }

    fn positive(last_octet: u8) -> QueryOutcome {
        response(0x8180, &[vec![192, 0, 2, last_octet]])
    }

    #[test]
    fn fast_returns_the_first_positive_and_cancels_losers() {
        let slow = MockUpstream::new(positive(1), 2);
        let fast_outcome = positive(2);
        let fast_upstream = MockUpstream::new(fast_outcome.clone(), 0);

        let result = run(fast::race(
            &[slow.clone(), fast_upstream],
            &[0],
            FastOptions::default(),
            &PollTimer(8),
            |_| true,
        ));

        assert_eq!(result, Some(fast_outcome));
        assert!(slow.was_cancelled());
    }

    #[test]
    fn fast_keeps_a_negative_as_the_fallback() {
        let negative = response(0x8183, &[]);
        let delayed_positive = MockUpstream::new(positive(3), usize::MAX);

        let result = run(fast::race(
            &[
                MockUpstream::new(negative.clone(), 0),
                delayed_positive.clone(),
            ],
            &[0],
            FastOptions::default(),
            &PollTimer(0),
            |_| true,
        ));

        assert_eq!(result, Some(negative));
        assert!(delayed_positive.was_cancelled());
    }

    #[test]
    fn fast_discards_results_rejected_by_accept() {
        let rejected = positive(4);
        let accepted = positive(5);

        let result = run(fast::race(
            &[
                MockUpstream::new(rejected.clone(), 0),
                MockUpstream::new(accepted.clone(), 1),
            ],
            &[0],
            FastOptions::default(),
            &PollTimer(8),
            |outcome| outcome.body != rejected.body,
        ));

        assert_eq!(result, Some(accepted));
    }

    #[test]
    fn fast_returns_none_and_cancels_on_deadline() {
        let first = MockUpstream::new(positive(6), usize::MAX);
        let second = MockUpstream::new(positive(7), usize::MAX);

        let result = run(fast::race(
            &[first.clone(), second.clone()],
            &[0],
            FastOptions::default(),
            &PollTimer(0),
            |_| true,
        ));

        assert_eq!(result, None);
        assert!(first.was_cancelled());
        assert!(second.was_cancelled());
    }

    #[test]
    fn fast_starts_at_most_six_queries() {
        let upstreams: Vec<_> = (0..MAX_CONCURRENT_UPSTREAMS + 2)
            .map(|_| MockUpstream::new(positive(1), usize::MAX))
            .collect();

        let result = run(fast::race(
            &upstreams,
            &[0],
            FastOptions::default(),
            &PollTimer(0),
            |_| true,
        ));

        assert_eq!(result, None);
        assert_eq!(
            upstreams
                .iter()
                .map(|upstream| upstream.cancellations.borrow().len())
                .sum::<usize>(),
            MAX_CONCURRENT_UPSTREAMS
        );
    }

    #[test]
    fn mix_collects_all_positive_ips_without_duplicates() {
        let first = MockUpstream::new(
            response(0x8180, &[vec![192, 0, 2, 10], vec![192, 0, 2, 11]]),
            0,
        );
        let second = MockUpstream::new(
            response(0x8180, &[vec![192, 0, 2, 11], vec![192, 0, 2, 12]]),
            0,
        );
        let negative = MockUpstream::new(response(0x8183, &[]), 0);

        let ips = run(mix::collect(
            &[first, second, negative],
            &[0],
            MixOptions::default(),
            &PollTimer(8),
        ));

        assert_eq!(
            ips,
            vec![
                vec![192, 0, 2, 10],
                vec![192, 0, 2, 11],
                vec![192, 0, 2, 12],
            ]
        );
    }

    #[test]
    fn mix_starts_at_most_six_queries() {
        let upstreams: Vec<_> = (0..MAX_CONCURRENT_UPSTREAMS + 2)
            .map(|_| MockUpstream::new(positive(1), usize::MAX))
            .collect();

        let ips = run(mix::collect(
            &upstreams,
            &[0],
            MixOptions::default(),
            &PollTimer(0),
        ));

        assert!(ips.is_empty());
        assert_eq!(
            upstreams
                .iter()
                .map(|upstream| upstream.cancellations.borrow().len())
                .sum::<usize>(),
            MAX_CONCURRENT_UPSTREAMS
        );
    }

    #[test]
    fn response_helpers_use_dns_classification() {
        assert_eq!(positive(8).classification, Classification::Positive);
    }
}
