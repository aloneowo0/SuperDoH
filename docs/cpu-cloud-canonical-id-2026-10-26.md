# Canonical-ID cloud CPU diagnosis — 2026-10-26

## Outcome

**The profiling blocker remains unresolved; no application fix or complete Free acceptance is claimed.** A separately authorized cloud-only continuation tested the canonical Worker ID with an exact active version and then `latest-deployed`. Both returned HTTP 404 / code 10393 despite ongoing correctly versioned traffic. Changing the Worker/version selectors did not resolve capture in this run; the underlying cause is not established.

[Sanitized evidence](results/2026-10-26/cpu-cloud-canonical-id.json) contains all attempts, joined native metrics, captures, configuration, module hashes, reproduction runner and independently verified restoration. This is progress on [#25](https://github.com/aloneowo0/SuperDoH/issues/25), not completion of that issue or [#7](https://github.com/aloneowo0/SuperDoH/issues/7).

## Scope and provenance

A new allowance, separate from prior runs: at most 60 client attempts including cleanup, serialized with at least one second after completion, and at most two CPU profile requests of at most ten seconds. Only the existing isolated `superdoh` producer and `superdoh-dns-cpu-fixtures-20261024` fixture were authorized. Cloudflare MCP handled all control-plane work; no Wrangler credential fallback, browser login, new resource, billing, business Worker, DNS or route change occurred. No public ECH probe or DoT workload ran.

The producer used the exact previously verified deployed `0582d86` application modules, not the dirty local workspace or its uncommitted DoT removal. They were not optimized or rebuilt:

- JS SHA-256: `3b32bd2b2bbee8242da529f0b8f504c7ac84911d34b71a85a6c6c340a52be007`.
- WASM SHA-256: `b19b09a573512b21f50c943c72ec6553078328623f442a511ddf33cd0b1f3a73`.

A separate temporary wrapper added expiry, correlation events and a version header around public `handleRequest`. Original modules remained byte-identical. Compatibility date/flags were preserved. Invocation logs were enabled and traces disabled during measurement; restored settings are described below.

The composed scenario retained controlled list membership, response-address attribution, DNS-source ECH, optional upstream failure/rollback, additional A, TTL 17 and AD clearing. The expected `UPSTREAM_FAILED / rolled_back_continue` event is not a failed final answer. All observed client edge labels were FRA, not proof of shared isolate identity.

## Native CPU and Wall

| Phase | Samples | CPU median / range, ms | CPU >10 ms | Wall median / range, ms |
| --- | ---: | --- | ---: | --- |
| Warmup | 16 | 7 / 5–37 | 1 | 23 / 21–139 |
| Measured, partial | 34 of 38 planned | 6 / 4–13 | 1 | 22 / 20–53 |

All 50 payloads passed independent wire assertions. Each had exactly one UUID/version-correlated native CPU/Wall row and one result event joined through the same native request ID. The telemetry query returned 150 events: 50 native, 50 result and 50 expected optional-failure events, below its 2,000-event limit. There were no missing, ambiguous or unmatched native rows; exported CSV SHA-256 was checked locally.

All outcomes were `ok`; that does not establish quota compliance. These 34 measured samples are an explicitly incomplete planned round, stopped because profiling failed, not selected according to CPU. No code improvement, cross-deployment A/B result, precise cold/warm identity or p95/p99 is inferred. Client elapsed time is separate from native CPU and Wall. Historical higher medians are not overwritten by this lower partial median.

## Capture-selection checks

Read-only metadata confirmed canonical ID `4469823865b04c96b95680ecbab4d3e7` belongs to `superdoh`. Measured version: `77889cac-b81c-4c3f-a57f-71439c73c2ae`, 100% active.

| Attempt | Version selector | Start, UTC | Result |
| --- | --- | --- | --- |
| 1 | Exact measured UUID | 03:02:29.372 | 404 / 10393: No recent executions were found for this Worker. |
| 2 | `latest-deployed`, after verifying the same 100% active UUID | 03:02:53.807 | Same 404 / 10393 |

The API requests selected the same Worker and intended active version. Only the selector changed; application, bindings and workload were unchanged between attempts. The first capture began 1,094 ms after the latest completed client request; the second began 336 ms after one. Requests continued after each. A request was already in flight around the first capture; complete timestamps are retained. Native and client clocks are separate, so these timings establish ongoing workload rather than exact isolate selection timing.

[Cloudflare profiling documentation](https://developers.cloudflare.com/workers/observability/profiling-in-production/) requires representative traffic before and during capture and documents the returned error. The [API contract](https://developers.cloudflare.com/api/resources/workers/subresources/workers/subresources/versions/methods/profile/) supports ID/name and `latest-deployed` selectors. These results do not prove an authentication, account-entitlement, isolate-lifetime or Cloudflare platform defect. MCP remained usable for control and telemetry. No third capture or alternate-credential attempt was made. No pprof decoder ran because no profile was obtained.

## Accounting and restoration

**52/60 client attempts:** 16 warmups + 34 measured + 2 cleanup checks. Minimum completion-to-next-start gap was 1,051 ms. Once both captures failed, a stop flag terminated the runner after its in-flight request; its `STOP_REQUESTED` exit is intentional, not a DNS failure. Four planned measured requests were not sent. The two capture attempts used the entire capture allowance; unused client slots were not reused.

- Producer restored to `f5ccd128-c42f-45f5-bd6f-7acdfc263a3c`: original two modules, wrapper removed, empty active/latest bindings. A separate post-cleanup download verified original JS/WASM hashes.
- Fixture restored to `c489c361-819f-485d-ba7f-6168ede2f3ce`: active/latest EXPIRES_AT=0 and LIST_STATE=good; observability remained absent/null.
- Producer observability restored exactly: logs, invocation logs **and traces enabled**, not disabled.
- Public cleanup verified empty-configuration DNS SERVFAIL and fixture HTTP 503. No ongoing client or scheduled traffic remains.

## Verification and next boundary

`npm --prefix SuperDoH run typecheck` passed. No production code changed, so no speculative regression test or CPU fix was created. Per the cloud-only instruction, local Node/Miniflare behavior tests and the full npm suite were not run; the 50 cloud wire checks and two cleanup checks are not a replacement for complete regression or Free acceptance. All 15 previously modified tracked files remained byte-identical.

The next diagnostic step needs a working profile capture route or a representative redacted profile from Cloudflare. Repeating the same failed requests, weakening protocol checks, declaring a cached result sufficient, or guessing a hotspot is not justified. The source-fix-verifying feedback loop, root cause, minimization and CPU optimization remain blocked. Reproduction sources in the evidence require fresh operational authorization and the documented local tooling/proxy prerequisites; they are not a self-authorizing clean-checkout benchmark.
