# Local stack-sampling diagnostic — 2026-10-22

## Correction: elapsed sample weights are not CPU

The original local summary in `54ba1ac` summed V8 profile `timeDeltas` and attributed them to the sampled stack. **A controlled one-second source wait disproved treating those weights as CPU, even after subtracting samples labeled `(idle)`.** Sampling can pause across I/O, leaving a large elapsed interval assigned to the next observed frame.

Accordingly, the earlier **314.402 ms `prepareTrustAnchors` weight must not be read as that function's CPU time**. The corrected tool exports stack-observation counts, elapsed profile windows and gap diagnostics, but no per-function CPU estimate. It does not clamp gaps or subtract an arbitrary threshold and call the remainder CPU.

This correction does not change the [online acceptance evidence](online-results-2026-10-22.md). A read-only re-query of the original platform invocation confirmed `$workers.cpuTimeMs:451`, `$workers.wallTimeMs:472` and `ECH_PROBE_FAILED`. Those are separate platform fields, not values derived from the local profiler or client latency. No new online invocation, deployment or credential-bearing request was performed.

## Explicit wait control

The production HTTP entry made a standard DNS query to an intercepted local source. The source returned identical valid DNS data, either immediately or after a one-second asynchronous wait. DNS cache reads/writes were disabled; all three requests in each case reached the source.

| Warm control | Observed stacks | Elapsed profile window | Longest sample gap | Old sum-minus-idle result: **invalid as CPU** |
| --- | ---: | ---: | ---: | ---: |
| Immediate source | 5 | 8.897 ms | 3.126 ms | 5.276 ms |
| Source waits 1 second | 5 | 1014.069 ms | 1005.134 ms | 1009.989 ms |

The one-second delay enlarged the elapsed window and a sample gap, not the amount of actual Worker computation by one second. This is why neither the profile window nor `sum(timeDeltas) - idle` is used as CPU. Stack counts are also **not** a calibrated CPU meter or a basis for claiming percentage CPU shares; suspension and sampling bias limit them.

Exact counts, counterexample arithmetic, original platform-field recheck and profile digests are in [local-profile.json](results/2026-10-22/local-profile.json), schema version 2. It explicitly supersedes the prior elapsed-weight interpretation.

## Reproduce locally

With Node.js 22+ and the locked development dependencies:

```sh
npm ci
node test/profile-local.mjs
```

The opt-in command accepts no endpoint, mode or credential arguments. It creates a fresh ignored `.acceptance/local-profiles-*` directory, bundles the unchanged production Worker, and uses its workerd date/flags. A loopback-only ephemeral inspector captures CDP profiles around public DoH requests, requesting a 100 microsecond sampling interval; that requested interval is not assumed to be the actual interval.

It sends **20 local requests**: fixed answers (2), default-authenticated probe against a loopback TLS-alert peer (3), explicit fixture-root authenticated probe against that peer (3), 1,000-entry list cases with 1 ms / 60,000 ms refresh (3 each), and immediate / one-second-wait DNS sources (3 each). The intercepted HTTP fixture permits only `lists.test` and `delay.test`; raw TCP and the inspector use loopback. Both probe cases retain certificate verification. The peer intentionally sends a TLS alert; this is not a successful ECH handshake test.

The harness independently checks HTTP status, DNS transaction ID/question, expected RCODE and list TTL 30, records source accesses, and closes the local server, sockets, inspectors and Miniflare instances. It saves 20 raw `.cpuprofile` files and `summary.json`. Raw profiles remain ignored; committed output contains allowlisted counts/metadata and digests, not credentials, request URLs or certificate dumps.

## Findings that remain supported

- The corrected first default-root profile contains `prepareTrustAnchors` on **359 of 421 observed stacks**, and `parseDer` on 344. This makes trust preparation a candidate for further investigation, **not a measurement of 359/421 of CPU or a number of CPU milliseconds**.
- Source inspection independently confirms repeated DER work: `decodePem` calls `parseDer` and returns bytes (`lib/ech-probe/internal/certificate.js:42`), followed by `result.map(parseDer)` in preparation (`:75`). The DER-input branch similarly parses before that map. This duplication is a code fact; no CPU saving has yet been measured from removing it.
- Default anchor records already have an isolate-local cache with defensive copies. Explicit custom roots are validated at core preflight, adapter execution and the library boundary. An optimization must retain invalid-unreachable-configuration rejection, canonical DER checks, bounds and mutable-input isolation; it cannot simply skip validation.
- The controlled list source was accessed three times for the 1 ms interval and once for the 60,000 ms interval, with TTL 30 in all six replies. This demonstrates local refresh/reuse behavior, not its CPU cost or new online cache coverage.
- Root preparation occurs before raw TCP connect. The loopback alert case reproduces that ordering but does not diagnose the precise public probe failure or the online invocation's per-function CPU split. The separate independent OpenSSL test remains the authenticated-positive interoperability check.

## Verification and limits

The corrected diagnostic completed all 20 public response assertions and profiles. Its built-in wait cases reproduce the counterexample; the exported summary contains no per-function millisecond weights or non-idle CPU estimate. Measurement CLI regression and typechecking are checked separately. No application/library algorithm, certificate policy, online measurement value, source destination or deployed configuration was changed.

After this correction, `npm test` passed all 237 application/tool tests, 130 DNS tests and 104 ECH offline tests. The separate 17-test measurement regression and `npm run typecheck` also passed. Independent Sonnet Standards and Spec reviews reported no concrete findings. The earlier full regression at `54ba1ac` did not validate the elapsed-to-CPU interpretation; the new wait counterexample is precisely the missing check. This opt-in diagnostic remains separate from the default test total.

References: [Cloudflare CPU and wall definitions](https://developers.cloudflare.com/workers/platform/limits/#cpu-time), [local profiling guidance](https://developers.cloudflare.com/workers/observability/dev-tools/cpu-usage/). Waiting on network I/O is not quota CPU; only actual platform CPU telemetry is used for the online limit comparison.
