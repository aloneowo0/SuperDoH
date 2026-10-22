# Local sampled-stack diagnostic — 2026-10-22

## Scope and conclusion

This follows the [isolated online acceptance](online-results-2026-10-22.md) recorded in `a7ea787`. **No additional online traffic, deployment, credential use, authentication downgrade or production algorithm change occurred.** The online decision remains **not accepted as a complete Free-plan release**.

An opt-in harness now captures local V8 sampling profiles through the production `src/worker.js` HTTP entry in real workerd. It confirms that **first-use default trust-anchor preparation is a major local hotspot**. It also demonstrates local due-refresh versus cached-list source access. This is diagnostic evidence for selecting the next optimization, not evidence that CPU or acceptance has improved.

## Reproduce

With the repository's locked dependencies and Node.js 22+:

```sh
npm ci
node test/profile-local.mjs
```

The command accepts no endpoint, mode or credential arguments. It:

- Creates a fresh ignored `.acceptance/local-profiles-*` directory, so old/concurrent captures cannot be merged accidentally.
- Bundles the unchanged production entry and uses the configured workerd date/flags.
- Opens a loopback-only ephemeral inspector and uses CDP `Profiler.start` / `Profiler.stop` around each public DoH request, requesting a 100 µs sampling interval.
- Sends 14 local requests: fixed answer (2), default-authenticated probe to a controlled TLS-alert peer (3), explicit fixture-root authenticated probe to that same peer (3), and 1,000-entry list cases with 1 ms and 60,000 ms refresh intervals (3 each).
- Allows the intercepted HTTP fixture only at `lists.test`; its response contains documentation-domain list data. The raw TCP peer and inspector listen on `127.0.0.1`, not public interfaces. The fixture sends a TLS alert, deliberately preventing a successful handshake. Both probe cases retain certificate verification enabled.
- Independently checks DNS response status, transaction ID, question, expected RCODE and list TTL 30. It counts fixture accesses and local TCP connections, closes sockets/inspectors and disposes each Miniflare instance.
- Saves 14 `.cpuprofile` files for DevTools/VS Code plus `summary.json`. Raw profiles stay ignored; only allowlisted statistics and profile digests are committed in [local-profile.json](results/2026-10-22/local-profile.json).

The fixed answer and list cases return NOERROR; the alert-peer probes return SERVFAIL as expected. This is not a positive ECH interoperability test. Use the separate independent OpenSSL test for authenticated success.

## Recorded local observations

Windows Node v24.14.0, workerd 1.20260730.1, compatibility date 2026-07-30. The final harness run exited 0 and produced all 14 profiles with matching response assertions. Source/harness hashes and exact profile digests are in the JSON evidence.

| Local capture | Profile window ms | Samples | Idle-labeled ms | Inclusive `prepareTrustAnchors` sampled ms | Inclusive `parseDer` sampled ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default roots, first | 440.325 | 651 | 64.660 | 314.402 | 299.816 |
| Default roots, next | 33.371 | 8 | 28.394 | 0.655 | 0 observed |
| Default roots, next | 28.206 | 9 | 18.654 | 0 observed | 0 observed |
| Explicit fixture root, first | 129.096 | 96 | 59.674 | 25.184 | 23.297 |
| Explicit fixture root, next | 29.827 | 31 | 9.562 | 9.291 | 8.663 |
| Explicit fixture root, next | 29.693 | 23 | 10.287 | 7.913 | 7.913 |

These are **sample weights and profile windows**, not Cloudflare quota CPU. Windows scheduling/sampling granularity, profiler overhead, idle and unattributed native/program frames limit precision. Inclusive stack weights overlap: `parseDer` is largely within `prepareTrustAnchors`; do not add them. Zero observed samples do not prove zero execution cost. Short warm profiles have too few samples for reliable fine-grained attribution or tail percentiles.

The controlled list source was accessed **three times** for the 1 ms interval and **once** for the 60,000 ms interval across three queries each. All six replies carried TTL 30. This establishes local maintenance/reuse behavior, not a new online cache/isolate observation, a recommendation to change freshness, or a Free CPU guarantee. Source-call counters reset per case; the TCP counter is cumulative across the whole diagnostic and ends at six connections.

## What source inspection confirms

- `lib/ech-probe/internal/certificate.js:45` already caches prepared **default** anchor records per isolate and returns defensive DER copies. The warm default-root profiles therefore do **not** justify proposing a new unbounded global cache.
- The initial valid-root preparation repeats structural DER work: `decodePem` calls `parseDer`, returns its bytes, and `prepareTrustAnchors` later calls `result.map(parseDer)` again. The DER-input branch also parses once before that map. Canonical DER/signature-algorithm checks remain essential; the candidate optimization is to retain the already-validated private record rather than repeat the same parsing, **not skip validation**.
- Explicit custom roots are preflight-validated by `src/rules/config.js:76`, validated again by the probe adapter, then prepared by the generic library. This explains why structural root preparation remains visible in the custom-root warm profiles. It does not prove that all repeated checks are removable: unreachable invalid configuration must still fail before action execution, direct library callers must still be validated, and mutable caller data must not bypass validation via cache identity.
- The default probe prepares anchors before opening its raw TCP socket (`lib/ech-probe/internal/probe.js:36`). Thus an unsuccessful peer/destination can still incur expensive first-use setup. The local alert fixture reproduces that ordering; it does **not** establish the exact low-level cause of the earlier public probe failure or its precise per-function CPU split.
- The list refresh path deliberately invalidates the old snapshot before loading/parsing its replacement. Faster code must preserve unavailable-on-failure behavior, shared quotas, deadlines and memory limits; returning old data is not an acceptable optimization.

## Next optimization boundary

The smallest candidate is removing duplicate parse/serialization work **within one trust-preparation call**, while preserving the complete canonical DER checks, limits, owned copies and certificate-chain behavior. Compare fresh-isolate profiles before/after; keep public malformed-root, mutation/isolation, wrong-SNI, untrusted-chain and independent authenticated-handshake regressions. Do not claim 10 ms compliance from a local reduction or move expensive work to Cron and call the quota solved.

No such production change has been made in this diagnostic commit. Broader options—lazy/default trust indexing, caching compiled configuration, different list refresh policy, another remote source, or a different probe service/plan—have separate invalidation, correctness, freshness or cost trade-offs. They are not silently selected by this harness. Any new online verification still needs the applicable account/resource/source/telemetry authorization.

## References

- [Cloudflare local CPU profiling](https://developers.cloudflare.com/workers/observability/dev-tools/cpu-usage/), retrieved 2026-10-22.
- [Workers CPU limits](https://developers.cloudflare.com/workers/platform/limits/#cpu-time).
- [Recorded online limitations](online-results-2026-10-22.md).

## Verification

The opt-in diagnostic exited 0 with all 14 public response assertions and profiles. The full default `npm test` was rerun afterward and exited 0: typechecking, 237 application/tool tests, 130 DNS library tests and 104 ECH offline tests. The diagnostic is deliberately not added to that default total. Independent Sonnet Standards and Spec reviews found no concrete remaining findings; the Spec pass matched the harness hash, observation table and repeated-DER call path. The online evidence and overall acceptance status were not changed.
