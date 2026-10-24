# Public ECH connection diagnosis — 2026-10-23

## Result

**The configured `cloudflare-ech.com:443` raw TCP target is rejected before the socket opens.** In this run, failure occurs before sending a TLS ClientHello or receiving any TLS bytes. This establishes a connection-boundary failure for this target and runtime, not a certificate-validation, TLS-parser or missing-ECH-extension failure. It does not retroactively establish the precise cause of historical generic errors or another target.

The source baseline was `539a750`. The existing user-identified test Worker, `superdoh-meta-ech-probe-20261018132148`, was updated; no new Worker was created. The previous version was recorded for rollback. Business Workers, DNS and routes were not changed. Supported existing OAuth was used; the credential supplied in chat was not used or saved.

## Feedback loop and minimization

The test-only wrapper first called the unchanged production `handleRequest` with a fixed HTTPS answer followed by the configured required `probeEch` and `applyEch`. Five fixed-answer smoke samples passed, then the actual ECH path returned RCODE 2 (SERVFAIL). Requests assert DNS identity and compare the response's native deployment version with the version recorded at deployment. The guarded client command was run and exited 2 on the real failure:

```sh
node .acceptance/diag-20261023/client.mjs /path/to/baseline-deploy.log baseline
```

The loop requires an authorized deployment and the existing local network configuration; it is not a standalone offline reproduction. It serializes samples, waits at least one second after completion and records attempts before sending them. The client endpoint and deployment logs remain in ignored local state, not in this report.

Ranked checks distinguished connection rejection, a completed handshake without retry configs, TLS/protocol incompatibility and certificate/resource failures. The minimized socket check opens only the same target, awaits `opened`, then closes it; it sends no application data. The library diagnostics use the existing internal `probeWithConnect` seam with the real native `connect`, observing open/read/write boundaries without modifying production files or adding a public testing API.

| Path | Observed result |
| --- | --- |
| Fixed DNS smoke | 5/5 valid answers |
| Required production probe, default/omitted verification | 2/2 SERVFAIL across the two deployment versions |
| Required production probe, explicit verification | 1/1 SERVFAIL |
| Minimal native socket | `opened=false`, zero bytes sent/received |
| Actual library engine, default verification | `IO`, `opened=false`, zero bytes sent/received |
| Actual library engine, explicit verification | `IO`, `opened=false`, zero bytes sent/received |
| Explicit HTTPS DoH control | 1/1 valid answer through `cloudflare-dns.com` |

All three connection diagnostics matched the documented disallowed-destination error signature, exported only as `PLATFORM_DESTINATION_DISALLOWED`. Arbitrary exception messages, addresses, certificates and TLS payloads were not exported. Cloudflare [documents](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/) that outbound TCP to its IP ranges is blocked and documents the matching error signature. The observed platform rejection is sufficient to explain this run's failure; this run did not separately export a DNS-to-IP attribution measurement.

Disabling certificate validation cannot make this connection open. No automatic source substitution, HTTP tunnel, retry, fallback or authentication downgrade was added. A reachable public ECH source must be explicitly chosen and authorized before attempting successful-handshake acceptance. The old test Worker's original experimental target was not silently reused as an additional permitted destination.

## Platform telemetry and limits

The deployed diagnostic wrapper adds response metadata/logs and stream-boundary observation. These are included in its CPU cost; its direct-library paths are not performance-equivalent to the production entry. CPU and wall fields were discovered from the current dataset before querying. Correlation used client UUID, response/native platform version, and the diagnostic/native request IDs.

| Case | Platform CPU / wall, ms |
| --- | --- |
| Five fixed answers, chronological | 19/20, 2/3, 2/3, 2/3, unavailable |
| Baseline required default probe failure | 7/13 |
| Minimal socket failure | 2/4 |
| Library default failure | 4/22 |
| Library explicit-verification failure | 2/5 |
| HTTPS DoH control | 40/54 |
| Diagnostic-version production default failure | 17/21 |
| Production explicit-verification failure | unavailable |

There are **10 matched platform rows for 12 payload requests**. Two payload invocations lack CPU/wall observations in the exported window; their missing values and outcomes remain unknown. The query returned 28 events, below its 2,000-event cap. All ten observed platform outcomes were `ok`; that is not successful DNS/ECH processing. Three CPU observations exceeded the [documented Free 10 ms threshold](https://developers.cloudflare.com/workers/platform/limits/). The account remains previously operator-confirmed Free, not independently billing-API verified.

The samples do not establish exact cold/warm isolate identity, tail percentiles, successful-handshake CPU, a controlled optimization percentage, or full Free-plan compliance. In particular, the small explicit-verification diagnostic result is a connection failure before certificate processing, not proof that authenticated handshakes are cheap.

## Budget and final resource state

The authorized cap was 30 client attempts. **17 were used**: two pre-proxy connection failures, two version readiness checks, twelve payload requests and one stop verification. No retries were used to turn a failing probe into a success. The two local connection failures were counted conservatively, then resolved by using the already configured loopback proxy; no credentials were added. Deployment-generated probes and uncorrelated requests are not formal measurement samples.

The existing test Worker was **retained**, not deleted. Its final version `0cc210cb-088c-4a28-a513-4d4465184bab` contains only an inert HTTP 410 handler with `X-Diag-State: stopped`. All outbound and diagnostic code was removed from the active deployment, invocation logging was disabled, and a client request verified the stopped state. Earlier versions remain historical; the original private route is not reproduced here.

[Sanitized evidence](results/2026-10-23/connection-diagnosis.json) contains the attempt ledger, ten correlated CPU/wall rows, missing-sample identities, deployment versions and the test-only/stopped source. Private endpoints, account identifiers, chat credentials and raw platform requests are omitted.

**#25 and #7 remain open.** This run localized the public-source blocker; it did not fix the connection by changing application code, prove a successful public ECH probe or complete the remaining performance/acceptance matrix.
