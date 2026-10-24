# Public Meta ECH handshake — 2026-10-23

## Result

**The current production DoH entry completed a public ECH retry-config handshake and applied the result to its HTTPS answer, both with default verification disabled and with explicit `verifyCertificate: true`.** The explicit authenticated case used the bundled trust roots, not a custom CA or fallback. This resolves the public successful-handshake evidence gap for this selected source; it does not establish Free-plan CPU compliance or complete #25.

The source was explicitly changed to the existing test Worker's original `scontent.xx.fbcdn.net:443`, with the same DNS `serverName`. This is a test configuration, not an application default or automatic fallback. The earlier [Cloudflare-target rejection](connection-diagnosis-2026-10-23.md) remains a separate historical run; the documented raw TCP restriction should have excluded that destination during preflight.

## Deployment and request boundary

- Source baseline: `539a750`; no production application or library files changed.
- Reused test Worker: `superdoh-meta-ech-probe-20261018132148`.
- Measurement version: `94102e36-b8e5-47cc-93cc-9aad8eaa1a6a`.
- Compatibility date `2026-07-30`, flags `enable_request_signal` and `global_fetch_strictly_public`; no `nodejs_compat`.
- Required `probeEch` followed by `applyEch` through unchanged `handleRequest`. Original DNS cache reads/writes disabled. The ECH probe timeout remained 1,500 ms and the receive limit 65,536 bytes. Only the explicitly named verified-cache mode enabled a 60-second probe cache.
- No response or credentials supplied by the client determine the socket destination. Only the fixed named test routes are accepted.
- Existing supported OAuth was used. The credential supplied in chat was not used or saved. The account remains previously operator-confirmed Free, not independently billing-API verified.

This continuation consumed the **remaining 13 client attempts**, bringing the shared authorized total to **30/30**: one version readiness check, five fixed-answer smoke samples, one minimal socket check, one uncached default probe, one uncached authenticated probe, two authenticated cache samples, one HTTPS DoH control and one final stop verification. Requests were sequential and spaced at least one second after completion. No further online test requests were issued.

## Correctness evidence

All five smoke answers were valid, and the minimal native socket opened successfully. Four production-path probe responses (default, explicit authentication, authenticated cache miss and authenticated cache hit) returned RCODE 0 with an HTTPS answer containing ECH. The client extracted ServiceParam key 5 from wire RDATA and validated its ECHConfigList structure.

All four results contained **707 bytes and 10 configurations**, with identical SHA-256:

```text
81fed4b7374fb1de95cbad6c7ec05823360d7ee10dba867603e983752d0a5595
```

The library's success contract completes CertificateVerify, server Finished and the client Finished write before returning; the explicit `true` path additionally verifies the CA chain and DNS identity. Platform source-state events include `acquired` for the uncached default and authenticated samples, with their respective verification policies. Unlike the independent local OpenSSL harness, this public server was not instrumented to count received client Finished records. This is retry-config acquisition/application, not a claim that a subsequent ECH connection using the returned public key was accepted.

For the two explicitly authenticated cache samples:

1. The first returned a valid ECH answer and logged `verification_enabled` / `miss`. Its `acquired` event and CPU/wall invocation row are missing in the exported window; neither is invented.
2. The second logged `verification_enabled` / `hit` and returned identical ECH bytes. The current implementation returns from the cache-hit path before invoking the library. This is application-side cache evidence, not an independent remote-server connection count.

The standard HTTPS DoH control through `cloudflare-dns.com` also returned a valid answer. It is not counted as an ECH probe.

## Actual platform CPU and wall time

The exported dataset contains **10 matched CPU/wall rows for 11 payload requests**. Correlation checks the client UUID, response/deployment version and the native request ID shared with a structured diagnostic event. The query returned 29 events, below the 2,000-event cap. All ten observed platform outcomes were `ok`; missing outcomes remain unknown. CPU and wall values use the previously discovered `$workers.cpuTimeMs` and `$workers.wallTimeMs` fields, not client elapsed time.

| Case | CPU, ms | Wall, ms | Result |
| --- | ---: | ---: | --- |
| Fixed answer, first observed | 39 | 40 | Valid answer |
| Fixed answer, next four | 5, 4, 4, 8 | 6, 5, 6, 9 | Valid answers |
| Minimal native socket | 2 | 9 | Opened |
| Default-unverified full probe and application | **73** | 92 | Valid ECH answer |
| Explicitly authenticated full probe and application | **138** | 156 | Valid ECH answer |
| Authenticated cache miss | unavailable | unavailable | Valid answer, miss event |
| Authenticated cache hit | 9 | 19 | Valid answer, hit event |
| HTTPS DoH control | 6 | 14 | Valid answer |

Three observed CPU values exceed the documented [Workers Free 10 ms threshold](https://developers.cloudflare.com/workers/platform/limits/). Successful HTTP/DNS processing or platform outcome `ok` does not mean the sample was within that threshold. There is only one uncached full-handshake CPU observation per verification policy, so no percentile, cold/warm-isolate identity or general improvement percentage is inferred. These measurements include the test wrapper's header/logging overhead; they do not attribute exact CPU to cryptography, certificate parsing, JIT or garbage collection. The cache-hit observation does not make uncached/default use Free-compliant.

## Final state and remaining work

The existing test Worker was retained and replaced with an inert HTTP 410 handler, version `5bb98264-87fa-40b5-8780-6b572084e4d2`. The client verified `X-Diag-State: stopped`. Active outbound/probe code was removed and invocation logging disabled. No new Worker, business Worker modification, DNS/route change or ongoing traffic was introduced. Earlier diagnostic versions remain historical, not active.

[Sanitized evidence](results/2026-10-23/meta-public-handshake.json) records the selected source, current-phase samples, observed source states, exact correlated CPU/wall rows, the missing sample, budget, versions and test-only source/client. Endpoint hostnames for the test Worker, account identifiers, chat credentials, raw platform requests and returned ECH key bytes are omitted.

**#25 and parent #7 remain open.** The remaining concerns include the full-handshake CPU cost above the Free threshold and the outstanding full matrix (public TCP/TLS DNS success, list/rule scale, attribution, cache/expiry boundaries and sufficient measurements). CPU optimization needs a measured local feedback loop before changing implementation. Additional online verification needs a new explicit request budget; the existing 30-attempt budget is exhausted. Do not silently shorten TLS authentication/Finished processing, use a paid-plan assumption, treat background work as quota relief, or replace the required public source with static data to report success.

## Local successful-handshake CPU follow-up

A no-network follow-up extended the independent local OpenSSL harness in an isolated Linux archive, without changing the application. Four alternating batches completed 20 successful handshakes each, measured by the unique stable workerd child process utime+stime counter across all Node-thread child lists. At 100 ticks/second, unverified batches used 130/120 ms total (6.5/6.0 ms per-handshake batch averages); explicit verification with the fixture CA used 190/210 ms (9.5/10.5 ms averages). The complete harness passed after correcting two preliminary counter-discovery/template issues; those failed attempts are not CPU measurements.

These are 80 timed local full handshakes, not new public requests. They include process/runtime/GC CPU, already-warmed code and a different certificate/CA/hardware path. They cannot prove Free compliance or establish that the 73/138 ms public observations were cold-start CPU. The public data has only one uncached full-handshake observation per policy; uncached repeated public samples are still needed before treating those numbers as steady-state costs or choosing a production optimization. [Local counter evidence and generator](results/2026-10-23/local-success-cpu.json).
