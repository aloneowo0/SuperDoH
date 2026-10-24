# Repeated public uncached ECH CPU — 2026-10-24

## Result

**All ten uncached public ECH acquisition/application requests succeeded, but all ten platform CPU observations exceeded the documented Workers Free 10 ms threshold.** Later sequential samples remained above the threshold under both policies. This is not merely one high first observation, and it does not establish precise cold/warm isolate identity.

No production source changes were made. The baseline remained `539a750`, using the same explicitly selected `scontent.xx.fbcdn.net:443` and DNS serverName. This is a test source, not a default or automatic fallback. Both the original DNS cache and ECH probe cache were disabled. Required probe/application ran through the unchanged production DoH entry, with a 1,500 ms timeout and 65,536-byte receive limit. Compatibility date was `2026-07-30`, with `enable_request_signal` / `global_fetch_strictly_public` and no `nodejs_compat`.

## Measurements

| Case, chronological | Platform CPU, ms | Platform wall, ms |
| --- | --- | --- |
| Fixed-answer smoke, five requests | 12, 2, 2, 1, 3 | 12, 2, 2, 2, 4 |
| Default, five uncached full probes | **31, 13, 12, 13, 13** | 53, 19, 17, 18, 17 |
| Explicit `verifyCertificate: true`, five uncached full probes | **39, 27, 21, 23, 24** | 45, 33, 27, 28, 29 |

CPU medians in these small samples were 13 ms (default) and 24 ms (authenticated). The later four observations were 12–13 ms and 21–27 ms respectively. No tail percentiles or improvement percentages are inferred. These are platform `$workers.cpuTimeMs` / `$workers.wallTimeMs`, not client latency. Wrapper/logging costs are included; exact parsing, crypto, JIT and GC costs are not attributed.

The telemetry query returned 51 events, below its 2,000-event cap, with **15/15 payload requests matched** by client UUID, version and native request ID shared with the structured diagnostic result. All outcomes were `ok`; this does not imply CPU compliance. Eleven of fifteen payload CPU observations exceeded 10 ms, including the first fixed answer.

## Correctness

All five fixed answers passed. Each of the ten production probes returned RCODE 0 and one HTTPS answer with a structurally valid ECHConfigList: 707 bytes, ten configurations, SHA-256 `81fed4b7374fb1de95cbad6c7ec05823360d7ee10dba867603e983752d0a5595`. Every probe had an `acquired` event and the appropriate verification-policy event; none had a cache-hit event or failure code.

The successful library contract retains CertificateVerify, server Finished and the client Finished write. Explicit authentication additionally verifies hostname and certificate chain using the bundled roots. No authentication bypass, partial-handshake shortcut, static answer substitution or source fallback was used. The public server was not instrumented to independently count client Finished records; the independent local OpenSSL evidence remains separate. Acquiring retry configs does not prove later ECH acceptance using those configs.

## Authorization and final state

The user explicitly authorized at most 20 additional client attempts. This phase used **17/20**: one readiness check, five smoke requests, ten probes and one stop verification. Requests were serialized with at least one second after completion. The shared ledger is **47/50**. Three unused slots were readiness contingencies, not permission for a new scenario. Supported existing OAuth was used; the chat credential was not used or saved. Free-plan status remains previously operator-confirmed, not independently billing-API verified.

The existing test Worker `superdoh-meta-ech-probe-20261018132148` was retained. Measurement version was `86479575-bcd6-4988-bd86-5561a175f29b`; the final inert version is `65cb2ec6-5bb2-4c40-8e8c-8f16a27ff6fd`. The stop request returned HTTP 410 with `X-Diag-State: stopped`; the active handler contains no outbound implementation. No business Worker, DNS record or route was changed.

[Sanitized evidence](results/2026-10-24/meta-uncached-cpu.json) preserves all matched rows, client samples, policy/acquired states, budgets, versions and test-only source. Private test endpoint URLs, account identifiers, credentials, raw request headers and returned ECH key bytes are omitted. Earlier dated evidence remains unchanged.

## Interpretation and next work

**#25 and parent #7 remain open.** Public correctness for this source passes, while full Free CPU acceptance does not. No code optimization was applied, so lower numbers than the [previous run](meta-public-handshake-2026-10-23.md) are not evidence of an optimization. This is not a controlled comparison between days.

Local investigation must separate duplicate certificate work, single-pass X.509 cost and other TLS/crypto costs before selecting a production change. Any candidate must preserve full handshake checks and fail-closed authentication. The remaining full matrix (including public TCP/TLS DNS success, list/rule scale, attribution, cache expiry/isolation and representative measurement coverage) is not completed by these ten probes. Further online scenarios require separate authorization, not reuse of readiness contingency.

### Local duplicate-leaf parsing experiment

An isolated `git archive HEAD` prototype reused the leaf record only within the same authenticated handshake, after certificate/hostname validation and with exact DER comparison before CertificateVerify. Production files were not modified. Existing parse counters confirmed the controlled fixture's subsequent authenticated handshake dropped from three full DER parses to two (first matching-root/backtracking case: five to four). Default verification-off mode still parses its leaf once; skipping intermediate validation there is already implemented and is not a new optimization.

Four 20-handshake batches per variant measured the unique stable Linux workerd process's utime+stime at 100 ticks/second:

| Variant | Default batch CPU averages, ms/handshake | Authenticated batch CPU averages, ms/handshake |
| --- | --- | --- |
| Baseline | 6.5, 6.5 | 11.5, 11.0 |
| Same-handshake leaf reuse prototype | 6.0, 5.5 | 9.5, 9.5 |

The default control improved despite no change to its path; an earlier exploratory prototype's authenticated averages were 11.0/10.5 ms. Consequently, the duplicate work is confirmed, but a stable causal CPU saving is not established. These local whole-process, warmed fixture-CA measurements cannot demonstrate public Meta or Free-plan compliance. One prototype authenticated batch used 190 ms process CPU over 20 handshakes while wall time was 402 ms, illustrating why elapsed time is not CPU.

The baseline Windows trust-store suite passed four tests. The prototype passed four Node/workerd trust-store checks, the independent local public-entry handshake test, and 57 Node plus 57 workerd offline ECH checks. The original final regression command mistakenly named nonexistent `test/run.mjs`; the correct `test/node.mjs` and `test/workerd.mjs` then passed separately. The first experiment's mixed stdout/stderr log lost part of its baseline; the table uses the later intact eight-batch record, not reconstructed values.

[Sanitized local experiment evidence and reproduction scripts](results/2026-10-24/local-leaf-reuse.json) preserve the prototype and counters. The candidate has **not** been promoted to production. Remaining hypotheses are the cost of one complete X.509 parse and other TLS/crypto work; neither has yet been assigned a measured share of public CPU. No further online requests were made.
