# Isolated online acceptance — 2026-10-22

## Decision: not accepted as a complete Free-plan release

This was an explicitly authorized, bounded run against **new isolated test resources**, not a deployment of the existing business Worker. Correctness observations passed for the configured lightweight paths, but the complete #25 acceptance **does not pass**:

- **32 of 265 correlated platform measurements exceeded the documented 10 ms Free CPU threshold.** These are observed CPU values, not 32 platform `exceededCpu` terminations. Every correlated platform outcome was `ok`; successful responses and occasional platform burst allowance do not establish a reliable Free CPU guarantee.
- The authenticated active ECH probe failed on its first sample with `ECH_PROBE_FAILED`, after **451 ms CPU / 472 ms platform wall time**. This is the cost of a **failed attempt**, not a measurement of a successful complete handshake. No verification-off retry or replacement source was used.
- Public TCP and native authenticated TLS samples returned SERVFAIL and stopped. Their positive remote interoperability and successful heavy-probe CPU path remain unaccepted.
- Five binary samples have no correlated platform measurement: the initial client-path timeout and four otherwise successful samples. Ten additional keyed/finalization checks intentionally have no platform telemetry because invocation logging was disabled before setting a fresh path Secret.
- The Workers Free plan was **operator-confirmed**. Billing/subscription verification returned HTTP 403 without Billing Read; `standard` usage model alone was not treated as proof of Free. The 10 ms comparison comes from the Cloudflare documentation retrieved on the test date, not an independently verified account billing entitlement.

No issue was changed or closed. No commit was pushed. No account upgrade, Paid Tail Worker, production route/DNS change, or existing business deployment was performed. Optimizations and architecture/target changes below require a separate decision; none were silently applied to make the run pass.

## Authorization, setup and accounting

The approval covered the already connected account, new `superdoh-acceptance-20261022` and same-prefix fixture/metrics names only, `workers.dev` only, controlled fixtures and Cloudflare public DNS/ECH sources, at most 500 client requests, concurrency one and at most one new request per second, retention of the new resources, and no ongoing traffic. Names were checked before creation; only the producer and fixture were created. The metrics/Tail Worker was not created because the proposed Tail mechanism was not available on Free.

The run used supported existing OAuth connections; the separately supplied temporary token was not used or copied into files. A fresh random path Secret was generated only after the producer's observability configuration was disabled. No credential, path key, raw URL-bearing invocation event, certificate dump or raw DNS payload is included in the evidence.

- **335 requests conservatively reserved; 285 sample records actually collected**, including 5 direct fixture diagnostics. The unused 50 reservations comprise requests not sent after case-stop conditions and a 5-request setup reservation that sent no traffic. The ledger was never reset to reclaim unused reservations. Deployment readiness/root probes and source subrequests are not client samples or CPU correlations.
- Producer binary collection: **260 records, 255 matching the configured expectations**. Five mismatches are retained: initial timeout, pre-fix cross-Worker HTTPS failure, TCP failure, TLS failure, and probe failure.
- Separate public/composed/keyed/finalization assertions: **20/20 correct**. Direct fixture diagnostics: **5/5 correct**, not counted as producer CPU observations.
- Public key-free producer samples: **270**, of which **265** have UUID-correlated CPU/wall records. The remaining 10 producer checks were deliberately unmeasured keyed checks. No missing CPU value was synthesized.
- Client records span the initial 04:47 UTC timeout through the last 05:30 UTC finalization run. All workloads have stopped; no schedule or persistent traffic was installed.
- Windows Node v24.14.0, Wrangler 4.151.3, workerd 1.20260730.1, compatibility date 2026-07-30; no `nodejs_compat`. Deployment startup observations were 3–6 ms; these are separate from per-request CPU and do not certify cold-isolate identity.
- The measured production `src/` and generic library source match base commit `1024ddb2865b67a7ed1c3d58c9643c86108fe861`. The deployed configuration changed the public-fetch flag; test-only fixture, collector TTL assertions, runtime-aligned harnesses and this evidence were pending working-tree changes, not a previously clean release commit. See the exact byte hashes and deployment/config hashes in [run provenance](results/2026-10-22/run-provenance.json). Lockfile SHA-256: `e41b85aea97fa69b5341cf0edfc796cb7f43be9df98d5984ffa083ee69ee5772`. Runtime manifest SHA-256: `14720e42833d1eacb63d2d108579401e6c25514e71254bebc97f8925ba7ee4a8`.

Initial direct Node access to `workers.dev` timed out on the first request; there was no matching DoH invocation, so that timeout was not attributed to Worker CPU. Subsequent client processes used the machine's **existing loopback proxy**, without changing system proxy/TLS settings. Client latency includes that proxy route, local setup/load and network latency; it is not a resolver-only latency or CPU measurement.

## Actual measurements

The table is generated from the retained per-run client samples and correlated platform values. All values are milliseconds. Triples are **min / median / max**. `First CPU` means the first client sample in that run, **not a verified cold start**; `Subsequent CPU` excludes that first sample, regardless of its declared phase label. Original `cold-candidate`/`warm` labels remain unchanged in the JSON. A fresh deployment or a `warm` label does not prove isolate identity or cache state. No scenario/phase has 100 samples, so no per-case p95 is reported.

| Scenario | Correct / collected | Measured CPU n | First CPU | Subsequent CPU | Platform wall | Client latency | CPU >10 n |
| --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| `smoke` | 0 / 1 | 0 | — | — | — | 10004.64 / 10004.64 / 10004.64 | 0 |
| `smoke-proxy` | 5 / 5 | 4 | 25 | 2 / 4 / 4 | 2 / 4.5 / 25 | 160.57 / 182.9 / 1114.02 | 1 |
| `fixed-warm` | 30 / 30 | 30 | 23 | 1 / 2 / 5 | 2 / 2.5 / 24 | 185.52 / 208.4 / 1204.56 | 1 |
| `rules-10` | 10 / 10 | 10 | 27 | 2 / 3 / 4 | 2 / 3 / 28 | 189.3 / 218.69 / 1281.37 | 1 |
| `rules-50` | 10 / 10 | 10 | 14 | 1 / 3 / 4 | 2 / 3 / 15 | 190.23 / 210.45 / 1710.17 | 1 |
| `rules-100` | 10 / 10 | 10 | 29 | 3 / 4 / 12 | 4 / 6 / 30 | 196.49 / 241.06 / 1506.98 | 2 |
| `https-hit` | 0 / 1 | 1 | 12 | — | 41 / 41 / 41 | 1162.72 / 1162.72 / 1162.72 | 1 |
| `https-hit-public-fetch` | 30 / 30 | 30 | 28 | 3 / 4 / 6 | 8 / 9 / 124 | 200.94 / 214.86 / 1358.04 | 1 |
| `https-miss` | 30 / 30 | 30 | 18 | 2 / 3 / 5 | 13 / 16 / 88 | 190.12 / 207.84 / 1358.52 | 1 |
| `https-bypass` | 30 / 30 | 30 | 21 | 2 / 4 / 6 | 9 / 11 / 90 | 203.2 / 238.21 / 1355.04 | 1 |
| `https-public` | 5 / 5 | 5 | 29 | 4 / 5 / 6 | 9 / 10 / 57 | 203.01 / 229.91 / 1316.19 | 1 |
| `list-100` | 10 / 10 | 10 | 15 | 1 / 2 / 3 | 2 / 2 / 52 | 186.66 / 202.93 / 1185.98 | 1 |
| `list-1000` | 10 / 10 | 10 | 45 | 2 / 3 / 5 | 2 / 4 / 93 | 212.44 / 226.22 / 1281.97 | 1 |
| `list-4096` | 10 / 10 | 9 | 22 | 1 / 2 / 3 | 2 / 2 / 64 | 182.28 / 194.51 / 1191.19 | 1 |
| `attribution-hit` | 10 / 10 | 9 | 20 | 3 / 3.5 / 8 | 6 / 8 / 74 | 198.41 / 219.73 / 1247.76 | 1 |
| `attribution-miss` | 10 / 10 | 9 | 27 | 4 / 5 / 6 | 10 / 12 / 93 | 214.81 / 233.27 / 1324.97 | 1 |
| `ech-direct` | 10 / 10 | 10 | 26 | 3 / 4 / 5 | 3 / 4.5 / 26 | 183.73 / 208.75 / 1167.18 | 1 |
| `ech-dns` | 10 / 10 | 10 | 25 | 3 / 4 / 5 | 6 / 7.5 / 98 | 182.3 / 205.14 / 1252.82 | 1 |
| `sequential-fallback` | 10 / 10 | 10 | 28 | 3 / 3 / 6 | 12 / 14 / 93 | 193.87 / 222.3 / 1286.97 | 1 |
| `tcp-public` | 0 / 1 | 1 | 13 | — | 27 / 27 / 27 | 1253.56 / 1253.56 / 1253.56 | 1 |
| `tls-public` | 0 / 1 | 1 | 21 | — | 46 / 46 / 46 | 1169.47 / 1169.47 / 1169.47 | 1 |
| `ech-probe` | 0 / 1 | 1 | 451 | — | 472 / 472 / 472 | 1708.37 / 1708.37 / 1708.37 | 1 |
| `refresh-good` | 5 / 5 | 5 | 18 | 18 / 19 / 21 | 22 / 25 / 46 | 264.66 / 294.02 / 1254.26 | 5 |
| `refresh-bad` | 5 / 5 | 5 | 15 | 2 / 3 / 4 | 6 / 8 / 49 | 204.23 / 209.04 / 1294.04 | 1 |
| `refresh-recovered` | 5 / 5 | 5 | 14 | 4 / 4 / 12 | 8 / 10 / 48 | 213.81 / 265.93 / 1274.5 | 2 |

### Separate public and key-protected assertions

| Check | Correct / collected | CPU observations | Platform wall | Client latency |
| --- | ---: | --- | --- | --- |
| `boundary-composed` | 5 / 5 | 8 / 9 / 38 | 24 / 26 / 129 | 240.76 / 461.93 / 1370.78 |
| `boundary-public` | 5 / 5 | 1 / 2 / 20 | 1 / 3 / 20 | 203.24 / 217.28 / 1202.71 |
| `boundary-keyed` | 5 / 5 | — | — | 199.68 / 221.33 / 1211.92 |
| `boundary-finalization` | 5 / 5 | — | — | 193.04 / 220.75 / 1629.83 |

### What these results establish

- **Cross-Worker HTTPS routing:** before `global_fetch_strictly_public`, the producer returned SERVFAIL/`UPSTREAM_FAILED` on its first HTTPS-fixture query, while five direct fixture requests succeeded. After enabling the documented public-fetch flag, 30/30 equivalent producer requests met their expectations. The flag is now in source configuration and production-entry test harnesses; [migration notes](migration.md#public-https-worker-sources) explain public routing/security/loop implications. This source change was not deployed to the existing business Worker.
- **Rule scale:** 10/50/100 nonmatching conditions, grouped in batches of 16, followed by one fixed-answer rule. These are not 100 executed network actions or a maximum-size stress test. The 100-rule run includes a subsequent 12 ms CPU sample, so overages were not confined to first requests.
- **Lists:** exact 100/1,000/4,096-entry bounded fixture lists drove an observable TTL change to 30. For due refresh, the producer was deployed once with a 1,000 ms interval. Only fixture state changed: good → HTTP 503 → recovered list without `example.com`. Five queries at each stage observed TTL 30 → SERVFAIL → TTL 60. The producer version stayed `4a1ef5f5-7007-40eb-824e-91a025b5987d`; no producer redeploy was used to force recovery. All five successful due-refresh samples consumed 18–21 ms CPU. Isolate identity itself was not instrumented, and the 1-second interval is an explicit test setting, not the default 60-second interval.
- **Attribution:** one documentation IPv4 address, explicit nested ASN/country mapping, and a same-address predicate drove TTL 30. Cases configured `cacheTtl:60` and `cacheTtl:0`. This verifies controlled metadata flow, not public ASN accuracy or physical geolocation. Multiple-address/IPv6 isolation and source-fault rollback remain independently covered by local public-entry tests, not claimed as newly measured online cases.
- **ECH and composition:** direct and DNS acquisition returned the expected response envelope. The separate composed check additionally used the independent DNS wire decoder to verify ECH bytes exactly, retained HTTPS port 443, additional A data, TTL 17, clear AD, and retained output after an explicit optional source failure. JSON checks observed the ECH value and TTL through the same pipeline. The combined flow explicitly raises the shared network allowance to 5; it is not a claim that this flow fits the default allowance of 2. The ECH bytes are a structural synthetic fixture, not a working public server key.
- **Sequential fallback:** ten successful final DNS replies retain UUID-associated `UPSTREAM_FAILED` / `rolled_back_continue` platform events for the explicitly failed first source. No automatic fallback or retry was added.
- **Access and finalization:** wire GET, JSON GET, duplicate JSON parameters (400), JSON POST (405), and malformed wire input (400) passed. With observability disabled and a fresh Secret, unkeyed/wrong-key requests returned 404, while authorized wire GET/POST and JSON GET succeeded. A further five keyed requests verified completed/stopped/returned empty pipelines produce SERVFAIL without implicit DNS work, and stop/return after a fixed answer preserve that answer and clear AD. These ten keyed checks have no CPU claim.

### Cache observations are deliberately limited

`https-miss` used 30 distinct names; `https-bypass` explicitly disabled both cache reads and writes; `https-hit-public-fetch` repeated a query with default original-response caching. Attribution likewise configured hit/reuse versus no-cache paths. Those are **configured cases**, not independent proof that every repeated request actually hit a particular cache/isolate. Fixture invocation counting and cache/isolate identity were not instrumented; source/query/Secret cache isolation and TTL aging are strongly checked locally but remain an online verification gap. Low CPU or a repeated query alone was not promoted to proof of a cache hit. Final rule/TTL assertions did run on the returned answers.

### Reachability and authentication limitations

The actual TCP result is `UPSTREAM_FAILED` with SERVFAIL, 13 ms CPU / 27 ms wall. Native TLS returned `UPSTREAM_INVALID` with SERVFAIL, 21 ms CPU / 46 ms wall. The probe returned `ECH_PROBE_FAILED`, 451 ms CPU / 472 ms wall. Their failed first samples are preserved; no additional sample was sent for those scenarios.

Cloudflare documents that outbound raw TCP to Cloudflare IP ranges is blocked. That is a relevant restriction on the authorized Cloudflare-only targets, **not proof of the precise low-level cause of every failure**. The sanitized events do not distinguish every connection, peer-close, certificate or framing cause; in particular, `UPSTREAM_INVALID` is not evidence of successful remote DNS/TLS interoperability. No failing source was substituted, no certificate validation was disabled, and no raw sensitive exception was exported.

The independent local OpenSSL/workerd public-entry handshake test passed again with the updated runtime flags. It exercises default authenticated success, wrong SNI, untrusted roots and separate explicitly configured verification-off behavior. That local result is not substituted for a successful online probe or remote native-TLS identity-error test. Successful heavy-probe CPU remains **unmeasured**, not estimated from the failed attempt or client latency.

## Telemetry and evidence

CPU/wall values came from the actual Workers Logs fields `$workers.cpuTimeMs` and `$workers.wallTimeMs`, in milliseconds, alongside outcome and deployment version. Invocation sampling was configured at 1, traces disabled, and measurement URLs contained no path key or credential header. The client UUID in `X-Acceptance-Sample-Id` was joined to the platform invocation; timestamps/order were not used to invent joins. Platform request IDs associated sanitized action events with those invocations. Deployment/root probes with no client UUID were excluded.

Four successful samples remained absent after a final full-window read; the initial timeout had no DoH invocation. The final query returned 340 events, below the 2,000-event page limit, with 265 UUID-bearing measured invocations. No silent top-N truncation occurred. `head_sampling_rate:1` is a configuration, not a guarantee that every event was available. All 265 observed outcomes were `ok`; no `exceededCpu`, `exceededMemory`, exception or cancellation platform outcome was observed. Application SERVFAIL/action failures are reported separately. Edge/colo context and verified isolate identity were not collected. The retained per-export counts include overlapping windows: 270 exported row occurrences were deduplicated to 265 unique UUID rows (5 identical overlaps removed). Per-export counts and event counts must not be summed as distinct measurements. Conflicting UUID payloads would have aborted the import.

Committed sanitized evidence:

- [Binary client samples](results/2026-10-22/samples.json), including failures and stopped scenarios.
- [Normalized CPU/wall input](results/2026-10-22/telemetry.json) and [offline report](results/2026-10-22/report.json). The report's `completeAcceptance` stays false; cases above 10 ms remain failed even with outcome `ok`.
- [Separate boundary assertions](results/2026-10-22/boundary-checks.json), including intentionally unmeasured keyed checks.
- [Allowlisted platform observations](results/2026-10-22/platform-observations.json), with UUID, CPU, wall, outcome, HTTP status, deployment version, timestamp and sanitized correlated failure codes only.
- [Run/config/deployment provenance](results/2026-10-22/run-provenance.json) and [reproduction inputs](results/2026-10-22/reproduction-inputs.json). Fixture origin is replaced by `https://fixture.example`; these portable binding templates therefore do **not** reproduce the exact original full deployment-config byte hash. The unredacted configuration hashes identify the measured private snapshots. The early 10/50-rule snapshots were reconstructed and checked against their original recorded hashes.

Recompute the offline binary report without credentials or network:

```sh
node scripts/acceptance-report.mjs \
  docs/results/2026-10-22/samples.json \
  docs/results/2026-10-22/telemetry.json \
  > .acceptance/replayed-report.json
```

Compare parsed JSON with the committed `report.json` (formatting may differ). The boundary evidence uses a separate schema because an intentionally correct HTTP 400/404/405 is not a successful binary DNS response.

### Repeating online work requires fresh authorization

Use the [runbook](online-acceptance.md), not this historical approval. For an approved new isolated environment:

1. Run `npm ci`, `npm test` and the independent opt-in ECH test. Verify candidate byte hashes/lockfile and current platform limits; do not assume this date's quota or authorization still applies.
2. Deploy the **test-only** `test/online-fixture-worker.js` separately with a finite numeric `EXPIRES_AT` in epoch milliseconds and `LIST_STATE:good`. It has no outbound requests, only documentation addresses, bounded DNS input, explicit failure/list/geo routes, and fails closed after expiry. Its standalone 9-test public-entry suite is `npm run test:online-fixtures`. Never use it as a real resolver or real attribution provider.
3. Materialize a phase's `vars` and runtime flags from `reproduction-inputs.json` into an ignored configuration with the approved account/name/main path. Replace only the fixture-origin placeholder with the newly approved fixture origin. Baseline smoke/fixed runs use the `baseline-fixed` binding template (A `192.0.2.8`, TTL 60); scale cases contain the stated nonmatching rules plus that answer. `examples/measurement-plan.json` is only a collector manifest, not that Worker configuration. No existing business name or route is a test target.
4. Use that phase's manifest with the bounded runner, after replacing commit/Worker/approval labels with the actual new candidate. Supply `DNS_ACCEPTANCE_URL` securely through the environment, never an argument or printed command. Preserve one shared cumulative reservation ledger across phases; runner limits alone do not enforce a session-wide 500-request cap.
5. For refresh, deploy the producer only for `refresh-good`; switch only fixture `LIST_STATE` to `bad` and `recovered` for the next two manifests, then restore `good`. Do not redeploy the producer between these stages. The measured interval was 1,000 ms.
6. For the composed fixture, use the `boundary-composed` binding template and `HTTPS` query for `example.com`. Check raw HTTPS priority/target, port 443, exact fixture ECH bytes, additional `192.0.2.8`, TTL 17 and clear AD with an independent decoder; repeat through JSON GET. Source fault events must still say `rolled_back_continue`. Keep explicit `maxNetworkRequests:5` visible.
7. Repeat the public and keyed boundary assertions described above. Disable observability/invocation URL logging **before** setting a new Secret through the supported Secret flow. Keep keyed correctness separate and unmeasured unless a separately approved URL-free telemetry method exists. The finalization template uses `no-response.example`, `stop-empty.example`, `return-empty.example` (SERVFAIL), and `stop-answer.example`, `return-answer.example` (one fixed A answer).
8. Collect only allowlisted real platform values, verify units/version/UUID correlation, page when needed, and retain missing/failing outcomes. Do not reuse the original endpoint, key, temporary token or expired fixture.

## Regression and independent review

The final `npm test` exited 0: typechecking, **237 application/tool tests across 15 suites**, **130 generic DNS tests**, and **104 ECH offline tests**, with zero failures/skips in the application/tool suites. The public-entry independent OpenSSL ECH test passed separately in WSL after runtime-flag alignment (1 integration test). Production `wrangler deploy --dry-run` exited 0: 2,000.24 KiB / gzip 477.28 KiB, without deploying the business Worker. These results do not certify Free CPU or remote reachability.

Independent Sonnet Standards review identified local/deployed runtime-flag mismatch and ambiguity in overlapping export-page counts. Harnesses were aligned and the metadata now explicitly distinguishes 270 exported occurrences from 265 unique UUID measurements. Final Spec review found no concrete defect, independently replayed the report, reconciled the CPU totals and verified all 38 runtime-file hashes plus the lockfile hash. Neither review overrides the measured failures or missing acceptance scope.

## Retained resources

Only the two authorized test Workers remain; there is no metrics/Tail Worker and no continuous traffic. The producer retains a fresh path Secret and disabled observability configuration, Logpush false, zero Tail consumers; its retained version is `e0419922-512a-445e-80a6-c129dcc02772`. The final correctness configuration is the keyed finalization template, not a production resolver policy. The key is not printed or committed; an account owner who wants to query the retained endpoint must set their own new Secret through the supported flow.

The fixture's last version is `dd8a3a60-57ed-44e1-91e7-e02d9dcec3fb`, state `good`, with expiry **2026-10-22T06:02:48.329Z**. After that time it returns 503 without being deleted. Retention is not permission for ongoing use or additional traffic, and no cleanup deletion was performed.

## Proposed next decisions — not silently implemented

1. **Profile and optimize bounded pure setup/validation**, particularly first-request configuration/codec/trust-anchor work. The failed probe's 451 ms does not localize its CPU cost, so profile before choosing a fix. Consider validated immutable compiled configuration or indexed trust material where correctness, Secret/config invalidation, resource ceilings and certificate authentication remain intact. Do not introduce global request I/O or claim amortization eliminates cold-path cost.
2. **Treat due refresh as real work.** The explicit 1-second refresh repeatedly used 18–21 ms CPU. Evaluate a different authorized refresh interval/data size or decomposition; never turn a failed refresh into silent stale-data success or change the user's configured freshness policy to pass.
3. **Complete remote positive interoperability** only against separately authorized, suitable reachable TCP/TLS/ECH targets. The current Cloudflare-only destination scope and sanitized failures do not establish remote certificate-identity/error coverage. Do not choose another provider or verification-off mode automatically.
4. **Decide the heavy-probe execution model.** An approved separate service/plan or bounded pre-acquired authenticated configuration might be appropriate, but changes trade freshness, deployment and cost. Background/Cron does not waive Free CPU limits. No such change or account upgrade was made here.
5. **Strengthen online evidence** with an approved privacy-safe source-access counter and isolate/cache identity, stable complete CPU correlation, broader negative/address/DNSSEC cases, and a fresh full matrix after any optimization. Keep the existing local independent protocol/cache/rollback/DNSSEC checks; do not relabel them as new online observations.

Until those choices and missing positive cases are addressed, the honest result is **useful bounded correctness and timing evidence, with failed CPU observations and blocked full acceptance**, not a complete Free-plan release.

## Sources checked on 2026-10-22

- [Workers CPU limits and burst flexibility](https://developers.cloudflare.com/workers/platform/limits/#cpu-time)
- [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Public fetch routing flag](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public)
- [Worker routing errors, including 1042](https://developers.cloudflare.com/workers/observability/errors/)
- [Outbound TCP restrictions](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)
- [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
- [Workers Observability API](https://developers.cloudflare.com/api/resources/workers/subresources/observability/)
