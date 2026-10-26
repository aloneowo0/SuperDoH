# Current-source cloud smoke — 2026-10-26

## Delivery and source identity

Named DNS upstreams now support **HTTPS and ordinary TCP only**. Every `transport: "tls"` definition fails whole-configuration preflight with `INVALID_CONFIG`, including unused definitions, optional actions and unreachable references. There is no downgrade or fallback. The independent ECH TLS probe is unchanged. See [ADR 0001](adr/0001-exclude-dot-from-current-scope.md).

Unlike the earlier diagnostics against historical deployed source, this smoke ran the exact current production bundle:

- Current JS: **1,208,784 bytes**, SHA-256 `209ab06c48b59319efee096bcba1482f7dedea800b4c22ecf4484b6dfe124b56`.
- Baseline JS: 1,209,790 bytes, SHA-256 `3b32bd2b2bbee8242da529f0b8f504c7ac84911d34b71a85a6c6c340a52be007`.
- Unchanged WASM: SHA-256 `b19b09a573512b21f50c943c72ec6553078328623f442a511ddf33cd0b1f3a73`.
- Candidate cloud version: `8a0129bd-3741-452b-8af5-523fb6c6cd1e`.
- Baseline version: `2e470072-a23f-4e12-a830-487815cf2f19`.

Independent esbuild output reproduced the original online module byte-for-byte. Six deterministic replacements produced the candidate; its entire JS hash matched the independent current-source build before upload. A separate wrapper selected fixed trusted configurations, bypassed original-response caching, collected sanitized failure codes through the existing observer seam, and echoed source hash/version/sample ID. The production module itself was unchanged by the wrapper. This is a correctness smoke, not a performance baseline.

[Machine-readable evidence](results/2026-10-26/current-source-smoke.json) includes per-request outcomes, source-file hashes, deployment/binding snapshots, build recipe, exact patches and executed client sources. Reproduction requires fresh authorization; archived paths are relative to the original ignored diagnostic directory.

## Bounded results

**17/20 client attempts**, serial with at least one second after completion, zero profiles, zero CPU-matrix requests, zero ECH probes. Control operations used Cloudflare MCP. Only the existing isolated producer was modified; the existing fixture was inspected but not modified. No business Worker, DNS, route, billing, key or Secret change occurred.

| Observation | Result |
| --- | --- |
| Regression sensitivity | An unused TLS definition returned the fixed NOERROR answer on the baseline; the same case returned SERVFAIL with `INVALID_CONFIG` on the candidate. The new rejection contract therefore fails on the old source. This is not a claim of test-first implementation chronology. |
| Fixed wire POST/GET and JSON GET | All three passed; answer `192.0.2.8`, TTL 60, AD cleared, no-store. |
| Explicit HTTPS source | Passed via the selected Quad9 HTTPS endpoint; associated A response. |
| Initial TCP source | **Failed**, HTTP 200 with observer code `UPSTREAM_INVALID`; its body was not decoded after the early assertion failed. |
| TLS unused/optional/unreachable/mixed definitions and TCP identity field | All five rejected with `INVALID_CONFIG`, empty SERVFAIL answers and preserved question/ID association. No live DoT request was deliberately sent; socket counts were not independently instrumented in this smoke. |
| No response / duplicate JSON name | Expected `NO_RESPONSE` SERVFAIL and HTTP 400 `DUPLICATE_PARAMETER`. |
| Minimal TCP follow-up | Baseline returned RCODE 0/two answers, refuting the harness expectation that the failure would repeat. One candidate confirmation then passed with associated A records. **The initial failure remains; its cause is not established.** |

The initial candidate pass was **11/12**, not all-green. The first TCP failure was not discarded or rewritten after confirmation. These two current TCP observations do not establish transport reliability or prove network causation; no production workaround or hidden retry was introduced.

## Harness exceptions and restoration

Two additional assertions used wrong expectations and remain in the raw ledger: the baseline TCP control expected `UPSTREAM_INVALID` but received a successful answer, and fixture cleanup expected HTTP 410 but observed HTTP 503. Inspection of the unchanged fixture source confirmed that `EXPIRES_AT=0` returns **503 before route handling**. Its active version was unchanged; no extra request was made to replace this record. Some failing Node assertions also emitted a Windows `UV_HANDLE_CLOSING` abort after their HTTP records had been saved.

An initial reverse-patch anchor guard stopped before a restoration upload because of string escaping. Exact base64-encoded original fragments then reproduced the original JS hash before upload. Independent downloads verified the original JS/WASM hashes, removal of the smoke wrapper, empty active/latest producer bindings, and restored observability. Producer public cleanup returned empty SERVFAIL with no smoke headers. Fixture bindings remained `EXPIRES_AT=0`, `LIST_STATE=good`; its original version remained `c489c361-819f-485d-ba7f-6168ede2f3ce`. Final producer version: `ee6b1ee5-b031-4eb2-8f1f-5e8bdaa54dbe`.

**The isolated producer was restored to its original modules, not left serving this candidate.** No background traffic or recurring job remains.

## Verification boundary

Static `npm run typecheck` and four changed-JavaScript syntax checks passed. No local behavioral suite, full npm suite, Rust suite, new native CPU campaign, ECH handshake or key test was run in this round. Earlier full-suite counts remain historical; checked-in socket-count/cache-bypass regression definitions were not newly executed locally.

The [practical Free policy](practical-free-closeout-2026-10-26.md) accepts occasional successful CPU overages without treating real execution failures as success. It remains applicable, but this smoke supplies no new native CPU values and does not turn historical measurements into candidate-version metrics. Existing key checks and CPU evidence are reused with their recorded boundaries. **#25/#7 remain open; full online acceptance is not declared.**
