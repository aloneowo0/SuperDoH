# Current-source cache isolation — 2026-10-26

## Result and scope

**14/14 assertions passed**: twelve payload requests plus two cleanup checks, under a fresh 24-request cap. Requests were serial, at least 1,006 ms after the previous completion. All twelve payloads reported colo **FRA**. There was no CPU matrix, profile, ECH handshake, business change or production algorithm change.

This verifies the production bundle from **65ef25f**, SHA-256 `209ab06c48b59319efee096bcba1482f7dedea800b4c22ecf4484b6dfe124b56`, identical to the [previous current-source smoke](current-source-smoke-2026-10-26.md). A separate temporary wrapper provided fixed configurations to the actual public `handleRequest` entry, collected sanitized failure codes and echoed source/version/sample/colo. The original-response cache was the real Worker Cache API, not a substitute. Both upstream identities were run-specific URLs on the existing controlled fixture; no public third-party DNS source was queried.

[Full evidence](results/2026-10-26/cache-isolation.json) contains every attempt, version IDs, source hashes, settings, executed client revisions and restoration checks.

## Observed coverage

| Check | Observed behavior |
| --- | --- |
| Prime A while fixture enabled | Correct A `192.0.2.8`; response rule sets TTL 7. Original fixture answer TTL is 60. |
| Configure fixture HTTP 503, change ID and TTL rule | Cached answer succeeds after 29,304 ms since prime completion, restores ID `0x4343`, and applies the current TTL 9 rule. This is later than the first final-answer TTL 7; no new origin answer is available. |
| Change source name, same resolved URL | SERVFAIL / `UPSTREAM_FAILED`, not the other source name's cached answer. |
| Change URL, same source name | SERVFAIL / `UPSTREAM_FAILED`, not A's cached answer. |
| Resolve actual Secret binding to the same URL A | Cached response succeeds, confirming resolved-target identity rather than a separate cache solely for literal versus Secret syntax. |
| Explicit read/write bypass | SERVFAIL / `UPSTREAM_FAILED` while fixture DNS serving is disabled (HTTP 503) despite the primed cache. |
| Change query name or CD flag | Both return expected source failure, not an incompatible cached answer. |
| Add unused TLS definition after priming | `INVALID_CONFIG` / empty SERVFAIL. Primed cache cannot bypass whole-configuration validation. |
| Actual Secret B-to-A rotation | Prime B through the actual Secret binding, configure fixture HTTP 503, then rotate the binding back to A. A returns source failure; a literal B positive control still hits the B entry after 32,581 ms. Changing the resolved Secret target did not reuse B's cached answer. |

These conclusions are bounded observations, not a complete cache-security matrix. Socket counts and origin invocation totals were not instrumented; the non-serving state is established by active expired fixture settings (the expiry guard returns HTTP 503) and expected source failures, with cache-hit positive controls in the same colo.

## Avoiding an expiry false positive

The initial A entry expired before the first Secret update finished. No request was sent for the original planned forward-rotation comparison: an expired A entry would not prove isolation. Instead, B was freshly primed and the reverse B-to-A comparison included a still-valid B hit in the same candidate version/colo. No extra request was consumed by this adjustment. The first client revision executed `prime` and `blocked`; the revised client executed `seedB`, `rotatedBack` and `cleanup`. Both exact client sources are archived, and unused branches are identified.

The Secret value was a **public, uncredentialed fixture URL**, not a private credential. This tests actual Secret-binding reference and rotation semantics; it is not a new private-credential leakage/redaction test. Previous path-key checks remain separate evidence.

## Restoration and verification

Temporary `ACCEPTANCE_SOURCE_URL` was explicitly deleted while collection was still disabled, before restoring observability. Independent control-plane reads and binary-safe downloads verified original producer JS/WASM hashes, empty active/latest producer bindings, original observation settings and removal of the wrapper. Producer final version is `93fb5bf5-15b2-490f-b2f2-11e68ca76f65`; fixture original version `c489c361-819f-485d-ba7f-6168ede2f3ce`, original ETag and `EXPIRES_AT=0` were restored. Public cleanup returned empty producer SERVFAIL and fixture HTTP 503. No background traffic remains.

The two run-specific cached entries had at most 60-second lifetimes; they were not globally purged, and both lifetimes had elapsed before final public cleanup. The isolated producer was restored to original modules, not left serving the candidate.

Static typechecking passed. Under the cloud-only instruction, no local Worker behavior/full npm/Rust suite was run. No new native CPU values were collected. Cross-transport isolation, ECS/DO variants, negative caching, signed DNSSEC rewrite combinations and cross-colo persistence remain outside this small check. Existing [practical Free CPU policy](practical-free-closeout-2026-10-26.md) and historical ECH costs remain unchanged. **#25/#7 remain open; this is not full online acceptance.**
