# Acceptance matrix and verification status

This matrix maps the current implementation surface to its local verification commands. A listed command is a reproducible check, not a claim that it was run for a particular release. Run in the repository root with Node.js 22+ and the locked dependencies. Workerd tests use the configured compatibility date and do not enable `nodejs_compat`.

## Local matrix

| Acceptance area | Command / suite | Observable scope |
| --- | --- | --- |
| JSON rule validation, stable order, conditions, state and failures | `npm run test:rules` (`test/rules.mjs`) | Public execution results, sorted groups, full preflight, resource limits, conditions, errors and rollback. |
| Standard DoH GET/POST, path authorization, upstream and DNS response semantics | `npm run test:doh` (`test/doh.mjs`) | Production `src/worker.js` HTTP entry, DNS wire output, no implicit requests, source failure, RCODE and DNSSEC cleanup. |
| Supported upstream transports and TLS rejection | `npm run test:doh`; `npm run test:tcp` (`test/tcp.mjs`); `npm run test:tls` (`test/tls.mjs`) | HTTPS and ordinary TCP behavior through the public workerd DoH entry; `transport: "tls"` rejected during full preflight, including unused definitions, with zero socket creation. `test:tls` is a rejection regression, not a DoT success suite. |
| Original upstream cache | `npm run test:cache` (`test/cache.mjs`) | Identity isolation, TTL/HTTP freshness, cache hits that still run rules, bypass and failure behavior. |
| Record changes and metadata separation | `npm run test:records` (`test/records.mjs`); `npm run test:metadata` (`test/metadata.mjs`) | DNSSEC/EDNS effects, rollback and controlled platform client/edge attributes. |
| Response-address attribution | `npm run test:attribution` (`test/attribution.mjs`) | Explicit lookup through the public DoH entry, same-address conditions, validated mapping, shared budgets, cache and rollback. |
| Maintained domain lists | `npm run test:lists` (`test/domain-lists.mjs`) | Inline/external text/JSON, complete replacement, due refresh, failure invalidation, recovery and bounded isolate state. Test time is controlled by the test harness, not a production clock hook. |
| ECH direct/HTTPS lookup/application and probe behavior | `npm run test:ech` (`test/ech.mjs`); `npm run test:ech-probe` (`test/ech-probe.mjs`) | ECH actions through the Worker boundary with controlled sources, validation, failure/rollback and resource behavior. |
| DNS/ECH library regression | `npm run test:libraries` | DNS WASM smoke and generic operations plus ECH Node/workerd offline suites. |
| Checked-in examples and composed source/cache/ECH flow | `npm run test:acceptance` (`test/acceptance.mjs`) | Executes checked-in JSON configurations and combines maintained lists, attribution, original caching, ECH and JSON; unsupported probe sources fail closed. Independent successful probe interop passed separately as recorded below. |
| Measurement collection and offline report tooling | `npm run test:measurement` | Bounded binary DoH collection through the production HTTP entry, safe errors and pacing, schema validation and separate CPU/wall/client summaries. Synthetic test telemetry is not an online result. |
| Types and combined default regression | `npm run typecheck`; `npm test` | TypeScript checks and the standard script sequence in `package.json`. |
| Opt-in JSON query adapter | `npm run test:json` (`test/json.mjs`) | `DNS_JSON` gating, `name`/`type`/`cd`, authentication, JSON errors and same-pipeline behavior. The script is part of the default npm test sequence. |

The public JSON adapter is enabled only by `DNS_JSON=true` (or the exact string `"true"`) and accepts one GET at the standard `/dns-query` path with `name`, optional `type`, and optional `cd`. It calls the DNS library's `toDnsJson`; this is not a promise of compatibility with a particular public provider's extra JSON fields. A valid DNS failure is represented by the DNS status; malformed HTTP/query parameters use the HTTP JSON error object. Wire-format and JSON entry paths share execution, authorization and response cleanup.

## Recorded local verification (2026-10-21)

The final integrated `npm test` run exited with code 0: typechecking, 211 application tests, 130 DNS library tests and 104 ECH library offline tests passed, with no application tests skipped. The independent ECH/OpenSSL test is opt-in and was **not** included in these passing totals.

Wrangler 4.151.3 local `deploy --dry-run` also succeeded (2,000.24 KiB bundle, 477.28 KiB gzip); no upload or deployment occurred. Binding types were regenerated with `wrangler types --include-runtime=false`. Independent Standards and Spec reviews found no remaining concrete defects in the local #24 deliverable; full acceptance remains partial for the blockers below.

## Independent ECH handshake

`test/ech-interop.mjs` and `npm run test:ech-interop` are opt-in. The test generates an ECH key with OpenSSL, starts a local TLS/ECH server using `s_server -ech_key`, and sends requests through the public workerd DoH entry. It uses the library's local test certificate fixture. It is an independent **local** handshake, not proof of interoperability with a public resolver or remote production endpoint.

Run only with an existing ECH-capable OpenSSL build:

```sh
ECH_PROBE_OPENSSL=/path/to/ech-capable/openssl \
LD_LIBRARY_PATH=/path/to/that/build \
npm run test:ech-interop
```

### Recorded independent verification (2026-10-22)

After the harness fixes, the full default regression was rerun on Windows on 2026-10-22 and exited with code 0: typechecking, 211 application tests, 130 DNS library tests and 104 ECH offline tests passed. The independent checks below ran separately in WSL, not inside that default total.

The Windows system OpenSSL lacks ECH support and the historical build path is absent. An isolated WSL build of official [OpenSSL source](https://github.com/openssl/openssl) at commit aff3d3cf25501f311f1e6a2946f4b6edc2b37d8c reports OpenSSL 4.2.0-dev and passed:

- Public production DoH entry: one integration test covering default authenticated acquisition/application, reuse without another complete handshake, wrong SNI, untrusted default roots, and separately explicit verification-off behavior.
- Generic ECH library: four OpenSSL/workerd cases passed; the independent server received three client Finished records, including the Node TLS baseline and both successful workerd clients. No nodejs_compat was enabled.

The wrong-SNI case uses wrong.invalid, outside the fixture certificate's wildcard SAN. The harness waits for OpenSSL's ACCEPT listener signal, retains the complete Miniflare runtime options on reconfiguration, and serializes JSON bindings to omit undefined fields. Failure diagnostics survive temporary-directory cleanup without dumping TLS hex records.

Reproduce inside Linux/WSL with Node.js 22+, GCC, Make, Perl and Git. Use fresh temporary directories; no system installation or account credentials are required:

```sh
git clone https://github.com/openssl/openssl.git /tmp/superdoh-openssl-ech
cd /tmp/superdoh-openssl-ech
git checkout --detach aff3d3cf25501f311f1e6a2946f4b6edc2b37d8c
./Configure no-shared no-tests enable-ech
make -j4

# In a separate Linux checkout of this repository, with locked dependencies:
npm ci
ECH_PROBE_OPENSSL=/tmp/superdoh-openssl-ech/apps/openssl npm run test:ech-interop
ECH_PROBE_OPENSSL=/tmp/superdoh-openssl-ech/apps/openssl node lib/ech-probe/test/interop.mjs
```

The executed build used /tmp/superdoh-openssl-ech-20261022 and an isolated repository copy at /tmp/superdoh-ech-acceptance-20261022; these are disposable local prerequisites, not committed dependencies or a deployment. The development OpenSSL revision is pinned for reproducibility, not recommended as a production dependency. This proves local protocol interoperability only, not public-source reachability or Free-plan CPU compliance.

## Outstanding acceptance

- **#22 local ECH interoperability:** passed in the isolated WSL environment above; keep this opt-in prerequisite separate from the default offline regression and rerun it for release candidates.
- **#25 online free-plan acceptance:** an isolated, explicitly authorized run was executed on 2026-10-22. Real platform CPU/wall samples include CPU above the documented Free threshold; public TCP/TLS/probe positive paths did not pass, and some telemetry is missing. The plan was operator-confirmed, not independently billing-API-verified. Overall acceptance remains **not passed**; see [actual results](online-results-2026-10-22.md).
- **Platform/resource caveats:** upstream reachability, Secrets/variable limits and Worker resource availability depend on the deployed account and environment. Application `DNS_LIMITS` values are resource bounds, not free-plan CPU guarantees.

The `.example` and `.test` names in `examples/*.json` are illustrative inputs for controlled harnesses, not live services. Replace them with sources you operate before deployment; these examples do not establish public reachability or online data accuracy.

## Build validation

`npx wrangler deploy --dry-run` validates the browser-target production bundle locally without upload; this is not a deployment or free-plan CPU test. `wrangler types --include-runtime=false` regenerates the checked-in binding declarations. The production configuration uses `keep_vars: true` so ordinary Dashboard-managed runtime variables survive code deployment; Workers Builds build-only variables remain separate, and ordinary deployments do not delete Secrets. See [configuration preservation](https://developers.cloudflare.com/workers/wrangler/configuration/) and [build/runtime variables](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/).

The bounded, authorization-gated procedure for remaining online work is in [online-acceptance.md](online-acceptance.md). It is not permission to deploy or repeat traffic. The separate [dated result](online-results-2026-10-22.md) records what was actually executed and what remains blocked.

## Measurement-tool regression (2026-10-22)

After adding the gated runner and offline reporter, the final `npm test` run exited with code 0: typechecking, 227 application/tool tests (including 16 measurement tests), 130 DNS library tests and 104 ECH offline tests passed. No tests in the application/tool suites were skipped. Standards review found no concrete violations; the Spec review's unknown-telemetry classification finding was fixed and independently rechecked. These are local regression results, not an executed #25 online performance acceptance.

## Authorized online-run regression (2026-10-22)

After adding bounded test-only online fixtures, the exact TTL expectation and public-fetch runtime alignment, `npm test` exited 0: typechecking, **237 application/tool tests**, **130 DNS library tests** and **104 ECH offline tests** passed. All 15 application/tool suites reported zero failures and zero skips. The updated production-entry OpenSSL/workerd interoperability test passed separately in WSL (1 integration test); no certificate-authentication downgrade was used for the authenticated path. Production `wrangler deploy --dry-run` exited 0 (2,000.24 KiB, gzip 477.28 KiB), without deployment of the business Worker. These checks do not override the failed/incomplete online CPU and reachability acceptance.

## Local profiling follow-up (2026-10-22)

The opt-in `node test/profile-local.mjs` diagnostic captures real local workerd sampled stacks through the production HTTP entry, with loopback TLS alerts and controlled list data. It performs no online requests and is separate from `npm test`. The [dated diagnostic](local-profile-2026-10-22.md) records 20 local profiles including explicit one-second wait controls. The earlier elapsed-stack weights were found to include I/O suspension and must not be interpreted as function CPU; corrected output reports stack counts and gap diagnostics only. The independently recorded platform CPU values and online acceptance decision are unchanged.

## CPU optimization and explicit default-policy revision (2026-10-23)

See [the dated follow-up](cpu-optimization-2026-10-23.md) for single-parse trust preparation, Windows process-CPU controls, and the user-requested default `verifyCertificate: false`. Explicit `true` preserves authentication. These changes do not revise historical online measurements or establish Free-plan acceptance; the independent OpenSSL rerun for 539a750 passed on 2026-10-23 as recorded below (the original optimization measurement did not include that rerun).

## Bounded cloud retest and cleanup (2026-10-23)

The [current-build cloud retest](cloud-retest-2026-10-23.md) records version-pinned platform measurements for the optional verification policy. Default-unverified failed probes used less CPU in the observed cases, but all active probes still failed; complete Free acceptance remains not passed. Both old test Workers and the new temporary Worker were deleted and confirmed absent. No business Worker or DNS/route change was made.

## Current-build task closeout (2026-10-23)

The source baseline was `539a750`. The current Windows `npm test` completed with exit code 0: typechecking, **238 application/tool tests**, **130 DNS library tests**, **114 ECH offline tests**, and **4 trust-store tests** passed (486 total; zero failures, cancellations or skips). Wrangler 4.151.3 `deploy --dry-run` passed with a 2,010.59 KiB bundle, gzip 475.15 KiB; no upload or deployment occurred. These are fresh runs, not the historical totals above.

The independent ECH-capable OpenSSL checks were then rerun in WSL using an isolated `git archive` of `539a750`, Linux Node.js 24.22.0 and the existing OpenSSL 4.2.0-dev build pinned to `aff3d3cf25501f311f1e6a2946f4b6edc2b37d8c`. Linux dependencies were reused only after byte-for-byte comparison of the locked dependency manifests; no historical application checkout was substituted for the current source.

- `npm run test:ech-interop`: **1 integration test passed**, zero failures/skips, covering explicit authenticated acquisition/application, cache reuse without another complete handshake, wrong SNI, untrusted roots, and an explicit verification-off complete handshake through the public production DoH entry.
- `node lib/ech-probe/test/interop.mjs`: **4 cases passed**; the independent server received **3 client Finished records**, including the Node baseline and both successful workerd clients. No `nodejs_compat` was enabled.
- The independent checks explicitly select true/false. The omitted-option default-false complete handshake is covered by the default offline regression; it is not mislabeled as an additional OpenSSL case.
- Initial launch attempts hit cross-shell expansion and Windows npm selection; fixing the Linux invocation environment resolved these before the successful runs. No application or test code was changed to obtain a pass.

The existing local interop reproduction commands above remain applicable. [Sanitized closeout evidence](results/2026-10-23/task-closeout.json) records versions, lockfile identity, counts and exact scope.

Delivery checks for #18–#24 and #26 are complete at this baseline. The #7/#22 task contracts were synchronized with the already recorded default verification-off policy while preserving the previous authenticated-default history. This is acceptance-item reconciliation plus regression and independent interop, not a claim of a new independent Standards/Spec dual-axis review. The isolated OpenSSL source is not a public production source. **#25 and parent #7 remain open; full online Free-plan acceptance is not passed.** No business Worker, route or DNS record was changed, and no online traffic or new cloud resources were created. Historical cloud measurements still target `e5954e9`, not `539a750`.

## Public-source connection diagnosis (2026-10-23)

A separately authorized bounded run updated the existing test Worker after the local closeout above. The current source baseline `539a750` reproduced production SERVFAIL and isolated the `cloudflare-ech.com:443` failure before socket `opened`, with zero TLS bytes sent/received and the documented disallowed-destination signature. HTTPS DoH remained reachable. The run used 17/30 client attempts; 10 of 12 payload samples have matched platform CPU/wall rows, with three values above 10 ms. No successful public ECH handshake or complete Free acceptance is claimed. The existing test Worker was retained with an inert 410 deployment and invocation logging disabled. See [diagnosis, exact scope and missing telemetry](connection-diagnosis-2026-10-23.md). #25 and #7 remain open.

## Public authenticated ECH success and CPU boundary (2026-10-23)

A continuation used the original test source `scontent.xx.fbcdn.net` explicitly, not as a default/fallback. On source baseline `539a750`, the unchanged production DoH entry successfully acquired and applied 707-byte / 10-entry ECHConfigLists under both default-unverified and explicit authenticated policies. The authenticated cache mode produced a valid miss response then an observed hit with identical ECH bytes. Actual platform CPU/wall were 73/92 ms for the default full probe, 138/156 ms for the authenticated full probe, and 9/19 ms for the authenticated cache hit. The cache-miss CPU/wall row is missing; do not infer a value. These are 10 matched telemetry rows for 11 payloads, not a complete performance distribution. The continuation used the remaining 13 client attempts, reaching 30/30 total; the existing test Worker was again replaced with an inert 410 handler and invocation logging disabled. The public successful-handshake evidence gap for this source is resolved, but the observed uncached CPU costs exceed the documented Free threshold and the full matrix remains incomplete. See [current results and boundaries](meta-public-handshake-2026-10-23.md) and [sanitized evidence](results/2026-10-23/meta-public-handshake.json). #25 and #7 remain open.

## Repeated uncached public CPU (2026-10-24)

On unchanged baseline `539a750`, five default and five explicitly authenticated uncached Meta probes all returned valid ECH answers. Platform telemetry is complete for all 15 payloads (five fixed smoke plus ten probes). Default CPU was **31, 13, 12, 13, 13 ms**; explicit authentication was **39, 27, 21, 23, 24 ms**. All ten probe observations exceed 10 ms, including later sequential samples; precise cold/warm isolate identity is not established. No production optimization was applied. The new authorization used 17/20 attempts, bringing the shared ledger to 47/50; the unused three were readiness contingencies. The existing Worker is retained with an inert HTTP 410 handler, version `65cb2ec6-5bb2-4c40-8e8c-8f16a27ff6fd`, verified stopped. **#25/#7 remain open and full Free acceptance is not passed.** See [the dated report](meta-uncached-cpu-2026-10-24.md) and [complete sanitized rows](results/2026-10-24/meta-uncached-cpu.json).

## Runtime upgrade and profiling tools (2026-10-24)

Wrangler is now pinned to **4.152.0**; deployment and current application tests use compatibility date **2026-10-19**. Wrangler, the application test harness and standalone ECH library tests execute **workerd 1.20261019.1**. Node compatibility remains explicitly disabled by `no_nodejs_compat` / `no_nodejs_compat_v2`, and source maps are explicitly enabled for future readable production profiles. Miniflare 4's existing fixture API is retained with a locked new-workerd override because the v5 converter cannot preserve the custom outbound network/CA fixture. No production DNS/TLS logic changed.

- The final full `npm test` in an isolated WSL working copy, using a fresh `npm ci` from the current lockfile, exited **0**: typecheck, **240 application/tool tests**, **130 DNS library tests**, **114 ECH offline tests** and **4 trust-store tests** (488 total), zero failures/skips. This is not described as a final full Windows run: the earlier Windows full run caught a missing-IP fixture mismatch; its eight metadata tests passed after the explicit fixture correction. The newer ingress supplies a loopback identity when the header is omitted, so the local wrapper now explicitly removes it for that negative case without changing production handling.
- Independent local OpenSSL: **1 production-entry integration test** and **4 library cases** passed; the independent server recorded **3 client Finished records**. These ran with the new engine and explicit Node opt-outs. Standalone library testing also passed 57 Node + 57 workerd offline checks on Windows.
- `wrangler types --include-runtime=false` completed; the generated project binding type content remained unchanged. `wrangler deploy --dry-run` passed: **2,010.59 KiB / gzip 475.15 KiB**, no upload.
- `wrangler check startup` successfully generated a local CPU profile (sampled startup activity, not ECH request CPU). The request-path local diagnostic also generated **20 profiles**, with zero online requests. Raw profiles remain in ignored `.acceptance/` local state.
- `npm audit` still reports **4 development-tool entries: 3 high, 1 moderate**; this upgrade is not an audit remediation or clean-audit claim. No force fix/downgrade was applied.

Cloudflare now documents deployed CPU/heap profile capture through Dashboard, `cf`, and API; it does not specify a minimum compatibility date for that feature. The existing test Worker was not reactivated and no cloud profile or new public acceptance traffic was requested. Upgrading the toolchain/date and successfully generating local profiles does **not** establish Free-plan CPU acceptance; #25/#7 remain open. See [runtime pins and profiling procedures](runtime-profiling-2026-10-24.md) and [sanitized verification evidence](results/2026-10-24/runtime-upgrade.json). No commit/push was made.

## Successful ECH library CPU localization (2026-10-24)

A library-only local OpenSSL run on workerd 1.20261019.1 completed **870 successful diagnostic handshakes**, with **873 independent client Finished observations** including baseline/interop. Unprofiled batches (160 handshakes/policy) averaged 2.5625 ms process CPU for default off, 4.5625 ms for explicit true/custom fixture CA, and 4.1875 ms for explicit true/test-only fixture-augmented default root index. These are warmed local whole-process counters, not public Meta or Free quota CPU. Eight profiles and separate 2,000-operation function loops identify X.509/ASN.1 parsing and canonical reencoding as the clearest JS hotspots: full fixture parseDer averaged 0.370 ms versus 0.440 ms for complete CertificateVerify; cached-key ECDSA verification averaged 0.040 ms. A private no-canonical-check loop isolated cost only and is explicitly not a proposed/shipped fix. Production code and public roots are unchanged; no online traffic or deployment occurred. See [diagnosis, controls and safe next steps](ech-library-cpu-2026-10-24.md) and [sanitized measurements/reproduction sources](results/2026-10-24/ech-library-cpu-profile.json). #25/#7 remain open.

## Current-source HTTPS/TCP-only smoke (2026-10-26)

The supported named upstreams are HTTPS and ordinary TCP; all DoT definitions fail full preflight without a transport rewrite, including unused, optional and unreachable definitions. The independent ECH TLS probe is unchanged; see [ADR 0001](adr/0001-exclude-dot-from-current-scope.md).

The [current-source cloud smoke](current-source-smoke-2026-10-26.md) records the exact production bundle hash, a baseline-sensitive DoT rejection check, twelve initial assertions (eleven passed, TCP failed), one baseline TCP control, one successful current TCP confirmation, and restoration. The initial TCP error and both harness expectation failures remain visible; this is not an all-green first pass or proof of TCP reliability. Static typechecking passed; no local behavior suite, CPU matrix or ECH probe was rerun. [Practical Free acceptance](practical-free-closeout-2026-10-26.md) allows occasional successful CPU overages without overlooking real execution failures. #25/#7 remain open.
