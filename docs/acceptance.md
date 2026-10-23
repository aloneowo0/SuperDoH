# Acceptance matrix and verification status

This matrix maps the current implementation surface to its local verification commands. A listed command is a reproducible check, not a claim that it was run for a particular release. Run in the repository root with Node.js 22+ and the locked dependencies. Workerd tests use the configured compatibility date and do not enable `nodejs_compat`.

## Local matrix

| Acceptance area | Command / suite | Observable scope |
| --- | --- | --- |
| JSON rule validation, stable order, conditions, state and failures | `npm run test:rules` (`test/rules.mjs`) | Public execution results, sorted groups, full preflight, resource limits, conditions, errors and rollback. |
| Standard DoH GET/POST, path authorization, upstream and DNS response semantics | `npm run test:doh` (`test/doh.mjs`) | Production `src/worker.js` HTTP entry, DNS wire output, no implicit requests, source failure, RCODE and DNSSEC cleanup. |
| TCP and authenticated TLS sources | `npm run test:tcp` (`test/tcp.mjs`); `npm run test:tls` (`test/tls.mjs`) | Workerd public DoH entry connected to controlled local protocol servers; framing, identity checks, timeouts, cleanup and shared request budgets. |
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

See [the dated follow-up](cpu-optimization-2026-10-23.md) for single-parse trust preparation, Windows process-CPU controls, and the user-requested default `verifyCertificate: false`. Explicit `true` preserves authentication. These changes do not revise historical online measurements or establish Free-plan acceptance; the new independent OpenSSL rerun has not been performed.
