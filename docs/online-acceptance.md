# Online acceptance runbook

Status: **bounded current-source checks completed; full acceptance is not declared**. The [unified #25 reconciliation](acceptance-closeout-2026-10-26.md) is the current decision: source-verified correctness and cache isolation, historical key/CPU provenance, practical Free policy, ECH costs and finite remaining claims. Earlier reports remain unchanged. This runbook is not authorization for another run; the reconciliation itself sent no cloud requests or behavior tests.

Current upstream scope, approved 2026-10-25, is HTTPS and ordinary DNS over TCP only. `transport: "tls"` in any `DNS_UPSTREAMS` definition is rejected before network work, including unused definitions; this runbook does not authorize DoT traffic. Earlier online DoT measurements remain historical evidence, not a passing current-scope test. The independent ECH TLS probe remains separate and unchanged. The complete #25 matrix remains unaccepted; previous key checks and practical CPU observations are recorded separately, not blanket failures. See [ADR 0001](adr/0001-exclude-dot-from-current-scope.md).

## Authorization gate

Before any account/resource mutation or online samples, obtain explicit approval of:

- The Cloudflare account and confirmation that the test Worker is actually on the Free plan.
- A **new, isolated** Worker name, hostname, permitted test sources and access policy. Do not overwrite an existing business Worker or revive historical credentials.
- Credential delivery through the supported login/Secret flow. Never put tokens or path keys in this document, command arguments, source, reports or raw exported request URLs.
- The telemetry method and retention policy, including whether an additional sanitized Tail Worker/collector is authorized. Do not enable URL-bearing invocation logs on a secret-path endpoint merely to obtain CPU values.
- A bounded run: begin with five sequential smoke requests; the proposed initial matrix allows at most 500 total client requests, concurrency one, and at most one new request per second. Stop failing cases rather than repeatedly retrying. Increasing scope requires approval.
- Whether to retain or delete the new test resources afterward. Neither cleanup nor ongoing traffic is implicit.

Keep normal production configuration unchanged. Prepare measurement-specific configuration in an ignored local file after the account and resource names are approved. Do not commit credential-bearing exports.

## Baseline and prerequisites

1. Record the commit, lockfile, Wrangler/workerd versions, compatibility date, deployment version, account plan, configuration hashes (not secrets), application limits and platform quotas verified on the test date.
2. Run `npm test`, `npm run typecheck`, local `wrangler deploy --dry-run`, and `npm run test:ech-interop` with an available ECH-capable OpenSSL build. Missing support remains a blocker, not an automatic skip or a reason to disable authentication.
3. Preflight raw TCP destinations against platform restrictions before deploying: Cloudflare IP ranges are blocked, so a Cloudflare-hosted ECH target is not a valid raw-TCP success fixture. Explicitly select an allowed, authorized source; do not silently substitute one. Verify HTTPS source identity and ordinary TCP reachability separately. Any DNS upstream definition using `transport: "tls"` is rejected by current configuration policy before network work and is not an online matrix case. ECH probe TLS remains a separate feature. Distinguish platform destination restrictions, HTTPS certificate errors and invalid DNS responses; never turn off verification or silently replace a failing transport.
4. Reuse checked-in JSON examples with explicitly configured, authorized sources. Keep the default original-response cache enabled for default scenarios; change its JSON policies explicitly for bypass cases.

## Measurement matrix

| Case | Required observations |
| --- | --- |
| First/cold versus warm | Preserve first-request and subsequent warm samples separately. A fresh deployment or idle interval is only a cold-start candidate unless telemetry verifies isolate state; label uncertainty. |
| HTTPS and ordinary TCP | Query each supported transport explicitly; validate question/ID association, NXDOMAIN/NODATA, full RCODE and HTTPS identity failures. `transport: "tls"` is out of scope and must fail preflight; do not send a DoT request or substitute another transport. No hidden retry, race, fallback or default query. |
| Cache miss/hit/bypass | Distinguish source access from final rewriting. Verify IDs/TTL aging, source/transport/query/Secret isolation, policy precedence, and rules running on hits. |
| Sequential fallback | Separate failed transport/protocol from valid SERVFAIL/REFUSED. Branch through lastAction/RCODE and preserve failure events after later success. |
| Rule scale | Compare bounded groups such as 1/10/50/100 rules; record actual visited actions/conditions and compilation, step or resource failures. Do not extrapolate to arbitrary input. |
| Maintained lists | First load, warm snapshot, due replacement, failed refresh with old data unusable, and recovery. Record entry/byte counts; start with 100/1,000 entries, then the configured maximum if small cases are safe. Refresh interval is not DNS TTL. |
| Address attribution | Single/multiple normalized addresses, same-address matching, hit/miss, missing fields, source fault, rollback and shared quotas. Metadata is not precise physical location. |
| Direct/DNS ECH | Preserve other HTTPS parameters, clear AD/affected signatures only on modification, isolate source and target, and validate safe DNS reuse. |
| Full authenticated ECH probe (separate TLS feature) | Separate complete handshake from cached configuration reuse. Select `verifyCertificate: true` explicitly for authenticated acceptance; separately cover the current default-unverified behavior, identity failure, timeout/byte limits and cleanup. Any explicitly configured verification-off diagnostic is separately labeled, never an automatic downgrade. |
| Access/failure boundaries | Authorization before source work; invalid input versus execution failure; stop/return/completed finalization; no-answer SERVFAIL; cancellation and redaction. |

Allocate the approved sample budget before sending traffic. For lightweight cases aim for at least 30 warm observations if the total budget permits; report the actual count. Label small heavy-probe samples and do not infer reliable tail percentiles from a handful of requests.

## Actual CPU and wall time

Cloudflare exposes CPU and wall time through invocation telemetry and Trace Events. Use the approved collection method to obtain **platform CPU**, **platform wall time**, outcome/resource status, deployment, timestamp and available edge context. Discover actual keys and units from the current schema and returned records before filtering/calculating; do not guess names or replace CPU with a stopwatch.

- Client monotonic elapsed time is end-to-end latency, not Worker CPU and not necessarily platform wall time.
- Network waiting, ECH elapsedMs, performance.now() around fetch, background work and Cron do not prove Free-plan CPU compliance.
- Production invocation logs/traces are disabled to protect path keys. Use authorized URL-free metrics/collection, or a separately approved public measurement endpoint without a path secret. Recheck access correctness separately without logging the secret path.
- Record telemetry sampling, unavailable fields, ingestion delay, lost samples and correlation uncertainty. Retain errors/timeouts rather than dropping them. Save only sanitized, approved evidence.

## Report and disposition

For each case report sample count, correctness, cache/source behavior, CPU/wall min/median/p95/max where defensible, client-latency distribution, errors, verified Free-plan limit, and pass/fail/blocked conclusion. Link configuration/version and local interop evidence without exposing credentials, private URLs or raw DNS payloads by default.

If a default or built-in path exceeds verified limits, report evidence and propose optimization, decomposition or explicit trade-offs. Do not call reduced scope complete, change authentication, or close #7/#25 without authorization. Retain/delete only the resources covered by the approval.

## References

- [Workers limits and CPU monitoring](https://developers.cloudflare.com/workers/platform/limits/)
- [Workers invocation logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
- [CPU/wall telemetry](https://developers.cloudflare.com/changelog/post/2025-04-09-workers-timing/)
- [Workers observability API](https://developers.cloudflare.com/api/resources/workers/subresources/observability/)

## Bounded collection and offline reporting tools

The repository contains bounded collection tools. They **do not grant authorization**; separately authorized results are recorded in the dated report, not inferred from these tools:

- `scripts/acceptance-runner.mjs` sends standard binary DoH POST requests using the public DNS library. It does not deploy, change bindings, select sources or enable telemetry. Its runtime bundling of the existing DNS WASM library uses the locked development `esbuild`; no new production dependency or protocol parser is introduced.
- `scripts/acceptance-report.mjs` reads sanitized samples plus optional normalized platform telemetry entirely offline. It never contacts Cloudflare or guesses a platform schema.
- `examples/measurement-plan.json` is a **tool manifest, not a Worker binding object**. Its placeholder commit/Worker/approval and expected answer must be replaced with the approved candidate and actual expected behavior. The fixed-answer template is only a starting point; allocate the approved budget across the full matrix above and run separately when changing Worker configuration.

Create private plans and outputs under ignored `.acceptance/`. Never put the endpoint/path key into a manifest, shell history, command argument or collected report. Supply the complete endpoint through the environment from the approved secure credential flow as `DNS_ACCEPTANCE_URL`; do not print that variable.

Offline preflight (no endpoint or network needed):

```sh
node scripts/acceptance-runner.mjs examples/measurement-plan.json --plan --authorized-online
```

`--authorized-online` is an operator acknowledgment that the separate account/resource/source/telemetry approvals already exist; the flag, a manifest label, and this document do **not** establish that approval. A real run must not be performed until the authorization gate above has been satisfied. The template cannot serve as an approval record.

After approval, with the actual private plan and endpoint provided securely:

```sh
node scripts/acceptance-runner.mjs .acceptance/plan.json --authorized-online > .acceptance/samples.json
node scripts/acceptance-report.mjs .acceptance/samples.json > .acceptance/report.json
```

The runner requires HTTPS in online mode, rejects URL userinfo/query/fragment, refuses redirects and performs no retries. A local harness may use `--local` only with an HTTP literal loopback address (`127.0.0.1` or `[::1]`); local manifests must declare `accountPlan: "local"`. There is no hostname/DNS fallback to reach non-loopback services in local mode.

Limits: at most 500 planned requests and 100 uniquely named scenarios, at least five planned smoke requests, 30-second maximum per-request timeout, 65,535-byte response cap, 512-KiB manifest cap, and a 15-minute execution deadline after local setup. Online intervals must be at least 1,000 ms; the runner conservatively waits the interval **after each completed request**, so there is no concurrent traffic. Local tests may use a shorter interval. A failure within the first five samples stops the run; later failures stop their own scenario. The output retains failed samples and stopped scenario names. Exit codes: 0 collected successfully, 1 preflight/setup failure with sanitized error, 2 observed failure or incomplete run with the sample JSON still emitted. If interrupted or killed before emission, treat output as incomplete; do not replace missing samples with success.

The endpoint is never exported. Output includes a random run ID, safe scenario/phase labels, start timestamps, client latency, HTTP status, DNS RCODE, simple correctness and safe error codes. DNS response checks cover identity/question association, QR/opcode/truncation, full RCODE, and configured answer count/AD flag and optional exact Answer TTL. An expected `ttl` must be an integer from 0 through 4,294,967,295; it requires at least one Answer and checks every Answer record. Use this for deterministic rewrite assertions, not an aging cache response whose exact TTL is inherently time-dependent. They do **not** prove every RR's content, source access, cache state, isolate identity or all DNSSEC semantics; retain independent acceptance evidence for those properties. Phase names are declared labels: `cold-candidate` is not verified cold, and repeated queries are not independently proven cache hits. Sample IDs are sent in `X-Acceptance-Sample-Id` for an explicitly approved collector to correlate; the application does not expose a new production API or log this header. Approved platform invocation logging can record request metadata, so it must be restricted to key-free measurement requests and disabled before the path-key phase.

### Normalized telemetry input

Read the actual approved platform dataset, discover its fields and units, verify the candidate/Worker and sampling, and correlate samples through the approved collection method. Only then export an allowlisted JSON object:

- Top level: `version: 1`, positive `cpuLimitMs` verified for the approved plan/date, `verifiedOn` as `YYYY-MM-DD`, and `samples` (at most 1,000).
- Each telemetry sample: `sampleId` copied from a correlated client UUID, finite nonnegative `cpuMs` and `wallMs` in milliseconds, and `outcome` from `ok`, `exception`, `exceededCpu`, `exceededMemory`, `canceled`, `unknown`.
- No raw event, URL, headers, credentials, certificate or exception body. Duplicate correlations and unknown fields are rejected. Input files are bounded to 2 MiB each and require valid UTF-8.

These are the tool's normalized field names, not an assumption that every Cloudflare API returns that shape. The [Workers Trace Events dataset](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/workers_trace_events/) documents `CPUTimeMs`/`WallTimeMs`; other telemetry surfaces can use different fields. Check the actual source before converting. Do not enable URL-bearing traces/invocation logs on a secret-path endpoint just to obtain these values.

```sh
node scripts/acceptance-report.mjs .acceptance/samples.json .acceptance/telemetry.json > .acceptance/report.json
```

Reports keep client latency, observed platform CPU and wall time separate; missing values stay unavailable, and missing/orphan/unknown telemetry is counted. Distributions provide min/median/max, with p95 only at 100 or more samples (still an observed quantile, not a tail-latency guarantee). An incomplete/stopped/local or unmeasured case cannot be reported as within the declared online limit. Incorrect responses and failing execution outcomes remain failures. Successful invocations above the declared CPU threshold are counted, not automatically treated as execution failures: `cpuWithinLimitCount`, `cpuOverLimitCount` and `cpuWithinLimitRatio` describe correlated samples, while `executionFailureCount` counts actual failed samples/outcomes. Missing/unknown telemetry, stopped cases and local runs remain blocked. A fully correlated successful case with overages is `observed-with-cpu-overages`; this does not assert that overages are rare, promise platform elasticity, or grant complete acceptance. A fully correlated case with every observed CPU value within the threshold is `observed-within-declared-limit`; the limit/account plan and correlation are externally supplied, not independently verified by this CLI. Every report keeps `completeAcceptance: false`. An operator must still complete the full matrix, source/cache/security checks and evidence review before any overall acceptance decision.

### Local verification

`npm run test:measurement` exercises collection through the production workerd HTTP entry and controlled local services, including rate/authorization gates, response/error limits, redaction, correlation schema and offline reporting. Test telemetry is synthetic, explicitly used only to test the report tool; it is not a measurement result. The script is included in `npm test`. Running that local suite creates no online resources and performs no online measurements. The separately authorized 2026-10-22 run, resource disposition and incomplete acceptance conclusion are documented in the dated report.
