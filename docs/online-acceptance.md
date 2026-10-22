# Online acceptance runbook

Status: **prepared, not authorized or executed**. This is the remaining #25 procedure, not a result or deployment approval. The independent local ECH/OpenSSL check passed on 2026-10-22; reproduce it using [acceptance.md](acceptance.md) for the actual candidate before claiming complete acceptance.

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
3. Verify source reachability and TLS identity for HTTPS/TCP/TLS separately. Distinguish platform destination restrictions, certificate errors and invalid DNS responses. Never silently replace a failing transport or turn off verification.
4. Reuse checked-in JSON examples with explicitly configured, authorized sources. Keep the default original-response cache enabled for default scenarios; change its JSON policies explicitly for bypass cases.

## Measurement matrix

| Case | Required observations |
| --- | --- |
| First/cold versus warm | Preserve first-request and subsequent warm samples separately. A fresh deployment or idle interval is only a cold-start candidate unless telemetry verifies isolate state; label uncertainty. |
| HTTPS, TCP, authenticated TLS | Query each explicitly; validate question/ID association, NXDOMAIN/NODATA, full RCODE and identity failures. No hidden retry, race, fallback or default query. |
| Cache miss/hit/bypass | Distinguish source access from final rewriting. Verify IDs/TTL aging, source/transport/query/Secret isolation, policy precedence, and rules running on hits. |
| Sequential fallback | Separate failed transport/protocol from valid SERVFAIL/REFUSED. Branch through lastAction/RCODE and preserve failure events after later success. |
| Rule scale | Compare bounded groups such as 1/10/50/100 rules; record actual visited actions/conditions and compilation, step or resource failures. Do not extrapolate to arbitrary input. |
| Maintained lists | First load, warm snapshot, due replacement, failed refresh with old data unusable, and recovery. Record entry/byte counts; start with 100/1,000 entries, then the configured maximum if small cases are safe. Refresh interval is not DNS TTL. |
| Address attribution | Single/multiple normalized addresses, same-address matching, hit/miss, missing fields, source fault, rollback and shared quotas. Metadata is not precise physical location. |
| Direct/DNS ECH | Preserve other HTTPS parameters, clear AD/affected signatures only on modification, isolate source and target, and validate safe DNS reuse. |
| Full authenticated probe | Separate complete handshake from cached configuration reuse. Check default authentication failure, timeout/byte limits and cleanup. Any explicitly configured verification-off diagnostic is separately labeled, never an automatic downgrade. |
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
