# Practical Free acceptance closeout — 2026-10-26

## What changed

The user clarified that **most requests should fit Free CPU usage, with occasional overages acceptable**. This supersedes treating any single CPU value above 10 ms as automatic failure of a workload. No new numeric percentage target was invented, and platform elasticity is not a guaranteed extra budget. [Cloudflare documents](https://developers.cloudflare.com/workers/platform/limits/#cpu-time) built-in isolate flexibility for infrequent overages, but consistent limit pressure can terminate execution.

The report CLI now distinguishes observations from failures:

- Correct, fully correlated invocations with CPU overages: `observed-with-cpu-overages`.
- Every measured CPU value within the declared threshold: `observed-within-declared-limit`.
- Incorrect responses or actual `exceededCpu`, memory, exception or cancellation outcomes: `failed`.
- Missing/unknown telemetry, stopped cases and local runs: `blocked`, unless there is an actual failure.
- `cpuWithinLimitCount`, `cpuOverLimitCount`, `cpuWithinLimitRatio` and `executionFailureCount` expose the evidence. The ratio denominator is correlated CPU samples, not all requests. Missing measurements remain separately visible.
- No case is automatically accepted merely because a bare majority fits; `completeAcceptance` stays false. Callers consuming `conclusion` must handle the new observational value.

Historical measurements were not rewritten. [The prior canonical-ID run](cpu-cloud-canonical-id-2026-10-26.md) had 33/34 measured samples within 10 ms and no observed resource-termination outcome, which supports practical use of that controlled ordinary combination. It does not establish the current dirty workspace's full cloud matrix. Profile capture is no longer a prerequisite for proceeding or accepting representative workloads.

## Bounded missing-key and rotation checks

This follow-up tested only the existing isolated `superdoh` Worker, with a new cap of 24 client requests, at least one second after completion, no profile and no public ECH requests. The fixture was not modified. All control operations used Cloudflare MCP; no login, business Worker, DNS, route or billing change occurred.

The deployed application remained the historical `0582d86` code, not the uncommitted local DoT-removal source. Only environment bindings/settings changed. Both before/after script ETags are identical. Temporary random keys were Secret bindings. Only RSA-OAEP ciphertext crossed the control/client boundary; plaintext keys and keyed URLs were never printed or recorded in the evidence. The temporary local decryption key file was removed after checks.

| Scenario | Observed result |
| --- | --- |
| No path key | HTTP 404 |
| Wrong path key | HTTP 404 |
| Unauthorized malformed JSON query | HTTP 404, not a parameter error |
| Correct key, wire POST | Correct A answer, TTL 60, AD clear, no-store |
| Correct key, wire GET | Same correct answer |
| Correct key, JSON GET | Same correct answer |
| Correct key, duplicate JSON parameter | HTTP 400 |
| Old key after rotation | HTTP 404 |
| New key, POST/GET/JSON | New configured answer, TTL 60, no-store |
| Restored empty configuration | Wire DNS SERVFAIL; JSON adapter HTTP 404 |

**Actual requests: 14/24.** Thirteen passed their assertions. One initial GET request used a runner encoding mistake (`Uint8Array.toString` rather than `Buffer.from(...).toString('base64url')`) and correctly received HTTP 400 instead of the runner's expected 200. It remains a failed runner sample; it was not erased or called a production defect. The corrected run resumed remaining checks rather than replaying the completed cases. No new CPU claims are made from these deliberately unmeasured keyed requests.

Rotating static answers verifies key retirement and configuration change, **not upstream cache identity isolation**. That remaining matrix dimension is not falsely marked complete.

## Control-plane details resolved without another test campaign

- After an explicit observability disable, Cloudflare returned script-level `observability: null` and omitted it in version settings. The first strict object-field check stopped before generating a key. Both settings APIs were then verified after a fresh explicit disable, with Logpush and Tail consumers absent, before any keyed traffic. This transaction-specific handling does not weaken the existing fail-closed safety helper to accept arbitrary missing metadata.
- PATCH settings created a latest version without deploying it. The intended version was explicitly activated and its Secret binding checked before traffic; latest was not assumed to mean active.
- Empty bindings preserved the Secret. The cleanup guard stopped before logging restoration, then explicitly deleted only the temporary `DNS_PATH_KEY` through the Secrets API. Active and latest bindings were independently verified empty before collection was restored.

## Verification and restoration

[Complete sanitized evidence](results/2026-10-26/practical-free-closeout.json) includes all requests, operational failures, settings snapshots, source ETags and the reproduction runner without secret values. Its machine-specific transcript path is replaced with the required `DNS_DIAGNOSTIC_TRANSCRIPT` environment variable; the embedded runner is a redacted reproduction template, not a byte-identical execution snapshot. A bounded query during the keyed window returned zero Worker events; this is not a promise about all intermediary/platform logging.

The revised report calculation functions passed **11 checks in the Cloudflare MCP runtime**: CPU boundary/overage accounting, four actual failure outcomes, stopped/local cases, unknown/missing/no telemetry and incorrect responses. SHA-256 of both function declarations matched the local source exactly. This is a cloud calculation check, **not execution of the Node filesystem/CLI wrapper**. CLI regression tests were added/updated, but not run locally under the cloud-only instruction. Syntax checks and TypeScript checking passed. The full local Node/Miniflare/npm/Rust suite was not run, and a full red-before-green CLI run is not claimed.

Final active version `457cbcd9-27c8-4611-a2fc-c3a171781e90` has empty active/latest bindings and no temporary Secret. Original script ETag was preserved. Producer observability, Logpush and Tail settings match the original snapshot exactly: logs, invocation logs and traces enabled; no Logpush or Tail consumers. Public cleanup checks passed. No background traffic remains.

## Remaining delivery boundary

The ordinary combination no longer needs repeated profiling solely because of occasional overages. Keyed wire/JSON behavior and key rotation now have explicit cloud evidence. No DNS/TLS production algorithm was changed to lower CPU.

Still not claimed: the entire current-source cloud matrix, complete upstream cache identity/security combinations, or consistently inexpensive uncached active ECH. Historical complete ECH probes often exceeded 10 ms; normal cache reuse and rare uncached acquisition must be assessed separately rather than silently disabling authentication or removing the feature. Historical resource failures and missing telemetry remain visible. #25/#7 are not automatically closed by this narrower closeout.
