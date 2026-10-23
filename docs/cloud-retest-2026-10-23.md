# Cloud retest — 2026-10-23

## Result

**The current build was tested online; complete Free-plan acceptance remains not passed.** Default-disabled certificate verification substantially reduced CPU in the observed failed-probe cases, but did not make the configured public ECH target work. Explicit verification still had a very expensive first observed invocation.

All previous test Workers and this run's temporary Worker were deleted. A final Cloudflare script-list query confirmed their absence at **2026-10-23T07:32:14.202Z**:

- `superdoh-acceptance-20261022`
- `superdoh-acceptance-20261022-fixtures`
- `superdoh-acceptance-20261023`

No business Worker, DNS record or route was changed. No account upgrade or ongoing traffic was arranged. Existing authorized OAuth connections were used; the token previously supplied in chat was not read or reused. The Free plan remains operator-confirmed, not independently verified through the billing API.

## Actual platform measurements

Build: `e5954e9`. Requests were sequential and spaced by at least one second after completion. DNS cache reads/writes were disabled. CPU values below are **`$workers.cpuTimeMs`**, not local profiler estimates or client latency. Lists are chronological within each phase.

| Version-pinned phase | DNS response assertions | Platform CPU, ms | Platform Wall, ms | ECH outcome |
| --- | --- | --- | --- | --- |
| Public HTTPS upstream | 3/3 passed | 24, 3, 5 | 27, 5, 8 | Not a TLS ECH probe |
| Direct ECH configuration action chain | 3/3 passed | 18, 4, 3 | 19, 4, 4 | Direct configuration, not a probe |
| Required probe, verification omitted/default false | 0/1 passed; SERVFAIL | 21 | 34 | `ECH_PROBE_FAILED`, terminated |
| Optional probe, verification omitted/default false | 5/5 retained the fixed DNS answer | 30, 5, 3, 2, 4 | 38, 13, 10, 4, 9 | **All five probes failed**, rolled back and continued |
| Optional probe, explicit verification true | 5/5 retained the fixed DNS answer | 843, 12, 8, 8, 9 | 900, 24, 16, 14, 14 | **All five probes failed**, rolled back and continued |

The optional phases' successful DNS replies are **not successful ECH probes**. The error events were joined to each invocation and all ten explicitly reported `ECH_PROBE_FAILED` with `rolled_back_continue`. Verification-state events confirm disabled versus enabled policy. Required probing failed closed as configured.

All 17 formal application samples have matching response phase/version metadata, platform version IDs and UUID-correlated CPU/Wall observations. All platform outcomes were `ok`; **six of 17 CPU observations exceeded 10 ms**, without an observed `exceededCpu` termination. First-versus-later observations do not prove exact cold/warm isolate identity. Small sample sets do not establish tail percentiles or a general percentage improvement.

The previous 451 ms online authenticated failure and this run's 843 ms authenticated failure are not a controlled before/after pair. Different invocations, versions and runtime conditions prevent attributing their difference to the single-parse optimization. The local experiment established reduced duplicated parsing; this online run does not establish an authenticated-path CPU improvement.

## Deployment propagation and exclusions

The first unpinned smoke request returned HTTP 404 and had no UUID-correlated Worker invocation in the exported query window. Five subsequent samples intended for the HTTPS configuration actually executed the earlier fixed-answer version. A successful DNS envelope alone would have mislabeled those five as HTTPS success. **All six initial attempts are retained as excluded evidence, not counted as formal phase successes.**

The corrected test used a test-only wrapper around the unchanged production entry. A readiness route and response headers expose a phase label and Cloudflare's native version-metadata binding. Each DNS response was checked against the expected deployed version, then independently matched to the version in platform telemetry. The wrapper adds some response-header/allocation overhead; the measurements include that overhead. Readiness calls do not execute the production DNS path and are excluded from application CPU comparisons.

Total client attempts: **28 of the 30-request bound**:

- Six excluded initial attempts.
- Five version-pinned readiness requests.
- Seventeen formal DNS requests.

Deployment-generated root probes and unrelated requests without our random sample UUIDs are not measurement samples. The final query returned 61 events below its 2,000-event limit, with 27 UUID-correlated platform observations: five excluded old-version responses, five readiness calls and 17 formal application calls. The initial 404 is the sole unmatched client attempt. The historical conservative shared ledger remains at 365 reserved requests of 500, including this run's 30 reservations; unused reservations were not reclaimed.

## Scope and remaining limits

The same allowed public sources were retained: `cloudflare-dns.com` for HTTPS DNS and `cloudflare-ech.com:443` for probing. No provider or verification mode was silently changed to obtain success. Cloudflare documents that raw outbound TCP to Cloudflare IP ranges is blocked; that is a relevant platform constraint, **not proof of the precise low-level cause of these generic probe errors**. Disabling certificate checks does not remove connectivity or protocol restrictions.

The direct-ECH case checks correlated DNS format, question and answer presence through the configured action chain; it is not an independent full-byte ECH interoperability test. No successful public probe handshake, new independent OpenSSL run, p95/p99 result, cache-hit proof or full default-scenario Free compliance is claimed.

[Sanitized evidence](results/2026-10-23/cloud-retest.json) contains every attempted client sample, exclusions, version joins, exact platform CPU/Wall values, failure/policy events, portable binding templates, runtime/lockfile hashes and the test wrapper. It omits account IDs, private origins, credential-bearing URLs, raw headers, IP metadata, exception payloads and credentials. Historical online results are unchanged.
