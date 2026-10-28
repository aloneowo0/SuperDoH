# EDNS Padding cache compatibility

Chrome's direct-browser NetLog contained EDNS Padding (option 12), including an 80-byte sample. The cache previously accepted only an empty OPT or a single validated ECS option, so these otherwise reusable browser queries skipped DNS cache reads and writes. ECH-source queries already had their own cache and build a fresh query without visitor Padding; this is a different cache path.

## Change

`src/doh/cache.js` now allows at most one Padding and one valid ECS, in either order, in a single OPT across the message. Padding may be empty or contain arbitrary octets, as required for receivers by [RFC 7830](https://www.rfc-editor.org/rfc/rfc7830.html). Duplicate OPT/ECS/Padding, Cookie, unknown options, TSIG and SIG remain ineligible for reuse. Existing ECS prefix/scope validation and response subnet matching are unchanged.

The cache key is unchanged: the encoded complete query, with only its ID zeroed, plus the named upstream and resolved target identity. Padding content, size and option order remain in the identity, along with ECS, DO/CD and UDP payload size. This intentionally does not normalize Padding or combine distinct subnets. Query and response Padding need not match; an upstream can add or remove it. TTL, negative-cache SOA and RRSIG lifetime logic are unchanged.

No new disabled-mode entrypoint validation is introduced. In this base version, `validateIncomingEcs()` is called when ECS policy is enabled. Raw malformed/duplicate ECS rejection tests explicitly enable that policy; duplicate options remain ineligible for caching regardless of policy.

## Cloud verification, 2026-10-28

- **52/52 new checks passed:** 18 eligibility, 8 hit/negative-cache, 7 query-identity, 1 upstream-identity, 10 bypass, 5 full-pipeline, 3 ECS/ECH checks.
- **72/72 existing Meta/X parity checks passed** against the candidate core, including static routes, record owners, signatures, HTTPS/ECH cases and preferred-address fallbacks.
- `npm run typecheck`, syntax checks and offline cloud bundling passed. Local behavioral/Miniflare suites were **not** run; three maintained local cache regressions were added and syntax checked.
- Hit evidence combines the actual request-local `createUpstream` network-attempt callback with a fresh DNS TXT receipt generated for every fixture invocation. Repeats use a single Worker invocation/colo, avoiding conclusions based on isolate-local counters. [Cache API data is local to a data center](https://developers.cloudflare.com/workers/reference/how-the-cache-works/).
- The independent ledger charged **37 of 40 permitted outer request attempts**, including failures. Starts were separated by at least 1.05 seconds; there were no automatic retries. Cloud suites were invoked through the existing local HTTP proxy; this was **not** a direct-browser reachability test.

The initial six attempts had Node fetch `TypeError` before an HTTP response because proxy environment variables were absent. An initial source-identity check returned `CACHE_FAILED` late in a larger suite; its root cause was not established. Separating source identity into its own suite passed. Initial invalid-query tests also had harness expectation/construction mistakes; they were corrected to build invalid raw bytes and enable ECS, then passed. The original records remain in the private ledger; the machine-readable summary retains the earlier failures, rather than replacing them with the final results.

The final seven Padding suites passed on check version `d867b7fb-d753-4f9d-bf5e-880f1a65b216`; parity suites passed on `c410913b-ac3f-4a66-a153-76e8e263aa77`, with the same cache implementation. No core behavior changes followed the first test run; subsequent edits corrected the harness and the cache comment. Both temporary Workers were deleted successfully via the Cloudflare API. At that verification checkpoint, production remained version `d702c08a-69d2-4746-a9d7-69b0741ac8f4` and the change was not yet deployed or committed/pushed. The later authorized publication is recorded below.

Sanitized results: `docs/results/2026-10-28/padding-cache.json`. Private configurations, secrets, raw responses and the cumulative ledger are under ignored `.acceptance/padding-cache-20261028/`; do not publish them.

## Harness

Source: `test/cloud/padding-cache/`. `build.mjs` bundles the check Worker and controlled fixture, reusing existing main-parity scenarios. `prepare.mjs` creates a fresh private configuration, secret files and independent ledger with exclusive file creation; it refuses to overwrite an existing run. It is deliberately scoped to the named temporary Workers in this account, not production. `runner.mjs` requires explicit suite selection and enforces expected check counts and the cumulative budget. Secrets must be supplied using Wrangler's `--secrets-file`; do not place them in tracked configuration or command arguments. Any new run requires a reviewed fresh run directory/temporary names and budget, not resetting this completed ledger.

## Remaining work

This repairs a demonstrated DNS-cache eligibility gap. It does not establish that X, Meta, linux.do or NodeSeek now open directly. The preliminary original-name HTTPS upstream query in runtime rules and the observed DoH HTTP/2/body-transfer instability are separate work. No Meta routing rules, production bindings, system DNS, hosts, proxy settings or normal browser profiles were changed. Production cutover and any new direct-browser acceptance run require the user's authorization.

## Production follow-up: direct access

After user authorization, commit `bb1f513` was fast-forward pushed to the intended `dev` branch. The accidentally published remote isolation branch was removed. Workers Builds deployed `superdoh` version `e54c4743-89ea-4a92-9db2-c964a6d3a09a` at 100% traffic. Comparing the old and new version resources confirmed all 21 bindings and runtime settings unchanged. The secondary `super-doh` build failed because its configured `npm run build` script does not exist; its production deployment did not change.

At the user's request, production data-plane checks explicitly bypassed proxies. Ten serial curl POSTs with 80-byte EDNS Padding produced five valid DNS responses and five transport timeouts. The X A response was initially marked failed by an incomplete hard-coded Cloudflare-range predicate in the private smoke harness; reviewing the saved response against the Cloudflare `/ips` API confirmed its addresses belong to `104.24.0.0/14` and `172.64.0.0/13`, with TTL 60. This correction did not delete the initial failure or rerun the request. Repeated production requests do not independently prove cache hits.

A separate isolated Chrome 156 profile used the actual production secure GET DoH template, no proxy, no resolver IP pinning and normal certificate checks. The completed NetLog confirms secure DNS mode 2, the expected resolver template and only `DIRECT` proxy resolution. One navigation per site showed:

| Site | Direct-browser observation |
| --- | --- |
| X | HTTP 403; ECH accepted, TLS 1.3, HTTP/2 |
| Facebook | 20-second navigation deadline exceeded; no document response |
| Instagram | 20-second navigation deadline exceeded; no document response |
| linux.do | 20-second navigation deadline exceeded; no document response |
| NodeSeek | HTTP 403 Cloudflare challenge, `Just a moment...`; ECH accepted, TLS 1.3, HTTP/2 |

Thus the patch is deployed, but usable unrestricted direct access is **not** established. Navigation deadlines are test limits, not server-generated timeout responses. No attempt was made to bypass site challenges. The temporary Chrome context was closed and only this run's isolated profile was removed; normal browser profiles and system settings were untouched. Raw NetLog, navigation records and challenge URLs remain private. Sanitized follow-up evidence: `docs/results/2026-10-28/padding-production-direct.json`.

## Direct-access diagnosis

A bounded follow-up compared both resolver IPv4 edges using native Node HTTPS and HTTP/2, explicit direct lookup, normal certificate verification and a 12-second client deadline. Each edge/protocol pair received an upstream-free root-path control request plus padded Facebook A and HTTPS queries: 12 actual network attempts, 3 completed HTTP responses and 9 client deadlines. Seven deadline cases had no completed TLS handshake. Initial harness failures caused by an incorrect Node lookup callback contract are excluded; their private records remain intact.

The upstream-free control itself can stall before TLS completion. Consequently, at least part of the failure is before HTTP request handling, rather than DNS cache eligibility, upstream DNS or ECH rewriting. Both edges and both protocols show failures; neither disabling HTTP/2 nor pinning one edge is a demonstrated fix. One padded Facebook HTTPS query completed successfully in 1.431 seconds. This small sample is diagnostic, not an availability estimate.

Saved browser NetLog separates the remaining outcomes:

- Facebook: its A/AAAA/HTTPS DoH requests received no headers/body before established resolver HTTP/2 sessions closed with `ERR_HTTP2_PING_FAILED` (-352), around 30 seconds. The page deadline was 20 seconds.
- Instagram: A/AAAA arrived around 15.2 seconds while HTTPS lookup did not complete. TCP connected to the configured address, but no completed TLS handshake was observed before navigation cancellation.
- linux.do: A arrived around 20.75 seconds; HTTPS headers around 22.03 seconds, without a completed body in the captured timeline. DNS already exceeded the page deadline.
- X: TLS 1.3, accepted ECH and HTTP/2 succeeded, followed by an empty 403 with `x-server: x-web` and `server: cloudflare envoy`. This reaches the site-facing HTTP stack; the exact rejection policy is unknown.
- NodeSeek: TLS/ECH succeeded, followed by an explicit `cf-mitigated: challenge` 403. DNS cannot guarantee website authorization.

Current production configuration also retains a required original-name HTTPS resolver lookup in `DNS_RULE_ENV_META_QUERY`; despite its name, its condition applies to all HTTPS queries. This adds a serial dependency before later synthesis and is a separate optimization candidate. It is not established as the cause of pre-TLS or HTTP/2 ping failures. Removing it requires preserving negative-response and fallback semantics. The configured 2-second upstream and 10-second execution budgets must not be confused with client-side connection/navigation deadlines.

There is no packet capture or correlated server-side duration evidence, so responsibility cannot be assigned to an ISP, local gateway, Cloudflare edge or another intermediary. The observability events tool rejected its response schema because a request ID was absent; available ACCESS_DENIED aggregates cannot be attributed to these authorized probes, and successful invocation logging was disabled. No production rules, bindings, system DNS, proxy settings or normal browser profiles were changed during diagnosis. Raw evidence stays private; the sanitized record is `docs/results/2026-10-28/padding-direct-diagnosis.json`.
