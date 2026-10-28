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

The final seven Padding suites passed on check version `d867b7fb-d753-4f9d-bf5e-880f1a65b216`; parity suites passed on `c410913b-ac3f-4a66-a153-76e8e263aa77`, with the same cache implementation. No core behavior changes followed the first test run; subsequent edits corrected the harness and the cache comment. Both temporary Workers were deleted successfully via the Cloudflare API. Production remained version `d702c08a-69d2-4746-a9d7-69b0741ac8f4`; this change has **not been deployed to production or committed/pushed**.

Sanitized results: `docs/results/2026-10-28/padding-cache.json`. Private configurations, secrets, raw responses and the cumulative ledger are under ignored `.acceptance/padding-cache-20261028/`; do not publish them.

## Harness

Source: `test/cloud/padding-cache/`. `build.mjs` bundles the check Worker and controlled fixture, reusing existing main-parity scenarios. `prepare.mjs` creates a fresh private configuration, secret files and independent ledger with exclusive file creation; it refuses to overwrite an existing run. It is deliberately scoped to the named temporary Workers in this account, not production. `runner.mjs` requires explicit suite selection and enforces expected check counts and the cumulative budget. Secrets must be supplied using Wrangler's `--secrets-file`; do not place them in tracked configuration or command arguments. Any new run requires a reviewed fresh run directory/temporary names and budget, not resetting this completed ledger.

## Remaining work

This repairs a demonstrated DNS-cache eligibility gap. It does not establish that X, Meta, linux.do or NodeSeek now open directly. The preliminary original-name HTTPS upstream query in runtime rules and the observed DoH HTTP/2/body-transfer instability are separate work. No Meta routing rules, production bindings, system DNS, hosts, proxy settings or normal browser profiles were changed. Production cutover and any new direct-browser acceptance run require the user's authorization.
