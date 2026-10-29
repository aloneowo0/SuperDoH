# Deployment-time IP lists

IP list **source configuration belongs to the build environment**, not the request path. Configure `DNS_IP_LIST_SOURCES` on the production Workers Builds trigger (or the shell invoking Wrangler):

```json
{
  "cloudflare": { "url": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cloudflare.txt", "format": "text" },
  "meta": { "url": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/facebook.txt", "format": "text" }
}
```

These are deployment choices, not defaults embedded in the runtime or generic library. Build variables are not Worker runtime variables. Runtime `DNS_IP_LISTS` uses small references:

```json
{
  "cloudflare": { "embedded": "cloudflare" },
  "meta": { "embedded": "meta" }
}
```

Rules keep their existing list names and `inList` conditions. Definitions cannot combine `embedded` with remote URL/secret/format/cache settings. Missing references and resource-limit violations fail configuration validation, including unused definitions. The explicit URL mode remains available for other applications; an embedded reference never silently uses it as fallback.

## Build and update

`wrangler.jsonc` runs `node scripts/build-ip-lists.mjs` before bundling. A normal `npx wrangler deploy` therefore downloads and compiles fresh sources even when the CI dependency cache exists. Missing build configuration, failed downloads, redirect responses, invalid media types, empty/invalid/oversized data or malformed CIDRs stop the build. There is no stale-data fallback. All sources must validate before the generated module is replaced. A failed compilation removes previous generated publication files so a stale file cannot be accidentally used afterwards.

The compiler accepts at most 16 named HTTPS sources, each at most 262144 bytes and 4096 source entries, with a 15-second download deadline per source and 4 MiB total estimated compiled-index state. It rejects URL credentials/fragments and does not follow redirects. Source formats are strict UTF-8 text or JSON string arrays. The same library compiler normalizes, sorts and merges ranges; its output is a versioned snapshot with hexadecimal boundaries. The ignored generated module contains no source URLs, only snapshots, content hashes and fetch times. `src/generated/ip-lists.manifest.json` records hashes, entry/interval counts, source sizes and fetch times for deployment verification.

Only runtime validation and restoration of immutable numeric ranges happen once per isolate. Requests do not download GitHub lists, read the IP-list Cache API, parse CIDRs or re-sort ranges. Runtime effective list count/entry/byte/state limits still apply. DNS upstream queries and DNS-response caching are unaffected.

Snapshots remain fixed for the lifetime of a deployed version. **There is no hourly refresh.** Deploy again to refresh. A source outage intentionally prevents updating production instead of silently publishing empty or previous data; the currently deployed version continues operating independently of the source.

## Development and verification

`npm run build:ip-lists` explicitly performs the same bounded download/compile step. Supply `DNS_IP_LIST_SOURCES` in the environment; do not commit private URLs or environment files. The generated JavaScript and manifest are ignored. Types are declared in `src/generated/ip-lists.d.ts`, so typechecking does not require a network fetch; behavioral runs/bundles importing the runtime do require generated data.

Cloud verification lives in `test/cloud/embedded-ip-lists/`. Generate real candidate snapshots first, prepare a fresh private expiring run configuration, then bundle the check and fixture. Only this test bundle adds explicit synthetic fixture indexes; production does not contain them. The controlled parity tests can select those indexes with the test-only `CHECK_IP_LISTS` setting. The runner has an independent cumulative 40-request budget, explicit suite selection, serial spacing, bounded response bodies and no automatic retries. It preserves earlier failures.

The no-I/O suite replaces fetch and IP-list Cache API access with throwing functions inside one isolated check request, then verifies successful production-list lookup, repeated identity reuse and strict failure cases. Membership equivalence checks source-derived indexes against compiled snapshots at both ends and outside every merged interval. Builder and snapshot-library cases cover invalid inputs and bounds; existing Padding/ECS and Meta/X controlled parity suites exercise the unchanged rule pipeline. Tests using live Google TCP retain real DNS queries and never use a hidden DoH fallback.

Switch production runtime references only after a compatible version containing the generated indexes is deployed. Keep other bindings and Google TCP upstreams unchanged. For rollback, coordinate the previous compatible code and original DNS_IP_LISTS; do not overwrite unrelated concurrent settings.

## Production verification, 2026-10-29

Compatible code was first deployed as `5d33888f-0524-4017-81b7-2717805791cf` while old definitions still worked, then only DNS_IP_LISTS changed to embedded references (`bdc6da67-acd5-48a4-bf25-b61c61d1f051`, 100% traffic). All other 20 bindings and runtime settings were preserved. DNS_IP_LIST_SOURCES was added to the existing dev Builds trigger without changing its deployment command. The normal Wrangler custom build downloaded both lists and reported 7 ms Worker startup time for this upload.

The published source snapshots contain 788 Cloudflare entries merged to 739 intervals and 119 Meta entries merged to 80 intervals. Full source SHA-256 hashes, sizes and fetch times are in the sanitized results. These are source-list memberships, not the smaller official Cloudflare proxy-only CIDR set.

Latest cloud verification passed **184 checks across 34 suites**, charging 38 of 40 allowed outer cloud requests: 28 library, 15 builder, 8 no-I/O/runtime, two source equivalence, 52 Padding/ECS, 72 controlled Meta/X parity, four live-Google candidate pipelines and three cloud-to-production DNS checks. Four initial cloud production-smoke attempts failed in the test client because Workers fetch rejects redirect:error; stage diagnosis identified it, and manual redirects passed all three cases. Those failures remain in the ledger and sanitized report. Earlier preflight syntax/build errors were corrected before cloud execution; no production-core change followed the initial 181 passing candidate checks.

Three separate proxy-bypassed client requests all timed out during connection without an HTTP response. Cloud-to-production checks nevertheless returned valid example.com A, X A and Facebook HTTPS answers. Neither result establishes website navigation success.

A first CPU observation compared 199 estimated requests before with 33 after. CPU P50/P95/P99 were 0.504/2.025/45.869 ms before and 0.720/21.580/48.215 ms after, with zero execution errors in both windows. These are unequal small windows with mixed request types: **no reliable CPU improvement is claimed**. The CPU tail still needs profiling. Removing list download/cache/compilation work from the request path does not remove every remaining CPU cost.

Typecheck, syntax and bundling passed; no local behavioral suites ran. Both temporary Workers were deleted (API 200). Evidence: `docs/results/2026-10-29/embedded-ip-lists.json`. Private settings, secrets, endpoints and raw logs remain ignored.
