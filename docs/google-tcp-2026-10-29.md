# Google TCP upstream cutover

On 2026-10-29 the user explicitly requested Google ordinary DNS over TCP for **all** upstreams, with no DoH, DoT/TLS or UDP fallback. Production `superdoh` now uses:

```json
{
  "resolver": { "transport": "tcp", "address": "8.8.8.8", "port": 53 },
  "echPrimary": { "transport": "tcp", "address": "8.8.8.8", "port": 53 },
  "echSecondary": { "transport": "tcp", "address": "8.8.8.8", "port": 53 }
}
```

The existing names preserve rule references; they share one Google target, not independent fallback providers. Browser-to-Worker HTTPS is unchanged. Worker-to-Google DNS is length-prefixed ordinary TCP without TLS encryption or certificate authentication. This does not reopen the TLS transport excluded by ADR 0001.

## Scope and publication

No production JavaScript changed. Existing `loadUpstreams()`, `queryStream()` and `createUpstream()` implement configuration validation, native TCP connections, DNS frame handling, deadlines/cancellation, response matching and caching. Cache identity already includes the complete target and source name, separating these entries from old HTTPS entries.

The Cloudflare settings API updated only `DNS_UPSTREAMS`, after a SHA-256 comparison against a private full-settings snapshot to detect concurrent changes. All other 20 bindings, rule groups, ECS policy, access paths and runtime settings were preserved. The platform also changed its `workers/triggered_by` annotation from `version_upload` to `upload`; this is metadata, not a runtime setting change. The observed production version after the settings update was `b23f3ecc-3510-454d-9060-ea3ffc732116`, with 100% traffic. Later code builds can produce a new version; `wrangler.jsonc` already sets `keep_vars: true` to preserve Dashboard-managed variables.

## Verification

The authenticated, expiring temporary Worker used the existing production core and a private copy of production rules with only the upstreams replaced. Latest results passed **11/11 cases**: A, AAAA, HTTPS, 80-byte Padding, ECS, both ECH source names, ordinary production A and the complete Facebook/Instagram/X HTTPS pipelines including ECH parameters.

At FRA, uncached individual Google TCP DNS calls in this sample took 7–12 ms. The three site HTTPS pipelines took 17–27 ms; the ordinary A pipeline took 421 ms. These are Worker-side samples, not browser round-trip times or a controlled DoH-versus-TCP comparison. The pipeline timings are aggregate, not per-action profiles. Outer test invocations used the existing HTTP proxy, while DNS inside the Worker used native TCP with no alternative DNS transport.

The ledger charged 13 of 20 allowed outer cloud requests, including two ECS harness failures. Initially its rule group was an array rather than the required `order`/`rules` object. A quoting-sensitive edit did not apply before the first explicit rerun; the verified correction passed next. No production transport change was needed. The first temporary upload also failed because one private test binding exceeded the size limit; splitting it into bounded bindings allowed deployment. Raw failures were retained privately, not replaced with passing results.

A separate three-request production curl smoke explicitly removed proxy environment variables and used `--proxy '' --noproxy '*'`; all reported `proxy_used=0`. The padded X HTTPS request returned HTTP 200 and a valid corresponding HTTPS DNS answer in 2.888 seconds. The example.com A and Facebook HTTPS attempts timed out during connection with no HTTP response. Thus the upstream switch is validated, but direct client-to-entry stability and website usability are **not** established. No browser navigation or site-challenge handling was rerun.

`npm run typecheck`, cloud bundle and syntax checks passed; local behavioral suites were not run. The temporary check Worker was deleted successfully (API 200). Private settings snapshots, authorization data, endpoint paths and raw logs remain under ignored `.acceptance/google-tcp-20261029/` and are not committed. Sanitized machine-readable evidence: `docs/results/2026-10-29/google-tcp.json`.

## Reusing the cloud check

Source: `test/cloud/google-tcp/main.js` and `build.mjs`. The current build output is an ignored run directory, not production. A new run requires a fresh expiring key, unique private configuration, independent budget ledger and cleanup. The handler accepts only eleven fixed POST case names; production test configuration is supplied through bounded secret chunks (`PRODUCTION_PARTS`, `PRODUCTION_0`, etc.), never embedded into the tracked bundle. Do not reuse an expired ledger/key or publish its contents.
