# Meta / X main-compatible policy

This policy closes the concrete DNS behavior gaps against main commit `8e8cb022f1ff274d23bf745c61e133963a9cb76b`. It does not replace the rule engine with main's concurrent racing implementation.

- Meta A uses the service-class static first-choice pool from main: 21 exact entries and 8 suffix entries, exact first. Unmapped A queries retain the normal upstream path. The source's June 2026 reachability comment is historical, not a new local reachability measurement.
- Meta and remap-domain AAAA return empty NOERROR answers. Other domains retain IPv6.
- Meta HTTPS responses are rebuilt at the original query owner with ALPN h2/h3 and main's ECH list, removing conflicting CNAME/AliasMode answers. This works for arbitrary matched subdomains, not just an enumerated list. Negative upstream answers are not converted to success.
- X/remap HTTPS obtains CF ECH before rebuilding the original-owner record, including when the upstream answer is empty or CNAME-only. Both ECH sources failing preserves the original response. The existing independent ECH source queries do not inherit visitor ECS.
- X/remap A uses the configurable preferred hostname `cf.090227.xyz`, filters addresses through the Cloudflare IP list, removes CNAME/non-CF A records, renames answer owners and sets TTL 60. Failed, negative, empty or non-CF preferred results explicitly fall back to the original A query. A negative original query is not overridden.

The preferred hostname is from main's configuration example and was separately checked through the production DoH: its A addresses were `104.21.71.249` and `172.67.172.155`, both in Cloudflare's official published IPv4 ranges. This verifies DNS ownership, not present-day reachability from the user's network.

## Reproduce configuration

```sh
node scripts/generate-ip-list-ech.mjs
node scripts/generate-main-parity.mjs
```

Outputs are `examples/meta-cf-ech-env-only/bindings.json`, `dashboard.txt`, and `main-parity-report.json`. The checked-in `meta-routes.json` records the main source commit and mapping. All generated variables are below 5 KB; the full example is about 20 KB. Example paths are templates, not the live random endpoint. Do not overwrite live ECS, paths, upstream definitions or unrelated bindings when applying a rule update.

## Cloud verification

The first bounded run passed 72 checks across 15 client requests: all static routes, owner references, protected records, old/new RRset signature invalidation, unchanged unrelated EDNS, response-size rollback, both IPv4 and IPv6 policies, empty/CNAME/AliasMode/existing HTTPS cases, exact ECH parameter bytes, primary/secondary source handling, negative responses, all preferred-address fallback cases and non-target controls. Fixtures use reserved test networks, not a visitor's real address. Local behavioral suites were not run; only syntax, TypeScript and offline bundling were used locally.

Tracked harness: `test/cloud/main-parity/`. Offline build: `node test/cloud/main-parity/build.mjs`. Actual expiring access guards/configurations and request ledgers live in ignored `.acceptance/main-parity-20261028/`. The runner reserves request budget for production verification, persists each attempt before sending, waits at least 1.05 seconds between starts, and never retries automatically. HTTP redirects at the Worker edge use manual handling.

Protocol parity is not a claim of successful ECH negotiation or direct browser access from China. Those require the user's actual network and browser. No system DNS, proxy, hosts or browser settings were changed.
