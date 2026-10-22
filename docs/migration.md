# Migration from historical SuperDoH configuration

This guide describes the current JSON-only runtime. It does not preserve old automatic behavior. The parent contract is [issue #7](https://github.com/aloneowo0/SuperDoH/issues/7); the detailed runtime contract, fields, limits and failure semantics are in [rules.md](rules.md).

## Before changing the Worker

1. Inventory the old configuration, upstream endpoints, policies, ECH values and any path key.
2. Move connection URLs or tokens that should not be ordinary variables into Cloudflare **Secrets**. Reference each Secret by binding name through `urlSecret`; never commit the value.
3. Prepare a `DNS_UPSTREAMS` JSON binding and one or more `DNS_RULE_*` JSON rule groups. Add `DNS_DOMAIN_LISTS`, `DNS_ADDRESS_SOURCES`, `DNS_CACHE`, `DNS_LIMITS` or `DNS_JSON` only when needed.
4. Configure bindings in the correct Cloudflare Dashboard/Workers Builds environment. Production and Preview can have different variables and Secrets. Keep them as Worker environment bindings; do not copy secrets into Git, a generated JS file or command arguments. The checked-in `wrangler.jsonc` uses `keep_vars: true` to preserve Dashboard-managed runtime variables; build-only variables do not become runtime bindings. Secrets are not deleted by ordinary deployments. After connecting a build or changing environments, verify the intended bindings remain configured.
5. Validate with controlled sources before switching a live route. No deployment or online acceptance is performed by this guide.

The current Worker entry is `src/worker.js` from the checked-in `wrangler.jsonc`. In a Git-driven Workers Builds setup, use the repository root, install dependencies with `npm ci`, and use the configured Wrangler entry for deployment (for example `npx wrangler deploy` where the Build environment is authorized). There is no `superdoh.config.js` generation step.

## Removed behavior: replace, do not translate literally

| Historical configuration or behavior | Current migration |
| --- | --- |
| `defineCondition`, `defineAction`, custom JS/TS callbacks, extension registries, `extensions` | Removed. Express conditions with fields and `all`/`any`/`not`; use supported JSON actions. Unknown extensions/custom conditions/actions are rejected during preflight. |
| `DNS_UPSTREAM`, default resolver, implicit default request | Removed. Define named entries in `DNS_UPSTREAMS`, then reference one explicitly with `queryUpstream` or `queryEch`. A configured source alone performs no request. |
| `DNS_UPSTREAM_GROUPS`, `DNS_DEFAULT_UPSTREAM_GROUP`, group `members`, `accept` policy, group fallback/exhaustion | Removed. Write sequential rules that inspect `lastAction` and/or `response.rcode`, then explicitly request the next named source. There is no automatic retry, failover, race or response adoption policy. |
| Implicit fallback after no answer, after a failure, or after `stop` | Removed. A completed or stopped pipeline without a response returns the corresponding SERVFAIL behavior. Add an explicit request action if a request is intended. |
| Old fields that decide whether NXDOMAIN, SERVFAIL or REFUSED is acceptable | Use explicit conditions on `response.rcode` and current `lastAction`. A valid DNS SERVFAIL/REFUSED is a successful upstream action; a later rule decides whether to query another source. A transport/protocol failure is a failed action and only continues when `onError: "continue"` is explicit. |
| `superdoh.config.js`, file fallback, `configured` toggle, browser wizard, `ENTRANCE`/`PROXY`, custom homepage | Not part of the current Worker. Put JSON bindings in the runtime environment and use `/dns-query`; there is no configuration UI or disguised proxy route. |
| Old public JSON DNS endpoint or implicit provider JSON | DNS JSON is an optional GET adapter on the same route. Set `DNS_JSON=true` and request `application/dns-json`; it is disabled by default and runs the same rule pipeline. |
| Old vendor constants or implicit ECH SNI rewrite | Choose an explicit source action: `loadEch`, `queryEch`, or `probeEch`, then use `applyEch` against an existing HTTPS ServiceMode answer. The direct sample in `examples/ech-direct.json` contains a **synthetic structural fixture**, not a working server key. |
| Request headers or edge location used as response-address geolocation | Keep `client.*`, `edge.*`, and `item.*` distinct. Use `enrichAddresses` after obtaining the response for response-address ASN/region data; matching an attribution field does not itself perform lookup. |
| Old-list fallback that silently keeps stale data after refresh failure | Use `DNS_DOMAIN_LISTS` and `inList`/`inListSuffix`. A failed due refresh invalidates the previous version; a dependent condition fails visibly until a later successful maintenance pass. |
| Automatic list loading on every condition, or list contents as executable rules | Lists are data. Core maintenance uses configured refresh intervals; predicate evaluation only performs in-memory membership checks. No JS/TS function or remote policy language is accepted. |

Removed legacy fields are not ignored for compatibility. Known removed configuration entrypoints and unsupported action/condition fields fail validation rather than silently restoring a prior default policy. Unrelated environment bindings are not interpreted as rules and do not enable historical features.

## Build the new environment

A `DNS_UPSTREAMS` value names connections, not policies. HTTPS entries use `transport: "https"` with `url` or `urlSecret`; TCP and TLS use their explicit `address`/`port` fields, and TLS may declare `serverName`. The only default cache is for original upstream responses; cache hits still execute configured rules. A query action may locally override its cache policy, but no cache setting makes a source run implicitly.

Use `order` to place groups and keep rule/action array order explicit. The engine sorts groups by integer `order`, then binding name. A fallback is a later rule, for example a primary query with `onError: "continue"` followed by a condition on `lastAction.success` and `response.rcode`. The complete binding-object examples are in [`examples/`](../examples/); they use reserved example domains and require controlled endpoints or replacement before deployment.

`DNS_PATH_KEY`, when set as a Secret, protects the exact route `/<key>/dns-query` before body parsing, rule/source validation or network work. The same path is used by JSON GET. Do not use a bearer token, request header or query parameter for the key. Do not put the path key in a URL committed to source control.

## Validate and roll out

- Run `npm run typecheck` and the relevant workerd tests from [acceptance.md](acceptance.md).
- Confirm no rule without an explicit upstream/ECH/list/attribution operation causes a network request.
- Confirm fallback rules distinguish action failure (`lastAction.success === false`) from a valid DNS response with an unsatisfactory RCODE.
- Confirm required actions terminate; `onError: "continue"` rolls back only the failed action's DNS candidate and retains its failure result/event.
- Confirm environment variables and Secrets are present in the correct Workers Builds environment before routing production queries.
- Deploy only under the operator's own authorization. Local controlled tests do not establish public reachability, account-specific limits, or free-plan CPU compliance.

### Public HTTPS Worker sources

The checked-in runtime flags now include `global_fetch_strictly_public`. Explicit HTTPS sources (DNS, lists and attribution) are fetched through the public Internet front door, including another Worker in the same zone. Without this opt-in flag, same-zone Worker fetches can fail with platform error 1042 or bypass the intended Worker route toward an origin. This was reproduced and corrected on the isolated acceptance deployment; no existing business deployment was changed.

This flag changes routing, not source policy: it does not add a default request, retry, fallback, service binding or TCP exception. Audit explicitly configured own-zone URLs before adopting the updated configuration: they now traverse public routing/security rules and can loop back to the same Worker if misconfigured. Public URLs must not assume private-origin reachability. For private service-to-service traffic, design an explicit authorized service-binding adapter separately rather than assuming that this HTTP configuration supplies one. Outbound raw TCP to Cloudflare IP ranges remains blocked by the platform.

References: [public fetch routing](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public), [error 1042](https://developers.cloudflare.com/workers/observability/errors/), [TCP restrictions](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/).
