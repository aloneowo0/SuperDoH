# SuperDoH

SuperDoH is a single-configuration DNS-over-HTTPS Worker. Its production behavior is configured with runtime environment bindings and declarative JSON rule groups. There is no built-in upstream, automatic routing, user-supplied JavaScript/TypeScript, configuration UI, or browser-based policy wizard.

## What it does

- Serves standard RFC 8484 DNS wire-format requests at `/dns-query` over HTTPS (GET or POST).
- Runs ordered `DNS_RULE_*` rule groups. Conditions inspect the current query/response and trusted client, edge, or explicitly enriched response-address properties.
- Uses explicitly named HTTPS, TCP, or TLS upstreams only when a `queryUpstream` or `queryEch` action asks for one.
- Supports an opt-in DNS JSON GET adapter through `DNS_JSON=true`; it uses the same rule pipeline as wire-format requests.
- Provides explicit DNS response-address attribution, maintained domain lists, and ECH acquisition/application actions. These do not run implicitly during condition matching.

The detailed runtime contract, fields, resource limits and failure semantics are in [docs/rules.md](docs/rules.md). Historical behavior and configuration changes are in [docs/migration.md](docs/migration.md); the verification matrix and current blockers are in [docs/acceptance.md](docs/acceptance.md).

## Runtime configuration

Configuration belongs in the Worker environment, not in request parameters or a checked-in JavaScript file. Each `DNS_RULE_*` variable is a complete JSON binding object with an integer `order` and an ordered `rules` array. Groups execute by ascending `order`, then by binding name; rules and their actions execute in array order. All configured branches and references are validated before execution, including unreachable rules.

Common bindings:

| Binding | Purpose |
| --- | --- |
| `DNS_RULE_*` | Ordered conditions and actions |
| `DNS_UPSTREAMS` | Named HTTPS, TCP, or TLS connections; definitions alone do not send requests |
| `DNS_CACHE` | Default policy for cached original upstream responses |
| `DNS_LIMITS` | Bounded request, configuration, list, source and execution budgets |
| `DNS_ADDRESS_SOURCES` | Trusted JSON mappings for explicit response-address attribution |
| `DNS_DOMAIN_LISTS` | Inline or HTTPS-maintained domain data |
| `DNS_JSON` | Opt-in DNS JSON GET endpoint; disabled unless true |
| `DNS_PATH_KEY` | Optional Worker Secret that restricts access to `/<key>/dns-query` |

Sensitive URLs should use a Secret binding and reference its **binding name** through `urlSecret`. The JSON examples use reserved `.example` hostnames and non-secret placeholder values for controlled test setups; replace them with sources you operate before deployment. Never commit real credentials or a real path key.

Small complete binding-object examples:

- [Explicit sequential fallback](examples/fallback.json)
- [Platform client-country selection](examples/client-selection.json)
- [Response-address attribution and matching](examples/attribution.json)
- [Maintained external domain list](examples/domain-list.json)
- [Direct ECHConfigList loading and application](examples/ech-direct.json)
- [ECH lookup from a DNS HTTPS answer](examples/ech-query.json)
- [Authenticated TLS ECH probe and application](examples/ech-probe.json)

There is no hidden default upstream. If a rule pipeline produces no response, the request fails with DNS SERVFAIL; it does not silently query a configured source. An explicit upstream action makes one request to the named source, and only JSON conditions decide whether later actions run.

## HTTP API

The default API accepts standard DNS wire requests:

- `GET /dns-query?dns=<canonical-base64url>` with an acceptable `Accept: application/dns-message` header.
- `POST /dns-query` with `Content-Type: application/dns-message` and a DNS wire body.

The optional JSON adapter is off by default. Set the normal environment binding `DNS_JSON` to boolean `true` (or the exact string `"true"`) and send a GET with `Accept: application/dns-json`, for example:

```text
GET /dns-query?name=www.example.com&type=A&cd=false
Accept: application/dns-json
```

`name` is required; `type` is an optional DNS type name or decimal code (default A); `cd` is optional and accepts only `true` or `false`. Duplicate, unknown or mixed wire/JSON query parameters are rejected. The response uses `application/dns-json` and the DNS library's `toDnsJson` representation; this is not a provider-specific JSON compatibility guarantee. A valid DNS failure is represented in its DNS status, while invalid HTTP/JSON parameters use an HTTP error object. Both entry formats share the same rules, cache, actions, authorization and DNSSEC cleanup.

If `DNS_PATH_KEY` is configured as a Secret, both entry formats use the same exact path form `/<configured-key>/dns-query`; the secret value is not a query parameter or request header. Authentication happens before reading a query or doing configuration/network work.

## Deploying with Cloudflare Workers Builds

1. Connect the repository in the Cloudflare Dashboard under Workers Builds. The repository root contains `wrangler.jsonc`, whose entry is `src/worker.js`.
2. Configure the project install/build/deploy commands for the checked-in Wrangler configuration (for example, install with `npm ci` and deploy with `npx wrangler deploy` where the Build environment is authorized). There is no application configuration download step or UI-generated file.
3. Add ordinary JSON bindings and Secret bindings in the Worker's Dashboard/Workers Builds environment settings. Use separate Production and Preview values as appropriate. Keep these values in the Worker environment, not in Git; code builds do not need to embed the bindings.
4. The checked-in Wrangler config sets `keep_vars: true` to retain Dashboard-managed runtime variables on code deployment. Build-only variables are separate and are **not** available to the running Worker. Secrets are not deleted by ordinary deployments. After connecting a build or changing environments, verify that ordinary variables and Secrets remain configured for the intended Worker environment. Preview and Production may have different values. Do not put Secret values in `wrangler.jsonc`, these examples, command-line arguments or build logs.
5. Test a controlled source and the expected Worker route before directing clients to it. This repository does not claim a deployment or online free-plan CPU acceptance.

The project plans around a 5,120-byte per-variable configuration budget and a 64-binding ordinary-variable/Secret budget; Cloudflare platform and account limits remain authoritative. Keep rule groups small and use a named external domain-list source for larger data rather than packing the list into a rule binding.

## Local checks

```sh
npm ci
npm run typecheck
npm test
```

`npm test` runs the standard type, workerd, DNS and ECH library regression suites. The opt-in independent ECH/OpenSSL handshake requires an ECH-capable OpenSSL build; the Windows system OpenSSL lacks the required ECH commands, but an isolated WSL build passed the public Worker and generic-library interop suites on 2026-10-22. See [docs/acceptance.md](docs/acceptance.md) for the pinned build, reproduction commands and outstanding online acceptance.

Platform references: [runtime/build variables](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/), [Wrangler variable preservation](https://developers.cloudflare.com/workers/wrangler/configuration/), [Workers limits](https://developers.cloudflare.com/workers/platform/limits/).

The bounded measurement runner and offline telemetry report CLI are documented in [docs/online-acceptance.md](docs/online-acceptance.md). Their manifest example is separate from Worker bindings; running online still requires explicit resource and measurement approval.
