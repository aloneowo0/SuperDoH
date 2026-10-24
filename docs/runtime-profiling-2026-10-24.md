# Runtime upgrade and CPU profiling — 2026-10-24

## Runtime configuration

- Wrangler: **4.152.0** (previously 4.151.3).
- Deployment and current application tests: compatibility date **2026-10-19** (previously 2026-07-30).
- Actual workerd binary: **1.20261019.1** in Wrangler, application tests and the independently installed ECH library tests. The date follows the supported binary release, not a newer host calendar date.
- Existing `enable_request_signal` and `global_fetch_strictly_public` flags remain. `no_nodejs_compat` and `no_nodejs_compat_v2` explicitly preserve the project's non-Node runtime: dates on/after 2026-08-04 would otherwise enable Node compatibility by default.
- `upload_source_maps: true` explicitly preserves readable function locations for a future deployed profile. This setting does not itself deploy or upload anything.
- No DNS/TLS business logic or authentication policy changed. Earlier measurement reports and deployment evidence retain their historical versions/dates.

### Test harness compatibility

Wrangler 4.152.0 itself uses Miniflare 5.20261019.2-beta. Directly upgrading the fixture harness to that version failed: v5 rejects the old constructor shape, its official converter rejects `modulesRules`, and it cannot convert the custom outbound network/CA fixtures without losing behavior. A temporary conversion adapter was removed rather than weakening those tests.

The application and ECH library therefore retain **Miniflare 4.20260730.0's fixture API**, with an explicit npm override of its workerd dependency to **1.20261019.1** in both package manifests/lockfiles. This is an intentionally tested harness/engine combination, not a claim that Miniflare 4 and 5 have identical APIs. Wrangler retains its own v5 dependency; all three environments execute the same new workerd version. Do not remove the override merely because the fixture API package's date is older.

`npm run test:runtime` verifies the installed engines agree with Wrangler, deployment/test dates agree, source maps are enabled, required flags remain, and a real request sees neither `process` nor `Buffer` globals. Library tests reuse `lib/ech-probe/test/runtime.mjs` to derive a supported date and explicit Node opt-outs.

## Which CPU profiling capability is new?

Cloudflare's [production profiling documentation](https://developers.cloudflare.com/workers/observability/profiling-in-production/) (updated 2026-10-20) describes CPU and allocation profile capture for deployed Workers/Durable Objects using the Dashboard, Cloudflare CLI (`cf`), or API. It does **not** specify a minimum compatibility date. Therefore changing the date alone is not what enables this facility.

- A **CPU profile** helps identify expensive functions/call stacks.
- A **heap profile** samples allocations, not retained memory or a heap snapshot.
- The requested version must already be active and loaded, with representative traffic before/during capture. Capturing does not invoke the application or reconstruct past requests.
- Use the exact deployed version, rather than assuming `latest` means the active version. Availability and rate limits must be checked for the actual target.
- Source maps make the resulting flamegraph readable. Wrangler versions >=4.150.0 upload them by default; this project now declares the setting explicitly.

For an already authorized, active test version, the documented Cloudflare CLI command shape is:

```sh
cf workers versions profile "$VERSION_ID" \
  --worker-id "$WORKER_ID" \
  --duration-ms 5000 \
  --profile-type cpu > worker-cpu.pprof
```

This is a **future authorized operation**, not a command run by this upgrade. It uses the separate `cf` CLI, not an invented Wrangler subcommand. Profile capture and representative online traffic need their own operational authorization; the previous run's unused readiness contingencies do not authorize a new scenario. Existing stopped test Workers were not reactivated.

## Local tools

Run from the repository root:

```sh
npx wrangler check startup
```

This reports local bundle sizes and a sampled startup profile and writes `worker-startup.cpuprofile`, viewable in Chrome DevTools or VS Code. It profiles module startup, **not** a successful ECH request.

For request paths, use [Wrangler DevTools profiling](https://developers.cloudflare.com/workers/observability/dev-tools/cpu-usage/): start `npx wrangler dev`, open DevTools with `D`, record the Profiler while sending representative local requests, and stop/save the profile. The existing `node test/profile-local.mjs` diagnostic automates a bounded local stack-sampling loop with fixed answers, early TLS alerts, lists and an I/O-wait control; it is not a successful public-handshake benchmark.

Do not treat `performance.now()`, profiler elapsed windows or the sum of sampling time gaps spanning I/O as exact Workers quota CPU. Use platform invocation CPU for quota measurements. Local stack profiles locate work; they do not by themselves prove the public Free 10 ms requirement was met.

## Verification boundary

The upgrade is local only: no deployment, profile capture against the account, new public DNS/ECH test traffic, business Worker/DNS/route change, commit or push. Dependency downloads are tool installation, not acceptance samples. The final regression and independent-interoperability results are recorded in [the acceptance status](acceptance.md).

References: [compatibility flags](https://developers.cloudflare.com/workers/configuration/compatibility-flags/), [startup command](https://developers.cloudflare.com/workers/wrangler/commands/workers/#startup), [production profiling](https://developers.cloudflare.com/workers/observability/profiling-in-production/), [DevTools CPU profiling](https://developers.cloudflare.com/workers/observability/dev-tools/cpu-usage/).

Dependency audit note: the final root install reports four development-tool dependency entries (three high, one moderate), through Miniflare/Sharp/Undici/Wrangler. They are not resolved by this runtime upgrade. No force audit fix or unrelated downgrade was applied; this is not a clean-audit claim.

The newer local ingress also supplies a loopback `CF-Connecting-IP` when omitted. A thin test-only `test/metadata-request-worker.js` removes that injected header for the explicit missing-IP negative case before calling unchanged `handleRequest`; the negative assertion remains enforced. The first full Windows run caught this fixture mismatch. No production metadata policy was relaxed.
