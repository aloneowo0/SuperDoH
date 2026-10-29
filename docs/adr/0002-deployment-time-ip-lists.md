# Compile production IP lists during deployment

On 2026-10-29 the user requested moving IP-range source parameters to deployment environment variables and downloading/embedding the lists when deploying. Production list preparation previously depended on remote origins, colo-local Cache API and isolate-local compilation. That added request-path I/O and CPU work even before rules could return a custom answer.

Use build-only `DNS_IP_LIST_SOURCES` to generate versioned, validated, merged range snapshots and embed them in the Worker bundle. Runtime `DNS_IP_LISTS` contains only explicit `embedded` references. Share immutable restored indexes per isolate, never request-scoped I/O. Retain the generic URL-list feature for explicit other configurations, but never treat it as an implicit embedded-source fallback.

Each deployed version owns a fixed snapshot. Refresh requires another deployment; hourly TTL refresh no longer applies. Missing configuration or any invalid/unavailable source fails the build, and missing/invalid embedded references fail runtime configuration. Never publish an empty list, partial generation or stale local artifact as a successful refresh. Existing list matching and resource-limit semantics remain enforced. No conclusion about CPU savings is accepted without measured, sample-qualified evidence.
