# ECH probe CPU and verification policy

## What was localized

The default trust store has 121 certificates. Previously, PEM decoding performed full DER validation and discarded the parsed record; preparation then parsed every DER certificate again to populate its private cache. The optimization preserves the fully validated records instead: 242 parses become 121 on the initial default-root preparation. It does not remove canonical DER checks, signature-algorithm consistency checks, input bounds, ownership isolation or mutation checks. Explicit custom roots benefit from the same single-parse path. Default roots already had an isolate-local cache; this is not a new global cache.

This is a reproducible local CPU contributor, not a complete attribution of the historical online 451 ms CPU invocation. Those original platform measurements remain unchanged.

## CPU evidence, not elapsed sample weights

`node test/cpu-local.mjs` is an opt-in Windows diagnostic requiring `pwsh` and the locked development dependencies. It bundles the production HTTP entry, locates exactly one `workerd.exe` child of its own Node process, and reads Windows `TotalProcessorTime` before and after public DoH requests. It accepts no arguments, uses only intercepted HTTP sources and loopback TCP, makes 23 local requests, and disposes its runtime and sockets.

The counter covers the **whole process and all its threads**, including runtime work and GC. It is coarse (observed increments were 15.625 ms), includes counter-query boundaries, and can exceed request wall time because the process has multiple threads and the windows differ. A reported zero does **not** mean the request used no CPU or passed a 10 ms limit. It is neither function CPU nor Cloudflare quota CPU. The separate `wallMs` is elapsed request/body time. No profiler `timeDeltas` are summed as CPU.

Three alternating controlled pairs changed only certificate preparation in the bundle, before the verification-default change. Initial authenticated-alert process CPU values were:

- Before: 281.250, 281.250, 265.625 ms.
- Single-parse: 234.375, 203.125, 171.875 ms.

The limited observations support reducing duplicated work; they do not establish a production percentage saving. Warm results and other modes have counter noise and must not be treated as precise per-request CPU measurements.

After applying the requested default policy, one complete 23-request diagnostic measured first-use default-unverified alert at **31.250 ms** versus explicit default-root verification at **156.250 ms**. The unverified path no longer prepares the full root store. Both connections intentionally receive a TLS alert and return DNS SERVFAIL; these are **not successful ECH handshake CPU measurements**. Immediate and one-second-wait sources also run with DNS cache reads/writes disabled; the wait increases wall time without adding one second of process CPU.

Allowlisted observations, source hashes and measurement limits are in [the evidence JSON](results/2026-10-22/cpu-optimization-2026-10-23.json). Prototype/count instrumentation is not a production testing hook. The diagnostic remains outside the default test suite.

## Requested verification policy

At the user's explicit request on 2026-10-23, the adapter and public library now default `verifyCertificate` to **false**. This replaces the former authenticated default; it is a policy choice, not proof that optimization alone met the Free budget.

```json
{ "type": "probeEch", "options": { "hostname": "example.com" } }
```

The default skips CA trust-chain and hostname validation and produces an **unauthenticated** library result. It still performs TLS key exchange, record AEAD, CertificateVerify, server Finished and client Finished processing. It cannot establish the server's identity. The core logs `verification_disabled` even when a cached result is used; it never labels that mode as authenticated.

To retain identity authentication:

```json
{ "type": "probeEch", "options": { "hostname": "example.com", "verifyCertificate": true } }
```

Custom `caCertificates` require explicit `verifyCertificate: true`; omission does not silently enable authentication or ignore custom roots. Invalid configurations still fail in preflight, including unreachable actions. Verified failures do not trigger an unverified retry. The normalized verification policy remains in the cache identity, preventing unverified results from satisfying verified lookups. Library and core configuration types distinguish default/false from explicit true.

## Validation and limits

New regression cases check byte-identical PEM/bounded DER views, independent output ownership, mutated prepared/default anchors, the omitted-option unverified complete handshake, and the explicit-verification requirement for custom CA before connecting. The default-behavior tests were observed failing before the policy change. Existing negative CV/Finished, chain/hostname, cancellation, byte-limit and socket-cleanup tests remain in place.

Full regression passed: 238 application/tool tests, 130 DNS tests, 112 ECH offline tests and typechecking. The independent ECH-capable OpenSSL rerun was not performed because the WSL command was declined; earlier interop results are historical, not validation of this change. No deployment, account change or online request was made. Online Free acceptance is **not established** by these local measurements.
