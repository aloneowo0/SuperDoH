# Valid ECS responses with longer scope

An actual direct IPv6-client production query for `example.com A` returned HTTP 200 with DNS SERVFAIL, whereas an otherwise equivalent explicit ECS `/0` query returned NOERROR and A answers. Response CF-Ray values correlated the normal query with `UPSTREAM_INVALID` in the mandatory base upstream action. A normal `x.com A` query returned an answer but its correlated log showed the same error rolling back an optional CF-address action; successful DNS status alone had hidden that failed branch.

A private cloud replay of the observed client identity isolated the failure: Google ordinary TCP returned a valid NOERROR response with IPv6 ECS source `/56`, scope `/64`, and the matching source subnet. Framing, DNS response matching and parsing succeeded; `checkEcsResponse` rejected the scope solely because it was longer than source.

[RFC 7871 sections 7.2.1 and 7.3.1](https://www.rfc-editor.org/rfc/rfc7871.html#section-7.3.1) permit a scope longer than the supplied source prefix. Such a response can answer the triggering query; it is not a malformed ECS identity. This implementation conservatively excludes it from its shared upstream-response cache rather than adding specialized scope storage or widening client disclosure.

## Fix and safeguards

- Validate response scope against the address-family width, not the supplied source prefix. Keep exact family, source prefix and subnet matching, canonical encoding, and duplicate/malformed ECS rejection.
- Preserve the existing cache refusal for scope longer than source. No cache identity, TTL policy or production cache setting changes.
- Preserve client IPv6 `/56` and IPv4 `/24` disclosure caps, incoming `/0`, and stripping of internally added ECS. Do not retry with a more specific client address.
- Keep all production upstreams on Google `8.8.8.8:53` ordinary TCP; no DoH, TLS or UDP fallback.

## Cloud verification

The maintained `test/cloud/ecs/scope.js` suite is available as `ecs-scope` through the existing Padding-cache cloud check and runner. It has 15 checks: valid IPv4, IPv6 and non-byte source/scope combinations; wrong family/source/subnet and out-of-family scope rejection; full `executeQuery` cache and sanitization checks.

Before the fix, six of those checks failed with `UPSTREAM_INVALID`, including the `/56 -> /64` pipeline. After the fix, all 15 passed. The pipeline uses controlled response bytes through the real upstream parser and validator, with request-local fetch/Cache API instrumentation restored in `finally`: three calls within the same `/56` but different `/64`s perform three upstream requests and zero cache writes for scope `/64`; scope `/56` still performs one upstream request and one cache write.

The original real Google TCP source `/56`, scope `/64` reproducer then passed. Four full production-rule candidate queries with the observed IPv6 context also passed with no failure events: `example.com A`, `www.cloudflare.com HTTPS`, `x.com HTTPS`, and `www.instagram.com HTTPS`.

The cloud replay used its cumulative eight-attempt budget. Two initial direct outer connections failed before HTTP; six subsequent outer invocations used the existing control-plane proxy, while behavior and Google TCP ran in Workers. Expected pre-fix failures remain recorded. Typechecking passed; no local behavioral suites were run. The temporary replay Worker was deleted (API 200). See [sanitized evidence](results/2026-10-29/ecs-response-scope.json).

This fixes the reproduced ECS rejection, not every possible CF-site failure. Local resolver bootstrap, TCP/TLS reachability and site HTTP challenges remain distinct. Candidate DNS tests are not proof of browser navigation success; production activation and actual-entry retests are checked separately after pushing dev. Raw traces, client identity, access path and credentials remain private.
