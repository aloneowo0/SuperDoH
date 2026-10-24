# ECH library CPU diagnosis — 2026-10-24

## Finding

**X.509/ASN.1 certificate parsing, object construction and canonical DER reencoding are the clearest JavaScript hotspots in the successful local handshake.** ECDSA verification and byte concatenation are not the first optimization targets supported by these measurements. CertificateVerify parses the entire leaf even when CA authentication is disabled; authenticated mode parses that leaf for chain validation and again for CertificateVerify.

No production implementation was changed. This diagnoses the library directly, not the application DNS/rule adapter, and does not establish public Meta CPU cost or Workers Free acceptance.

## Feedback loop and scope

The run used an isolated Linux copy, workerd **1.20261019.1**, compatibility date **2026-10-19**, explicit Node compatibility opt-outs and an independent loopback OpenSSL 4.2.0-dev ECH server. Dependencies were reused only after exact root lockfile comparison. No public DNS/ECH source, account profiling or deployment was used.

The existing four library interoperability cases passed first: successful true/false handshakes, wrong-hostname rejection and rejection of the fixture by the unchanged public root set. The diagnostic entry then called `probeEch` directly, checking status, `authenticated`, `handshakeComplete`, nonempty retry configs and the expected public name for every success.

Three successful modes were measured:

- `default-off`: omitted authentication option, preserving the actual default.
- `custom-ca`: explicit true and the local fixture CA supplied as PEM on each call.
- `fixture-default-ca`: explicit true using the complete pinned root index **plus one test-only fixture root**, substituted only in the isolated bundle. This exercises the lazy default-store path; it is not authentication of the fixture by real public roots or a production trust-store change.

There were **870 successful diagnostic TLS handshakes**: 30 warmups, 480 in unprofiled CPU batches and 360 in profile batches. The independent uncapped streaming counter observed **873 client Finished records**, including the three successful baseline/interop clients. The original harness's capped textual-log closing count is not used as the total. Local servers and workerd were disposed at completion.

## Unprofiled whole-process CPU

CPU batches ran **before attaching/enabling the profiler**. The unique stable workerd child was found across all Node-thread child lists. Linux utime+stime uses 100 ticks/second: **10 ms counter resolution**. Each policy ran four 40-handshake batches, reversing policy order on alternating rounds.

| Mode | Timed handshakes | Batch mean CPU, ms/handshake | Aggregate mean CPU, ms/handshake |
| --- | ---: | --- | ---: |
| Default off | 160 | 3.00, 2.25, 2.50, 2.50 | **2.5625** |
| True, custom fixture CA | 160 | 5.50, 4.25, 4.25, 4.25 | **4.5625** |
| True, test default index | 160 | 5.00, 4.25, 3.75, 3.75 | **4.1875** |

Controls: 200 empty requests used 120 ms process CPU (0.6 ms/request). Twenty 100 ms timer-wait requests used 30 ms CPU while taking about 2,112 ms wall time. CPU includes all workerd threads, runtime, HTTP/JSON wrapper and GC. Do not subtract controls and call the remainder exact library CPU. These local ECDSA-fixture measurements are not a controlled before/after comparison with earlier application/public runs.

## Successful-handshake stack samples

Two 60-handshake profiles per policy requested V8 sampling at 100 microseconds. Empty and timer-wait profiles provided controls. These are **observed stacks**, not exact per-function CPU milliseconds; native crypto is not fully attributable from JS stacks. Inclusive counts overlap.

| Policy | Non-idle/root observations | `parseDer` inclusive | `verifyCertificateVerify` inclusive | `validateCertificateChain` inclusive |
| --- | ---: | ---: | ---: | ---: |
| Default off | 965 | **316** | 376 | 0 |
| Custom CA true | 2,159 | **908** | 272 | 651 |
| Test default-index true | 1,753 | **676** | 283 | 704 |

`fromBER`, `toBER` and certificate model operations were prominent. Disjoint key-schedule/Finished groups had 120/119/103 observations respectively; buffer-helper groups had only 14/15/12. GC had 23/174/51 observations, consistent with allocation activity but not attribution of every collection to a specific operation. Unknown/program/runtime observations remain unassigned.

The wait control captured nine samples over a roughly 1,072 ms profile window, with a largest gap around 415 ms. Summing sample gaps or treating the window as CPU would give wrong attribution.

## Function-level cost isolation

A separate process ran **2,000 operations per mode** in four alternating-order 500-operation batches. The certificate is **548-byte ECDSA P-256**, not the public Meta certificate. Signature modes verify real valid fixture signatures. Cached-key verification isolates crypto from certificate decoding/key import. Values remain whole-process batch averages, not precise individual call timings.

| Operation | Total CPU for 2,000, ms | Mean CPU per operation, ms |
| --- | ---: | ---: |
| Loop/Promise control | below counter resolution | not measurable |
| `fromBER` plus input copy | 200 | **0.100** |
| Complete `parseDer` | 740 | **0.370** |
| Diagnostic parse without canonical reencode guard | 410 | **0.205** |
| Complete `verifyCertificateVerify` | 880 | **0.440** |
| ECDSA SPKI key import | 20 | **0.010** |
| ECDSA verify, already imported key | 80 | **0.040** |

Full-parse batch means were 0.42/0.36/0.32/0.38 ms; no-canonical diagnostic means were 0.22/0.20/0.20/0.20 ms. The aggregate difference is 0.165 ms per fixture certificate. This supports canonical model reserialization as a meaningful part of parsing cost, not an exact public-request saving prediction.

**The no-canonical variant is only private cost isolation.** It weakens input acceptance and is not a safe replacement, was never used for a handshake and must not be shipped. Production canonical DER, algorithm checks, CertificateVerify, chain/hostname policy and Finished remain intact. Zero counter increments mean below-resolution observations, not zero CPU.

## Source locations and optimization order

1. `lib/ech-probe/internal/certificate.js:43–56`: DER copy/decode, PKI model and strict canonical reencoding; the roundtrip is at lines 51–52.
2. `certificate.js:233` / `:317`, called from `lib/ech-probe/internal/tls.js:227` / `:235`: authenticated chain validation and CertificateVerify parse the leaf separately. A same-handshake immutable parsed-leaf/public-key handoff is the narrowest candidate. Do not cache cross-request authentication results or skip current trust/hostname/validity checks. This cannot remove the one parse in default-off mode and cannot alone be assumed to close the public gap.
3. For the shared/default-off path, investigate avoiding unnecessary full certificate-model/serialization work while retaining equivalent strict input validation and all negative cases. Replacing the canonical roundtrip requires separate design/regression proof; deleting the guard is not acceptable.
4. `lib/ech-probe/internal/crypto.js:4–14`: repeated HMAC imports and key-schedule work are secondary sampled areas. This run does not assign an exact native crypto share.

Custom-vs-default timings also differ in issuer selection; their difference is not an exact isolated root-cache benefit. Buffer copying is not the leading sampled hotspot in this fixture.

## Reproduction and evidence

Ignored diagnostics live in `.acceptance/ech-cpu-20261024/`. In an isolated Linux copy with current locked dependencies and an ECH-capable OpenSSL:

```sh
node /path/to/diagnostics/make-profile.mjs /path/to/isolated-repo
cd /path/to/isolated-repo
ECH_CPU_OUTPUT=/path/to/local-output \
ECH_PROBE_OPENSSL=/path/to/ech-capable/openssl \
node lib/ech-probe/test/cpu-profile-local.mjs
```

Pass `micro-body.txt` as the generator's third argument for the separate function loop. The generated harness must not be deployed. [Sanitized evidence](results/2026-10-24/ech-library-cpu-profile.json) includes all counters, profile summaries, grouping rules, raw-profile hashes and generator/body/analyzer sources. Raw profiles remain ignored locally; filesystem call-frame paths and TLS/key payloads are omitted from published evidence.

**Localization is complete for these fixtures; production optimization and public revalidation were not performed. #25/#7 remain open.** No cloud deployment, new public request, production source edit, commit or push occurred.
