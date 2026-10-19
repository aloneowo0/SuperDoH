# Vendored cryptography and trust data

- `pki-core.js`: browser-targeted, self-contained ESM bundle of the fixed packages in `manifest.json`. Exact dependency versions and npm integrity hashes are in `../package-lock.json`. Rebuild with `npm ci` and `npm run build:vendor` from this library directory. Package notices are in `licenses/`.
- `cacert.pem`: unmodified curl/Mozilla CA extract. Its source URL, snapshot date and SHA-256 are recorded in `../internal/trust-store.js`. The runtime imports the generated static JS, not this PEM file. Run `npm run build:trust-store` to regenerate from the checked-in snapshot; the script only downloads if that file is absent. To update, explicitly replace and review the snapshot, regenerate, rerun tests and deploy.
- Mozilla CA data is distributed under MPL-2.0. License text: `licenses/mozilla-ca-MPL-2.0.txt` (from the SPDX license-list-data text copy). Original terms: https://www.mozilla.org/MPL/2.0/ . Certificate data source: https://curl.se/ca/cacert.pem . This snapshot is not a browser's complete CT, revocation, or root-program policy implementation.
- Tests use their own private CA and signing keys under `../test/fixtures`; none is part of the runtime default root set.

Build scripts may use Node.js and curl. The runtime bundle does not require these tools or Node compatibility mode.
