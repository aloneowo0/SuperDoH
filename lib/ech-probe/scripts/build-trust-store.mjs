import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const source = resolve(root, 'vendor/cacert.pem');
const output = resolve(root, 'internal/trust-store.js');
await mkdir(resolve(root, 'vendor'), { recursive: true });
let pem;
try { pem = await readFile(source, 'utf8'); }
catch {
  const { stdout } = await execFileAsync('curl', ['-fLsS', 'https://curl.se/ca/cacert.pem'], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, env: process.env });
  pem = stdout;
  await writeFile(source, pem);
}
if (!pem.includes('-----BEGIN CERTIFICATE-----')) throw new Error('Downloaded CA bundle does not contain PEM certificates');
const snapshotDate = pem.match(/Certificate data from Mozilla as of: ([^\r\n]+)/)?.[1] ?? 'unknown';
const sha256 = createHash('sha256').update(pem).digest('hex');
const embeddedPem = [...pem.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].map(match => match[0]).join('\n');
const js = `// Mozilla CA snapshot distributed by curl.se; date: ${snapshotDate}\n// Source: https://curl.se/ca/cacert.pem\n// SHA-256: ${sha256}\n// License: MPL-2.0 (Mozilla CA Certificate Store)\nexport const TRUST_STORE_METADATA = Object.freeze({ source: 'https://curl.se/ca/cacert.pem', snapshotDate: ${JSON.stringify(snapshotDate)}, sha256: '${sha256}', license: 'MPL-2.0' });\n// This is a static trust-anchor snapshot; no runtime network, OCSP, CRL, or CT policy is included.\nexport const DEFAULT_CA_PEM = ${JSON.stringify(embeddedPem)};\n`;
await writeFile(output, js);
console.log(`Wrote internal/trust-store.js (${sha256}, ${snapshotDate})`);
