import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Certificate, fromBER } from '../vendor/pki-core.js';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const source = resolve(root, 'vendor/cacert.pem');
const output = resolve(root, 'internal/trust-store.js');
if (process.argv.slice(2).some(arg => arg !== '--check') || process.argv.length > 3) throw new Error('Usage: build-trust-store.mjs [--check]');
// Use the pinned local snapshot only; rebuilding must never silently refresh trust.
const pem = await readFile(source, 'utf8');
const blocks = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)];
if (!blocks.length || blocks.length > 512) throw new Error('Invalid pinned CA bundle count');
let totalBytes = 0;
const index = blocks.map(match => {
  const certificate = match[1].replace(/\s/g, '');
  const der = Buffer.from(certificate, 'base64');
  if (der.toString('base64') !== certificate || !der.length || der.length > 65536) throw new Error('Invalid pinned CA DER encoding');
  totalBytes += der.length;
  const parsed = fromBER(der);
  if (parsed.offset !== der.length) throw new Error('Invalid pinned CA DER');
  const cert = new Certificate({ schema: parsed.result });
  if (!Buffer.from(cert.toSchema().toBER(false)).equals(der)) throw new Error('Noncanonical pinned CA DER');
  return { subject: Buffer.from(cert.subject.valueBeforeDecode).toString('base64'), certificate };
});
if (totalBytes > 2 * 1024 * 1024) throw new Error('Pinned CA bundle exceeds byte budget');
const snapshotDate = pem.match(/Certificate data from Mozilla as of: ([^\r\n]+)/)?.[1] ?? 'unknown';
const sha256 = createHash('sha256').update(pem).digest('hex');
const embeddedPem = blocks.map(match => match[0]).join('\n');
const js = `// Mozilla CA snapshot distributed by curl.se; date: ${snapshotDate}\n// Source: https://curl.se/ca/cacert.pem\n// SHA-256: ${sha256}\n// License: MPL-2.0 (Mozilla CA Certificate Store)\nexport const TRUST_STORE_METADATA = Object.freeze({ source: 'https://curl.se/ca/cacert.pem', snapshotDate: ${JSON.stringify(snapshotDate)}, sha256: '${sha256}', license: 'MPL-2.0' });\n// This is a static trust-anchor snapshot; no runtime network, OCSP, CRL, or CT policy is included.\nexport const DEFAULT_CA_PEM = ${JSON.stringify(embeddedPem)};\n// Subject DER is a candidate-selection hint, never proof of trust. Keep every matching root.\nexport const DEFAULT_CA_INDEX = Object.freeze(${JSON.stringify(index)}.map(entry => Object.freeze(entry)));\n`;
if (process.argv.includes('--check')) {
  if (await readFile(output, 'utf8') !== js) throw new Error('Generated trust store is stale; rebuild from the pinned snapshot');
  console.log(`Checked internal/trust-store.js (${sha256}, ${snapshotDate})`);
} else {
  await writeFile(output, js);
  console.log(`Wrote internal/trust-store.js (${sha256}, ${snapshotDate})`);
}
