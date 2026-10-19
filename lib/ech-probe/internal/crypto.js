import { concat, u16, fail } from './bytes.js';

export async function hash(data) { return new Uint8Array(await crypto.subtle.digest('SHA-256', data)); }
export async function hmac(key, data) {
  const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, data));
}

// TLS 1.3 labels in this probe need at most one SHA-256 HKDF block.
export async function expandLabel(secret, name, context, length) {
  const label = new TextEncoder().encode('tls13 ' + name);
  if (length < 1 || length > 32 || label.length > 255 || context.length > 255) fail('LIMIT', 'Unsupported HKDF label size');
  const info = concat(u16(length), new Uint8Array([label.length]), label, new Uint8Array([context.length]), context);
  return (await hmac(secret, concat(info, new Uint8Array([1])))).slice(0, length);
}

export async function handshakeKeys(shared, transcript) {
  const empty = new Uint8Array(), zeros = new Uint8Array(32);
  const earlySecret = await hmac(zeros, zeros);
  const derived = await expandLabel(earlySecret, 'derived', await hash(empty), 32);
  const handshakeSecret = await hmac(derived, shared);
  const transcriptHash = await hash(transcript);
  const serverHandshakeSecret = await expandLabel(handshakeSecret, 's hs traffic', transcriptHash, 32);
  const clientHandshakeSecret = await expandLabel(handshakeSecret, 'c hs traffic', transcriptHash, 32);
  const masterDerived = await expandLabel(handshakeSecret, 'derived', await hash(empty), 32);
  const masterSecret = await hmac(masterDerived, zeros);
  const server = await trafficKeys(serverHandshakeSecret, 'decrypt');
  const client = await trafficKeys(clientHandshakeSecret, 'encrypt');
  // Keep key/iv at the top level for compatibility with the original helper.
  return { key: server.key, iv: server.iv, server, client, earlySecret, handshakeSecret,
    serverHandshakeSecret, clientHandshakeSecret, masterSecret };
}

export async function trafficKeys(secret, usage) {
  const empty = new Uint8Array();
  const rawKey = await expandLabel(secret, 'key', empty, 16);
  const iv = await expandLabel(secret, 'iv', empty, 12);
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, [usage]);
  rawKey.fill(0);
  return { key, iv, secret };
}

export async function applicationKeys(masterSecret, transcriptHash) {
  const serverSecret = await expandLabel(masterSecret, 's ap traffic', transcriptHash, 32);
  const clientSecret = await expandLabel(masterSecret, 'c ap traffic', transcriptHash, 32);
  return { server: await trafficKeys(serverSecret, 'decrypt'), client: await trafficKeys(clientSecret, 'encrypt') };
}

export async function verifyFinished(trafficSecret, transcriptHash, verifyData) {
  const rawKey = await expandLabel(trafficSecret, 'finished', new Uint8Array(), 32);
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  rawKey.fill(0);
  return crypto.subtle.verify('HMAC', key, verifyData, transcriptHash);
}

export async function finishedVerifyData(trafficSecret, transcriptHash) {
  const key = await expandLabel(trafficSecret, 'finished', new Uint8Array(), 32);
  return hmac(key, transcriptHash);
}

export function nonce(iv, sequence) {
  const out = iv.slice();
  for (let i = 11; i >= 4; i--) { out[i] ^= Number(sequence & 255n); sequence >>= 8n; }
  return out;
}
