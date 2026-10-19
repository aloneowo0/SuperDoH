import { bytes, Cursor, extensions, fail } from './internal/bytes.js';
export { EchProbeError } from './internal/bytes.js';

function base64(data) {
  let text = '';
  for (let i = 0; i < data.length; i += 4096) text += String.fromCharCode(...data.subarray(i, i + 4096));
  return btoa(text);
}

/** Parses configuration structure only; does not establish identity, validity or acceptance. */
export function parseEchConfigList(input) {
  const data = bytes(input);
  if (data.length > 65537) fail('LIMIT', 'ECHConfigList exceeds its uint16 vector size');
  const c = new Cursor(data), list = new Cursor(c.vec16());
  c.end();
  if (!list.remaining) fail('MALFORMED', 'ECHConfigList must not be empty');
  const configs = [];
  while (list.remaining) {
    const version = list.uint16(), contents = list.vec16();
    if (version !== 0xfe0d) {
      configs.push({ version, known: false, contents });
      continue;
    }
    const cfg = new Cursor(contents);
    const configId = cfg.uint8(), kemId = cfg.uint16(), publicKey = cfg.vec16();
    if (!publicKey.length || (kemId === 0x20 && publicKey.length !== 32)) fail('MALFORMED', 'Invalid ECH public key length');
    const suites = new Cursor(cfg.vec16()), cipherSuites = [];
    if (!suites.remaining || suites.remaining % 4) fail('MALFORMED', 'Invalid ECH cipher suites');
    while (suites.remaining) cipherSuites.push({ kdfId: suites.uint16(), aeadId: suites.uint16() });
    const maximumNameLength = cfg.uint8(), name = cfg.vec8();
    const publicName = String.fromCharCode(...name);
    const labels = publicName.split('.');
    if (!publicName.length || publicName.length > 253 || !labels.every(label =>
      label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)) || /^(?:[0-9]+|0x[0-9a-f]*)$/i.test(labels.at(-1))) {
      fail('MALFORMED', 'ECH public_name must be an ASCII DNS hostname');
    }
    const extra = extensions(cfg.vec16());
    cfg.end();
    configs.push({ version, known: true, contents, configId, kemId, publicKey, cipherSuites,
      maximumNameLength, publicName, extensions: Array.from(extra, ([type, value]) => ({ type, data: value })) });
  }
  return { bytes: data.slice(), base64: base64(data), configs };
}
