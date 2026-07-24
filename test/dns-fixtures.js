import { buildDNS, buildQueryWireId } from '../dns-lib.js';

export function query(name = 'example.com', type = 1, id = 0x1234) {
  return buildQueryWireId(name, type, id);
}

export function responseFor(queryBody, rdata = [new Uint8Array([1, 2, 3, 4])]) {
  const view = new DataView(queryBody);
  return buildDNS(view.getUint16(0), 'example.com', view.getUint16(queryBody.byteLength - 4), rdata, 60);
}

export function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let text = '';
  for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
