/** DoH HTTP boundary: parse one request into a validated DNS query. */

import { buildQueryWireId, decodeBase64Url, parseQtype, validateDnsQuery } from './dns-lib.js';

const DNS_MEDIA_TYPE = 'application/dns-message';
const MAX_DNS_MESSAGE_SIZE = 65535;

function hasMediaType(value, expected) {
  return typeof value === 'string' && value.split(';', 1)[0].trim().toLowerCase() === expected;
}

function wantsDnsJson(request) {
  const accept = request.headers.get('Accept') || '';
  return accept.toLowerCase().split(',').some(function(value) {
    return value.trim().split(';', 1)[0] === 'application/dns-json';
  });
}

function clientError(status, error, headers) {
  return { error: { status, error, headers: headers || {} } };
}

export async function parseDohRequest(request) {
  const wantsJson = wantsDnsJson(request);
  if (request.method !== 'GET' && request.method !== 'POST') {
    return clientError(405, 'method_not_allowed', { Allow: 'GET, POST' });
  }

  try {
    if (request.method === 'POST') {
      if (!hasMediaType(request.headers.get('Content-Type'), DNS_MEDIA_TYPE)) {
        return clientError(415, 'unsupported_media_type');
      }
      const contentLength = Number(request.headers.get('Content-Length'));
      if (Number.isInteger(contentLength) && contentLength > MAX_DNS_MESSAGE_SIZE) {
        return clientError(413, 'dns_message_too_large');
      }
      const body = await request.arrayBuffer();
      if (body.byteLength > MAX_DNS_MESSAGE_SIZE) return clientError(413, 'dns_message_too_large');
      return { body, queryMeta: validateDnsQuery(body), wantsJson };
    }

    const url = new URL(request.url);
    const dns = url.searchParams.get('dns');
    const name = url.searchParams.get('name');
    if (dns !== null && name !== null) return clientError(400, 'ambiguous_query');
    if (dns !== null) {
      const bytes = decodeBase64Url(dns);
      if (bytes.byteLength > MAX_DNS_MESSAGE_SIZE) return clientError(413, 'dns_message_too_large');
      const body = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
      return { body, queryMeta: validateDnsQuery(body), wantsJson };
    }
    if (name === null || name === '') return clientError(400, 'missing_name_or_type');
    const idBytes = new Uint16Array(1);
    crypto.getRandomValues(idBytes);
    const body = buildQueryWireId(name, parseQtype(url.searchParams.get('type')), idBytes[0]);
    return { body, queryMeta: validateDnsQuery(body), wantsJson };
  } catch (_) {
    return clientError(400, 'invalid_dns_query');
  }
}
