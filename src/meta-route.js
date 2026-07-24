/** Meta class-based static IP routing — maintained from verified-reachable pool */

// ── Service class → verified exact IPs ──
// Each Meta CDN edge IP serves a specific class of hostnames.
// IPs verified reachable via TCP/443 from China (June 2026).

let _metaExact = null;
let _metaWild = null;

function metaExactMap() {
  if (_metaExact) return _metaExact;
  _metaExact = {
    'facebook.com':           [new Uint8Array([57,144,44,1])],
    'www.facebook.com':       [new Uint8Array([57,144,44,1])],
    'm.facebook.com':         [new Uint8Array([57,144,44,1])],
    'b-graph.facebook.com':   [new Uint8Array([57,144,44,1])],
    'fbsbx.com':              [new Uint8Array([57,144,44,1])],
    'instagram.com':          [new Uint8Array([57,144,44,34])],
    'www.instagram.com':      [new Uint8Array([57,144,44,34])],
    'i.instagram.com':        [new Uint8Array([57,144,44,192])],
    'lookaside.facebook.com': [new Uint8Array([57,144,44,128])],
    'connect.facebook.net':   [new Uint8Array([57,144,44,128])],
    'graph.facebook.com':     [new Uint8Array([157,240,31,16])],
    'edge-mqtt.facebook.com': [new Uint8Array([157,240,31,7])],
    'messenger.com':          [new Uint8Array([57,144,44,141])],
    'www.messenger.com':      [new Uint8Array([57,144,44,141])],
    'threads.net':            [new Uint8Array([57,144,44,192])],
    'www.threads.net':        [new Uint8Array([57,144,44,192])],
    'meta.com':               [new Uint8Array([57,144,44,141])],
    'whatsapp.com':           [new Uint8Array([57,144,45,32])],
    'web.whatsapp.com':       [new Uint8Array([57,144,45,32])],
    'oculus.com':             [new Uint8Array([57,144,45,141])],
    'thefacebook.com':        [new Uint8Array([57,144,44,141])],
  };
  return _metaExact;
}

function metaWildList() {
  if (_metaWild) return _metaWild;
  _metaWild = [
    ['fbcdn.net',       new Uint8Array([57,144,44,128])],
    ['xx.fbcdn.net',    new Uint8Array([57,144,44,128])],
    ['cdninstagram.com',new Uint8Array([57,144,44,192])],
    ['facebook.com',    new Uint8Array([57,144,44,141])],
    ['fb.com',          new Uint8Array([57,144,44,141])],
    ['whatsapp.com',    new Uint8Array([57,144,45,32])],
    ['whatsapp.net',    new Uint8Array([57,144,45,32])],
    ['fbsbx.com',       new Uint8Array([57,144,44,128])],
  ];
  return _metaWild;
}

/**
 * Resolve a Meta domain to known-reachable IPs from the static class map.
 * Returns Uint8Array[] on match, null if domain is not in the map.
 */
export function resolveMetaFromMap(domain) {
  try {
    if (!domain || typeof domain !== 'string') return null;
    const d = domain.trim().toLowerCase().replace(/\.+$/, '');
    if (!d) return null;
    const exact = metaExactMap()[d];
    if (exact) return exact;
    const wild = metaWildList();
    for (let i = 0; i < wild.length; i++) {
      const suffix = wild[i][0];
      if (d === suffix || d.endsWith('.' + suffix)) return [wild[i][1]];
    }
    return null;
  } catch (_) { return null; /* ignore — return null on malformed domain */ }
}
