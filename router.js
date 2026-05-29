import { UPSTREAMS, MIX_PROVIDER } from './config.js';

const VALID_PROVIDERS = new Set([...Object.keys(UPSTREAMS), MIX_PROVIDER]);

export function resolveRoute(request) {
  const url = new URL(request.url);
  const { pathname, search } = url;

  // Homepage routes
  if (pathname === '/' || pathname === '/index.html' || pathname === '/en') {
    return { home: true };
  }

  if (pathname === '/health') {
    return { health: true };
  }

  // Legacy v1 compat: bare /query-dns without a provider prefix
  if (pathname === '/query-dns') {
    return { provider: MIX_PROVIDER, queryString: search };
  }

  // /<provider>/query-dns pattern
  const match = pathname.match(/^\/([^/]+)\/query-dns$/);
  if (!match) return { home: true };

  const provider = match[1];
  if (!VALID_PROVIDERS.has(provider)) return { error: 'unknown_provider' };

  return {
    provider,
    queryString: search,
  };
}
