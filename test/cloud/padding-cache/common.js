import { readBody } from '../../../src/doh/body.js';

export async function authorized(request, env) {
  const expiry = Number(env.EXPIRES);
  if (!env.KEY || !Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now() + 3600000) return false;
  const supplied = new TextEncoder().encode(new URL(request.url).pathname.split('/')[1] ?? '');
  const expected = new TextEncoder().encode(env.KEY);
  return supplied.length === expected.length && crypto.subtle.timingSafeEqual(supplied, expected);
}
export const boundedBody = request => readBody(request.body, 4096, request.signal);
export const check = (ok, label) => { if (!ok) throw Error(label); };
export const pad = (data = Array(80).fill(0)) => ({ code: 12, data });
export const ecs = (network = 100) => ({ code: 8, data: [0, 1, 24, 0, 198, 51, network] });
export const cookie = () => ({ code: 10, data: [1, 2, 3, 4, 5, 6, 7, 8] });
export const unknown = () => ({ code: 65001, data: [9] });
