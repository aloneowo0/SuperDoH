// Test configuration follows the installed workerd release, not the host clock.
// Newer workerd rejects compatibility dates newer than the binary understands.
export function runtimeInfo(require) {
  const miniflare = require('miniflare/package.json').version;
  const workerd = require('workerd/package.json').version;
  const date = /\.(\d{4})(\d{2})(\d{2})\./.exec(workerd);
  if (!date) throw new Error(`Cannot determine supported compatibility date from workerd ${workerd}`);
  return { miniflare, workerd, compatibilityDate: `${date[1]}-${date[2]}-${date[3]}` };
}
