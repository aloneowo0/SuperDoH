import { mkdir, writeFile, rename, rm } from 'node:fs/promises';
import * as http from 'node:http';
import { buildSnapshots } from './lib/build-ip-lists.js';
http.setGlobalProxyFromEnv?.();
const dir = new URL('../src/generated/', import.meta.url);
await mkdir(dir, { recursive: true });
const moduleFile = new URL('ip-lists.js', dir), manifestFile = new URL('ip-lists.manifest.json', dir);
try {
  const lists = await buildSnapshots(process.env.DNS_IP_LIST_SOURCES);
  const manifest = Object.fromEntries(Object.entries(lists).map(([name, { snapshot, ...meta }]) => [name, { ...meta, entries: snapshot.entries, sourceBytes: snapshot.sourceBytes, intervals: snapshot.ranges.reduce((n, family) => n + family.length, 0) }]));
  await writeFile(new URL('ip-lists.js.tmp', dir), '// Generated at deployment; do not edit.\nexport default ' + JSON.stringify(lists) + ';\n');
  await writeFile(new URL('ip-lists.manifest.json.tmp', dir), JSON.stringify(manifest, null, 2) + '\n');
  await rename(new URL('ip-lists.manifest.json.tmp', dir), manifestFile);
  await rename(new URL('ip-lists.js.tmp', dir), moduleFile);
  console.log(JSON.stringify({ embeddedIpLists: manifest }));
} catch (error) {
  // A failed build must not leave a previous successful module available for publication.
  for (const file of [moduleFile, manifestFile, new URL('ip-lists.js.tmp', dir), new URL('ip-lists.manifest.json.tmp', dir)]) await rm(file, { force: true });
  console.error('IP list build failed:', error?.code ?? error?.name ?? 'BUILD_FAILED');
  process.exitCode = 1;
}
