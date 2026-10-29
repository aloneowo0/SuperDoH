import { compileList, createIpListStore, type LoadOptions } from '../index.js';
const index = compileList(new TextEncoder().encode('192.0.2.0/24'), 'text', 16, 1024);
const matches: boolean = index.contains('192.0.2.1');
const options: LoadOptions = { source: 'https://example.com/list', format: 'text', maxEntries: 16, maxBytes: 1024, maxStates: 16, maxStateBytes: 4096, load: async () => new Uint8Array() };
void createIpListStore().load(options);
void matches;

const snapshot: import('../index.js').CompiledSnapshot = (await import('../index.js')).exportSnapshot(index, 12);
const restored: import('../index.js').Index = (await import('../index.js')).restoreSnapshot(snapshot, 16, 1024, 4096);
void restored;
