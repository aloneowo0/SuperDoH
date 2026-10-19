import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runSuite } from './suite.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const meta = JSON.parse(await fs.readFile(path.join(root, 'fixtures/meta.json'), 'utf8'));
const certificates = JSON.parse(await fs.readFile(path.join(root, 'fixtures/certificates.json'), 'utf8'));
const result = await runSuite({ meta, certificates });
console.log(`ECH probe Node offline tests: ${result.passed} passed`);
