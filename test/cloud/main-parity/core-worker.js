import { runCore } from './core.js';
export default { async fetch() { return Response.json(await runCore()); } };
