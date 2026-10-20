import { executeQuery } from '../src/index.js';
import type { Action, Condition } from '../src/rules/types.js';

const when: Condition = { field: 'query.name', op: 'suffix', value: 'example.com' };
const action: Action = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } }] };
const result = executeQuery(new Uint8Array(), { DNS_RULE_A: { order: 0, rules: [{ when, actions: [action] }] } });
const response: Uint8Array | null = result.response;
const termination: 'completed' | 'stopped' | 'returned' = result.termination;
result.query.questions[0].name = 'changed.example';
// @ts-expect-error The original query is deeply read-only.
result.originalQuery.questions[0].name = 'changed.example';
// @ts-expect-error The original questions array is read-only.
result.originalQuery.questions.push({ name: 'changed.example', rtype: 1, class: 1 });
// @ts-expect-error Query types are numbers or names, not booleans.
const invalid: Condition = { field: 'query.type', op: 'eq', value: false };
void [response, termination, invalid];
