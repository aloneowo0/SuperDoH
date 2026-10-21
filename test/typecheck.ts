import { executeQuery } from '../src/index.js';
import type { Action, Condition } from '../src/rules/types.js';

const when: Condition = { field: 'query.name', op: 'suffix', value: 'example.com' };
const action: Action = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } }] };
const result = await executeQuery(new Uint8Array(), { DNS_RULE_A: { order: 0, rules: [{ when, actions: [action] }] } });
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

const optionalAction: Action = { type: 'setTtl', ttl: 30, onError: 'continue' };
executeQuery(new Uint8Array(), {}, {
  requestId: 'typed-request',
  onEvent(event) {
    const code: string = event.code;
    const disposition: 'terminated' | 'rolled_back_continue' | 'fallback' | 'exhausted' = event.disposition;
    // @ts-expect-error Event identity is immutable.
    event.requestId = 'changed';
    // @ts-expect-error Nested event locations are immutable.
    event.location.group = 'changed';
    void [code, disposition];
  },
});
// @ts-expect-error Failure policy is explicit, not an arbitrary string.
const invalidPolicy: Action = { type: 'return', onError: 'ignore' };
// @ts-expect-error Observers are functions rather than logger binding names.
executeQuery(new Uint8Array(), {}, { onEvent: 'logger' });
void [optionalAction, invalidPolicy];

const networkCondition: Condition = { all: [
  { field: 'client.ip', op: 'cidr', value: '2001:db8::/32' },
  { field: 'client.country', op: 'in', value: ['DE', 'GB'] },
  { collection: 'response.addresses', quantifier: 'any', where: { all: [
    { field: 'item.ip', op: 'cidr', value: '192.0.2.0/24' },
    { field: 'item.asn', op: 'gt', value: 64512 },
  ] } },
] };
executeQuery(new Uint8Array(), {}, { context: {
  client: { ip: '::1', asn: 64512 }, edge: { colo: 'LHR' },
  addresses: { '192.0.2.1': { country: 'DE' } },
} });
// @ts-expect-error Item predicates require a collection binding.
const unboundItem: Condition = { field: 'item.ip', op: 'eq', value: '::1' };
// @ts-expect-error Record items do not have address attribution fields.
const wrongScope: Condition = { collection: 'response.records', quantifier: 'any', where: { field: 'item.asn', op: 'eq', value: 1 } };
// @ts-expect-error Text properties cannot use numeric comparisons.
const wrongComparison: Condition = { field: 'client.country', op: 'gt', value: 1 };
// @ts-expect-error Numeric membership cannot contain booleans.
const wrongMember: Condition = { field: 'client.asn', op: 'in', value: [true] };
void [networkCondition, unboundItem, wrongScope, wrongComparison, wrongMember];

const { defineCondition, defineAction } = await import('../src/index.js');
const customWhen: Condition = { custom: { name: 'minimumTtl', params: { ttl: 10 } } };
const customAction: Action = { type: 'custom', name: 'setTtl', params: 30, onError: 'continue' };
const customResult: Promise<import('../src/rules/types.js').ExecutionResult> = executeQuery(new Uint8Array(), {}, { extensions: {
  conditions: {
    minimumTtl: defineCondition((params: unknown) => {
      if (typeof params !== 'number') throw new Error();
      return params;
    }, async (ctx, minimum) => {
      const n: number = minimum;
      const signal: AbortSignal = ctx.signal;
      // @ts-expect-error Conditions cannot write the current query.
      ctx.query.questions[0].name = 'bad.example';
      if (ctx.response) {
        // @ts-expect-error Conditions cannot mutate answer records.
        ctx.response.answers[0].ttl = 1;
      }
      // @ts-expect-error Original data is deeply readonly.
      ctx.originalQuery.questions[0].name = 'bad.example';
      void signal;
      return (ctx.response?.answers[0]?.ttl ?? 0) >= n;
    }),
  },
  actions: {
    setTtl: defineAction((params: unknown) => {
      if (typeof params !== 'number') throw new Error();
      return params;
    }, async (ctx, ttl) => {
      ctx.query.questions[0].name = 'allowed.example';
      if (ctx.response) ctx.response.answers[0].ttl = ttl;
      // @ts-expect-error Actions cannot mutate original data.
      ctx.originalQuery.questions[0].name = 'bad.example';
      // @ts-expect-error Matching context is not writable action state.
      ctx.context.client.asn = 1;
    }),
  },
} });
// @ts-expect-error Condition functions must return booleans, not truthy values.
defineCondition(() => 1, () => 'yes');
void [customWhen, customAction, customResult];

const upstreamAction: Action = { type: 'queryUpstream', onError: 'continue' };
const { handleRequest } = await import('../src/worker.js');
const httpResponse: Promise<Response> = handleRequest(new Request('https://example.test/dns-query'), {}, { signal: new AbortController().signal });
// @ts-expect-error Cancellation must be an actual AbortSignal.
executeQuery(new Uint8Array(), {}, { signal: 'cancel' });
void [upstreamAction, httpResponse];

const groupQuery: Action = { type: 'queryUpstream', group: 'standard' };
const sources: Record<string, import('../src/rules/types.js').UpstreamConfig> = { backup: { urlSecret: 'BACKUP_URL' } };
const upstreamGroup: import('../src/rules/types.js').UpstreamGroupConfig = { members: ['backup'], accept: customWhen };
// @ts-expect-error Group references must be names.
const wrongGroup: Action = { type: 'queryUpstream', group: 1 };
// @ts-expect-error An upstream cannot supply both URL sources.
const ambiguousUpstream: import('../src/rules/types.js').UpstreamConfig = { url: 'https://test/', urlSecret: 'SECRET' };
void [groupQuery, sources, upstreamGroup, wrongGroup, ambiguousUpstream];
