import { executeQuery } from '../src/index.js';
import type { Action, Condition } from '../src/rules/types.js';

const when: Condition = { field: 'query.name', op: 'suffix', value: 'example.com' };
const action: Action = { type: 'answer', records: [{ name: 'example.com', type: 'A', ttl: 60, rdata: { A: { addr: '192.0.2.1' } } }] };
const result = await executeQuery(new Uint8Array(), { DNS_RULE_A: { order: 0, rules: [{ when, actions: [action] }] } });
const response: Uint8Array = result.response;
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
    const disposition: 'terminated' | 'rolled_back_continue' = event.disposition;
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

// @ts-expect-error User function factories are no longer exported.
const { defineCondition, defineAction } = await import('../src/index.js');
// @ts-expect-error Custom function references are not JSON conditions.
const customWhen: Condition = { custom: { name: 'old' } };
// @ts-expect-error Custom function references are not basic actions.
const customAction: Action = { type: 'custom', name: 'old' };
// @ts-expect-error User registries are not execution options.
executeQuery(new Uint8Array(), {}, { extensions: {} });
// @ts-expect-error Extension registry types have been removed.
type RemovedRegistry = import('../src/rules/types.js').ExtensionRegistry;
void [defineCondition, defineAction, customWhen, customAction];

const upstreamAction: Action = { type: 'queryUpstream', upstream: 'A', onError: 'continue' };
const { handleRequest } = await import('../src/worker.js');
const httpResponse: Promise<Response> = handleRequest(new Request('https://example.test/dns-query'), {}, { signal: new AbortController().signal });
// @ts-expect-error Cancellation must be an actual AbortSignal.
executeQuery(new Uint8Array(), {}, { signal: 'cancel' });
void [upstreamAction, httpResponse];

const namedQuery: Action = { type: 'queryUpstream', upstream: 'standard' };
const sources: Record<string, import('../src/rules/types.js').UpstreamConfig> = { backup: { transport: 'https', urlSecret: 'BACKUP_URL' } };
// @ts-expect-error Policy group types have been removed.
type RemovedGroup = import('../src/rules/types.js').UpstreamGroupConfig;
// @ts-expect-error Legacy policy selection is not a request action.
const oldGroup: Action = { type: 'queryUpstream', group: 'standard' };
// @ts-expect-error Requests must explicitly name their source.
const missingSource: Action = { type: 'queryUpstream' };
// @ts-expect-error An upstream cannot supply both URL sources.
const ambiguousUpstream: import('../src/rules/types.js').UpstreamConfig = { transport: 'https', url: 'https://test/', urlSecret: 'SECRET' };
// @ts-expect-error TCP uses address/port, not HTTPS URL fields.
const unsupportedTransport: import('../src/rules/types.js').UpstreamConfig = { transport: 'tcp', url: 'https://test/' };
void [namedQuery, sources, oldGroup, missingSource, ambiguousUpstream, unsupportedTransport];

const recent: Condition = { all: [
  { field: 'lastAction.success', op: 'eq', value: false },
  { field: 'lastAction.code', op: 'in', value: ['UPSTREAM_FAILED', 'UPSTREAM_TIMEOUT'] },
  { field: 'lastAction.action', op: 'gte', value: 0 },
] };
if (result.lastAction) {
  const success: boolean = result.lastAction.success;
  // @ts-expect-error Action results cannot be changed by callers.
  result.lastAction.success = false;
  // @ts-expect-error Action locations are deeply read-only.
  result.lastAction.location.action = 2;
  void success;
}
// @ts-expect-error Last-action boolean conditions do not accept text values.
const badResultCondition: Condition = { field: 'lastAction.success', op: 'eq', value: 'false' };
// @ts-expect-error Runtime results are not caller-supplied state.
executeQuery(new Uint8Array(), {}, { lastAction: { success: true } });
void [recent, badResultCondition];

const tcpSource: import('../src/rules/types.js').UpstreamConfig = { transport: 'tcp', address: 'resolver.example', port: 53 };
// @ts-expect-error Ports must be numbers.
const badTcpPort: import('../src/rules/types.js').UpstreamConfig = { transport: 'tcp', address: 'resolver.example', port: '53' };
void [tcpSource, badTcpPort];

const tlsSource: import('../src/rules/types.js').UpstreamConfig = { transport: 'tls', address: '192.0.2.53', serverName: 'resolver.example' };
// @ts-expect-error TLS does not expose an authentication downgrade.
const insecureTls: import('../src/rules/types.js').UpstreamConfig = { transport: 'tls', address: 'resolver.example', verifyCertificate: false };
void [tlsSource, insecureTls];

const cachePolicy: import('../src/rules/types.js').CachePolicy = { read: true, write: false, maxTtl: 60 };
const cacheAction: Action = { type: 'setCache', read: false, maxTtl: 0 };
const requestCache: Action = { type: 'queryUpstream', upstream: 'primary', cache: { write: false } };
// @ts-expect-error Cache keys are derived from source and DNS identity, never caller supplied.
const unsafeCacheKey: Action = { type: 'queryUpstream', upstream: 'primary', cache: { key: 'same' } };
// @ts-expect-error Cache flags are booleans, not strings.
const badCacheFlag: Action = { type: 'setCache', read: 'yes' };
void [cachePolicy, cacheAction, requestCache, unsafeCacheKey, badCacheFlag];

const removeAAAA: Action = { type: 'removeRecords', where: { field: 'item.type', op: 'eq', value: 'AAAA' } };
const replaceAddress: Action = { type: 'replaceRecords', where: { field: 'item.ip', op: 'cidr', value: '192.0.2.0/24' }, records: [] };
const selectiveTtl: Action = { type: 'setTtl', ttl: 7, where: { field: 'item.section', op: 'eq', value: 'authority' } };
const extraRecords: Action = { type: 'addRecords', section: 'additional', records: [] };
// @ts-expect-error Deletion requires an explicit selector.
const implicitRemoval: Action = { type: 'removeRecords' };
// @ts-expect-error Record actions cannot carry user callbacks.
const functionSelector: Action = { type: 'removeRecords', where: () => true };
// @ts-expect-error Record section names are explicit.
const invalidRecordSection: Action = { type: 'addRecords', section: 'header', records: [] };
void [removeAAAA, replaceAddress, selectiveTtl, extraRecords, implicitRemoval, functionSelector, invalidRecordSection];

const enrichment: Action = { type: 'enrichAddresses', source: 'geo', onError: 'continue' };
const addressSource: import('../src/rules/types.js').AddressSourceConfig = {
  urlSecret: 'GEO_URL', ipParam: 'ip', cacheTtl: 60,
  fields: { ip: ['query', 'ip'], asn: ['network', 'asn'], country: ['location', 'country'] },
};
// @ts-expect-error Address sources require a named JSON source, not a function.
const invalidEnrichment: Action = { type: 'enrichAddresses', source: () => ({ asn: 1 }) };
// @ts-expect-error Field mappings are paths, not executable selectors.
const invalidMapping: import('../src/rules/types.js').AddressSourceFields = { ip: 'query.ip' };
void [enrichment, addressSource, invalidEnrichment, invalidMapping];

const listCondition: Condition = { field: 'query.name', op: 'inList', value: 'selected' };
const domainList: import('../src/rules/types.js').DomainListConfig = { urlSecret: 'LIST_URL', format: 'text', refreshIntervalMs: 60000 };
void [listCondition, domainList];

const directEchAction: Action = { type: 'loadEch', config: 'base64' };
const dnsEchAction: Action = { type: 'queryEch', name: 'source.example', upstream: 'primary', cache: { maxTtl: 30 } };
const applyEchAction: Action = { type: 'applyEch', where: { field: 'item.name', op: 'suffix', value: 'example.com' } };
void [directEchAction, dnsEchAction, applyEchAction];

const probeAction: Action = { type: 'probeEch', options: { hostname: 'example.com', serverName: 'example.com', verifyCertificate: true, alpn: ['h2'], cacheTtl: 60 } };
// @ts-expect-error Native cancellation signals are never accepted in JSON probe options.
const badProbe: Action = { type: 'probeEch', options: { hostname: 'example.com', signal: new AbortController().signal } };
void [probeAction, badProbe];

const parsedTrustRoots: (roots: readonly (string | number[])[]) => Uint8Array[] = (await import('../lib/ech-probe/index.js')).parseTrustAnchors;
void parsedTrustRoots;
