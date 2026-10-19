import {
  FLAGS, TYPES, buildQuery, buildResponse, parseMessage, encodeMessage,
  createMessage, decodeRdata, encodeRdata, setEdns, setEcs, getEcs,
  setSvcParam, getSvcParam, setRcode, matchResponse, extractIPs,
  type DnsRecord, type NativeRdataMap,
} from '../index.js';

const query = buildQuery('example.com', TYPES.A, 123, { class: 1 });
const message = parseMessage(query);
message.answers.push({ name: 'example.com', rtype: TYPES.A, class: 1, ttl: 60, rdata: { A: { addr: '1.2.3.4' } } });
for (const rr of message.answers) if ('A' in rr.rdata) rr.rdata.A.addr = '8.8.8.8';
message.flags |= FLAGS.QR;
setEdns(message, { udp_payload_size: 1232 });
setEcs(message, { address: '2001:db8::1', source_prefix: 56 });
const ecs = getEcs(message);
const prefix: number | undefined = ecs?.source_prefix;
setRcode(message, 16);
const output: Uint8Array = encodeMessage(message, { invalidate_rrsets: [{ name: 'example.com', rtype: TYPES.A, class: 1 }] });
matchResponse(output, query);
extractIPs(output);
const https: DnsRecord = { name: 'example.com', rtype: 65, class: 1, ttl: 60, rdata: { Https: { priority: 1, target: '.', params: [] } } };
setSvcParam(https, 1, ['h2', 'h3']);
getSvcParam(https, 1);
const record = decodeRdata(1, [1, 2, 3, 4]);
encodeRdata(1, record);
buildResponse(query, { rcode: 3 });
createMessage({ additional: [https] });
const key: NativeRdataMap['Dnskey'] = { flags: 257, protocol: 3, algorithm: 15, public_key: 'AQID' };
void prefix; void key;
// @ts-expect-error IP fields are strings, not numbers.
const invalid: DnsRecord = { name: '.', rtype: 1, class: 1, ttl: 0, rdata: { A: { addr: 123 } } };
void invalid;
