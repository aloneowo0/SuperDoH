import * as dns from '../index.js';

export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname === '/views') {
        const atomic = dns.createMessage();
        const before = JSON.stringify(atomic);
        try { dns.setEdns(atomic, { udp_payload_size: 1232, flags: 65536 }); } catch (_) {}
        if (JSON.stringify(atomic) !== before) throw new Error('failed edit was not atomic');
        const query = dns.buildQuery('example.com', 1, 0x4242);
        const storage = new Uint8Array(query.length + 20); storage.set(query, 7);
        const first = dns.parseMessage(storage.subarray(7, 7 + query.length));
        const second = dns.parseMessage(new DataView(storage.buffer, 7, query.length));
        if (first.id !== second.id) throw new Error('view mismatch');
        first.answers.push({ name: 'example.com', rtype: 65280, class: 1, ttl: 1, rdata: { Raw: new Uint8Array([0, 255, 192, 12]) } });
        const out = dns.parseMessage(dns.encodeMessage(first));
        return Response.json({ id: out.id, raw: out.answers[0].rdata.Raw });
      }
      if (url.pathname === '/op') {
        const { op, args = [] } = await request.json();
        if (!Object.hasOwn(dns, op) || typeof dns[op] !== 'function') throw new Error('unknown test operation');
        const value = dns[op](...args);
        return new Response(JSON.stringify(value, (_key, v) => v instanceof Uint8Array ? Array.from(v) : v), { headers: { 'Content-Type': 'application/json' } });
      }
      if (request.method === 'POST') return Response.json(dns.parseMessage(await request.arrayBuffer()));
      const wire = dns.buildQuery(url.searchParams.get('name') || 'x.com', Number(url.searchParams.get('type') || 65), 0x4242);
      return Response.json({ ...dns.parseMessage(wire), wire: Array.from(wire) });
    } catch (error) {
      return Response.json({ error: String(error) }, { status: 400 });
    }
  },
};
