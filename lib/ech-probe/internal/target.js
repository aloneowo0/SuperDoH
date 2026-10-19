export function dnsName(value, field) {
  if (typeof value !== 'string') throw new TypeError(`${field} must be a DNS hostname`);
  const name = value.endsWith('.') ? value.slice(0, -1).toLowerCase() : value.toLowerCase();
  const labels = name.split('.');
  if (!name.length || name.length > 253 || !labels.every(label => label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) || /^(?:[0-9]+|0x[0-9a-f]*)$/i.test(labels.at(-1))) {
    throw new TypeError(`${field} must be an ASCII DNS hostname, not an IP address or URL`);
  }
  return name;
}

export function target(options) {
  if (typeof options.hostname !== 'string' || !options.hostname.length) throw new TypeError('hostname is required');
  let hostname = options.hostname, ip = false;
  if (/^[0-9]+(?:\.[0-9]+){3}$/.test(hostname)) {
    if (!hostname.split('.').every(part => Number(part) <= 255 && String(Number(part)) === part)) throw new TypeError('Invalid IPv4 hostname');
    ip = true;
  } else if (hostname.includes(':') || hostname.includes('[') || hostname.includes(']')) {
    const literal = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
    if (!/^[0-9a-f:.]+$/i.test(literal)) throw new TypeError('Invalid IPv6 hostname');
    try { hostname = new URL(`http://[${literal}]/`).hostname.slice(1, -1); }
    catch { throw new TypeError('Invalid IPv6 hostname'); }
    ip = true;
  } else hostname = dnsName(hostname, 'hostname');
  if (ip && options.serverName === undefined) throw new TypeError('serverName is required when connecting to an IP address');
  const serverName = dnsName(options.serverName === undefined ? hostname : options.serverName, 'serverName');
  const port = options.port === undefined ? 443 : options.port;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new RangeError('port must be an integer in 1..65535');
  const alpn = options.alpn === undefined ? [] : options.alpn;
  if (!Array.isArray(alpn)) throw new TypeError('alpn must be an array of ASCII protocol names');
  const protocols = [];
  let size = 0;
  for (const name of alpn) {
    if (typeof name !== 'string' || !/^[\x01-\x7f]{1,255}$/.test(name) || protocols.includes(name)) {
      throw new TypeError('ALPN names must be unique nonempty ASCII strings of at most 255 bytes');
    }
    size += name.length + 1;
    if (size > 12000) throw new RangeError('ALPN list exceeds the single-record ClientHello budget');
    protocols.push(name);
  }
  return { hostname, port, serverName, alpn: protocols };
}
