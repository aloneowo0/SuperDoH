/** Native domain 0.12.3 record models. Binary conventions are preserved from upstream. */
export interface NativeRdataMap {
  A: { addr: string; };
  Aaaa: { addr: string; };
  Ns: { nsdname: string; };
  Md: { madname: string; };
  Mf: { madname: string; };
  Cname: { cname: string; };
  Mb: { madname: string; };
  Mg: { madname: string; };
  Mr: { newname: string; };
  Ptr: { ptrdname: string; };
  Dname: { dname: string; };
  Soa: { expire: number; minimum: number; mname: string; refresh: number; retry: number; rname: string; serial: number; };
  Hinfo: { cpu: string; os: string; };
  Minfo: { emailbx: string; rmailbx: string; };
  Mx: { exchange: string; preference: number; };
  Txt: Array<string>;
  Rp: { mbox: string; txt: string; };
  Srv: { port: number; priority: number; target: string; weight: number; };
  Naptr: { flags: string; order: number; preference: number; regexp: string; replacement: string; services: string; };
  Ds: { algorithm: number; digest: string; digest_type: number; key_tag: number; };
  Sshfp: { algorithm: number; fingerprint: Array<number>; fingerprint_type: number; };
  Ipseckey: { algorithm: number; gateway: 'None' | { Ipv4: { addr: string } } | { Ipv6: { addr: string } } | { Name: string }; gateway_type: number; key: Array<number>; precedence: number; };
  Rrsig: { algorithm: number; expiration: number; inception: number; key_tag: number; labels: number; original_ttl: number; signature: string; signer_name: string; type_covered: string; };
  Nsec: { next_name: string; types: Array<string>; };
  Dnskey: { algorithm: number; flags: number; protocol: number; public_key: string; };
  Nsec3: { flags: number; hash_algorithm: number; iterations: number; next_owner: string; salt: string; types: Array<string>; };
  Nsec3param: { flags: number; hash_algorithm: number; iterations: number; salt: string; };
  Tlsa: { data: Array<number>; matching_type: number; selector: number; usage: number; };
  Cds: { algorithm: number; digest: string; digest_type: number; key_tag: number; };
  Cdnskey: { algorithm: number; flags: number; protocol: number; public_key: string; };
  Openpgpkey: { key: Array<number>; };
  Zonemd: { algo: number; digest: Array<number>; scheme: number; serial: number; };
  Caa: { flags: number; tag: string; value: Array<number>; };
}
