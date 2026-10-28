import meta from '../../../lib/ech-probe/test/fixtures/meta.json';
export const META_ECH = meta.base64;
const bytes=Uint8Array.from(atob(META_ECH),c=>c.charCodeAt(0));
const length=((bytes[4]<<8)|bytes[5])+4;
const entry=Uint8Array.from([length>>8,length&255,...bytes.slice(2,2+length)]);
export const CF_ECH=btoa(String.fromCharCode(...entry));
export const scenarios=['empty','cname','alias','existing','negative','refused','echfail','secondary','preferred','prefempty','prefbad','prefnx','preferr','non-target','meta-ip','native-cf'];
