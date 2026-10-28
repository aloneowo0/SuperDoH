// Fixed, short-lived fixture. No arbitrary destinations or outbound requests.
const u16=n=>[n>>>8&255,n&255];
const ech=Uint8Array.from(atob('AD7+DQA6AQAgACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAEAAEAAQALZXhhbXBsZS5jb20AAA=='),c=>c.charCodeAt(0));
export default {async fetch(request,env){
  if(Date.now()>Number(env.EXPIRES))return new Response('Expired',{status:410});
  const path=new URL(request.url).pathname.slice(1);
  if(path==='fail')return new Response('Unavailable',{status:503});
  if(path==='redirect')return new Response(null,{status:302,headers:{Location:'/text'}});
  if(path==='html')return new Response('<html>192.0.2.1</html>',{headers:{'Content-Type':'text/html'}});
  if(path==='utf8')return new Response(new Uint8Array([255]),{headers:{'Content-Type':'text/plain'}});
  if(path==='bad')return new Response('192.0.2.1\nBAD',{headers:{'Content-Type':'text/plain'}});
  if(path==='large')return new Response('192.0.2.1\n'.repeat(100),{headers:{'Content-Type':'text/plain'}});
  if(path==='slow'){await new Promise(resolve=>setTimeout(resolve,250));return new Response('192.0.2.0/24',{headers:{'Content-Type':'text/plain'}});}
  if(['text','text2','json'].includes(path))return new Response(path==='json'?'["192.0.2.0/24","2001:db8::/32"]':'192.0.2.0/24\n2001:db8::/32',{headers:{'Content-Type':path==='json'?'application/json':'text/plain','Cache-Control':'no-store'}});
  if(!['dns-cf','dns-meta','dns-non','dns-negative','ech'].includes(path)||request.method!=='POST')return new Response('Not found',{status:404});
  const b=new Uint8Array(await request.arrayBuffer());
  if(b.length<17||b.length>4096)return new Response('Bad query',{status:400});
  let end=12;while(end<b.length&&b[end]){if(b[end]>63||end+b[end]+1>=b.length)return new Response('Bad query',{status:400});end+=b[end]+1;}end+=5;
  if(end>b.length)return new Response('Bad query',{status:400});
  const type=b[end-4]*256+b[end-3];let records=[];
  if(path!=='dns-negative') {
    if(path==='ech')records=[{type:65,data:[0,1,0,0,5,...u16(ech.length),...ech]}];
    else if(type===1)records=[{type:1,data:path==='dns-meta'?[157,240,1,1]:path==='dns-cf'?[104,16,1,1]:[192,0,2,9]}];
    else if(type===28)records=[{type:28,data:[32,1,13,184,...Array(12).fill(0)]}];
    else records=[{type:65,data:[0,1,0,0,1,0,3,2,104,50]}];
  }
  const wire=Uint8Array.from([b[0],b[1],129,path==='dns-negative'?131:128,0,1,...u16(records.length),0,0,0,0,...b.slice(12,end),...records.flatMap(rr=>[192,12,...u16(rr.type),0,1,0,0,0,60,...u16(rr.data.length),...rr.data])]);
  return new Response(wire,{headers:{'Content-Type':'application/dns-message','Cache-Control':'no-store'}});
}};
