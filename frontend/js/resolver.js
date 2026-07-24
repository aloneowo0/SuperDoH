async function resolveDomain(){
  const name=document.getElementById('dns-name').value.trim();
  const type=parseInt(document.getElementById('dns-type').value);
  if(!name){return}
  const r=document.getElementById('results'),t=r.querySelector('tbody');
  t.innerHTML='<tr><td colspan=4 style="color:#999;text-align:center;padding:16px">查询中...</td></tr>';
  try{
    const res=await fetch('/dns-query?name='+encodeURIComponent(name)+'&type='+type,{headers:{'Accept':'application/dns-json'}});
    const data=await res.json();
    t.innerHTML='';
    if(data.Answer){
      data.Answer.forEach(function(a){
        const row=t.insertRow();
        const typeNames={1:'A',28:'AAAA',15:'MX',16:'TXT',5:'CNAME',2:'NS',65:'HTTPS'};
        row.innerHTML='<td>'+a.name+'</td><td>'+(typeNames[a.type]||a.type)+'</td><td>'+a.TTL+'</td><td style="word-break:break-all"><code>'+a.data+'</code></td>';
      });
    }else{
      const rcodes={0:'NOERROR（无记录）',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN（域名不存在）',4:'NOTIMP',5:'REFUSED'};
      t.innerHTML='<tr><td colspan=4 style="color:#999;text-align:center;padding:16px">'+((data.Status in rcodes)?rcodes[data.Status]:'状态码 '+data.Status)+'</td></tr>';
    }
  }catch(e){
    t.innerHTML='<tr><td colspan=4 style="color:#e74c3c;text-align:center;padding:16px">请求失败</td></tr>';
  }
}
document.getElementById('dns-name').addEventListener('keydown',function(e){if(e.key==='Enter')resolveDomain()});
