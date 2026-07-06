/**
 * DoH Proxy v2 - Homepage (Chinese / English)
 * Exports: serveHomepage(request, upstreamNames), serveHomepageEn(request, upstreamNames)
 */

// ── Chinese HTML template ──────────────────────────────────────────

const HTML_CN = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DoH 服务</title>
<style>
:root{--primary-color:#f6821f;--secondary-color:#3b88c3;--dark-color:#404041;--light-color:#f4f4f4}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;line-height:1.6;color:#333;background:var(--light-color)}
.container{max-width:900px;margin:0 auto;padding:0 20px}
header{background:var(--primary-color);color:#fff;text-align:center;padding:1.5rem 0;margin-bottom:1.5rem}
header h1{font-size:2rem;margin-bottom:.25rem}
.subtitle{font-size:.95rem;opacity:.9}
.lang-switch{float:right;color:#fff;text-decoration:none;font-weight:700;padding:.2rem .7rem;border:2px solid #fff;border-radius:4px;font-size:.9rem}
.lang-switch:hover{background:#fff;color:var(--primary-color)}
section{background:#fff;margin:1.2rem 0;padding:1.2rem 1.5rem;border-radius:5px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h2{color:var(--primary-color);margin-bottom:.7rem;border-bottom:1px solid #eee;padding-bottom:.4rem;font-size:1.15rem}
h3{color:var(--secondary-color);margin:.7rem 0 .3rem;font-size:1rem}
p{margin:.4rem 0}
ul,ol{margin:.5rem 0 .5rem 1.5rem}
li{margin-bottom:.25rem}
code{font-family:'SF Mono',Menlo,monospace;font-size:.88em}
pre{background:#f8f8f8;padding:.8rem;border-radius:4px;overflow-x:auto;margin:.5rem 0;border-left:3px solid var(--primary-color)}
pre code{font-size:.82em;line-height:1.5}
.endpoint{display:inline-block;background:#fff3e8;padding:.1rem .5rem;margin:.1rem .15rem;border-radius:3px;font-family:monospace;font-size:.9em;border:1px solid #fdd5b0}
.btn{display:inline-block;background:var(--primary-color);color:#fff;padding:.5rem 1.2rem;border:none;border-radius:4px;cursor:pointer;font-weight:700;font-size:.9rem;transition:background .2s}
.btn:hover{background:#e67e22}
footer{text-align:center;padding:1.5rem 0;background:var(--dark-color);color:#fff;margin-top:1.5rem;font-size:.88rem}
footer a{color:var(--primary-color)}
.resolver-form{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.resolver-form input{flex:1;min-width:160px;padding:8px 12px;border:1px solid #ddd;border-radius:4px;font-size:.9rem}
.resolver-form select{padding:8px;border:1px solid #ddd;border-radius:4px;font-size:.9rem;background:#fff}
.resolver-form input:focus,.resolver-form select:focus{outline:none;border-color:var(--primary-color)}
#results{margin-top:12px}
#results table{width:100%;border-collapse:collapse}
#results th{border-bottom:2px solid var(--primary-color);padding:6px 10px;text-align:left;font-size:.85em}
#results td{padding:6px 10px;border-bottom:1px solid #eee;font-size:.88em}
#results tr:hover td{background:#fafafa}
.caps-table{width:100%;border-collapse:collapse;margin-top:8px}
.caps-table th{background:#f5f5f5;border-bottom:2px solid var(--primary-color);padding:6px 10px;text-align:left;font-size:.85em}
.caps-table td{padding:6px 10px;border-bottom:1px solid #eee;font-size:.88em}
.caps-table .yes{color:#27ae60;font-weight:700}
.caps-table .no{color:#e74c3c}
.row{display:flex;gap:20px;flex-wrap:wrap}
.row>section{flex:1;min-width:280px}
@media(max-width:600px){header h1{font-size:1.5rem}section{padding:1rem}.lang-switch{float:none;display:inline-block;margin-top:.5rem}.row{flex-direction:column}}
</style>
</head>
<body>
<header>
  <div class="container">
    <a href="/en" class="lang-switch">EN</a>
    <h1>SuperDoH</h1>
    <p class="subtitle">轻量级 DNS over HTTPS 代理</p>
  </div>
</header>
<div class="container">
  <section>
    <h2>项目介绍</h2>
    <p>基于 Cloudflare Workers 的 DoH 代理，支持多上游并发查询和 EDNS 客户端子网注入。请求路径决定路由目标，完整保留原始查询参数。</p>
    <h3>主要功能</h3>
    <ul>
      <li><strong>多上游并发</strong>：/dns-query 端点同时查询所有上游，返回最快响应</li>
       <li><strong>EDNS 支持</strong>：自动智能补全 ECS 客户端子网</li>
      <li><strong>灵活路由</strong>：每个上游独立路径，可单独使用</li>
      <li><strong>零配置部署</strong>：基于 Cloudflare Worker/Pages，无需服务器</li>
    </ul>
  </section>

  <section>
    <h2>可用端点</h2>
    <p>__UPSTREAM_LIST__</p>
  </section>

  <div class="row">
  <section>
    <h2>上游 EDNS 能力</h2>
    <p style="font-size:.85em;color:#666">部署时自动探测或手动标记</p>
    __EDNS_CAPS_TABLE__
  </section>
  <section>
    <h2>域名解析</h2>
    <div class="resolver-form">
      <input id="dns-name" type="text" placeholder="输入域名，如 example.com">
      <select id="dns-type">
        <option value="1">A (IPv4)</option>
        <option value="28">AAAA (IPv6)</option>
        <option value="15">MX</option>
        <option value="16">TXT</option>
        <option value="5">CNAME</option>
        <option value="2">NS</option>
        <option value="65">HTTPS</option>
      </select>
      <button class="btn" onclick="resolveDomain()">解析</button>
    </div>
    <div id="results"><table><thead><tr><th>名称</th><th>类型</th><th>TTL</th><th>数据</th></tr></thead><tbody></tbody></table></div>
  </section>
</div>

  <section>
    <h2>使用方法</h2>
    <p>支持 POST application/dns-message、GET ?name=&type= 和 Accept: application/dns-json（RFC 8484 透传）。</p>
    <h3>并发模式</h3>
    <pre><code>curl "https://__HOST__/dns-query?name=example.com&type=A"
# 全部上游并发，返回最快有效响应</code></pre>
    <h3>单上游查询</h3>
    <pre><code>curl "https://__HOST__/google/dns-query?name=example.com"
curl "https://__HOST__/cloudflare_Public/dns-query?name=example.com"</code></pre>
    <p style="font-size:.85em;color:#666;margin-top:.8rem">更多上游可通过编辑 <code>.env</code> 启用（设置 <code>=true</code> 后运行 <code>npm run build</code>）</p>
  </section>
</div>
<footer>
  <div class="container">
    <p>MIT License</p>
  </div>
</footer>
<script>
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
        var row=t.insertRow();
        var typeNames={1:'A',28:'AAAA',15:'MX',16:'TXT',5:'CNAME',2:'NS',65:'HTTPS'};
        row.innerHTML='<td>'+a.name+'</td><td>'+(typeNames[a.type]||a.type)+'</td><td>'+a.TTL+'</td><td style="word-break:break-all"><code>'+a.data+'</code></td>';
      });
    }else{
      var rcodes={0:'NOERROR（无记录）',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN（域名不存在）',4:'NOTIMP',5:'REFUSED'};
      t.innerHTML='<tr><td colspan=4 style="color:#999;text-align:center;padding:16px">'+((data.Status in rcodes)?rcodes[data.Status]:'状态码 '+data.Status)+'</td></tr>';
    }
  }catch(e){
    t.innerHTML='<tr><td colspan=4 style="color:#e74c3c;text-align:center;padding:16px">请求失败</td></tr>';
  }
}
document.getElementById('dns-name').addEventListener('keydown',function(e){if(e.key==='Enter')resolveDomain()});
</script>
</body>
</html>`;

// ── English HTML template ──────────────────────────────────────────

const HTML_EN = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DoH Service</title>
<style>
:root{--primary-color:#f6821f;--secondary-color:#3b88c3;--dark-color:#404041;--light-color:#f4f4f4}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;line-height:1.6;color:#333;background:var(--light-color)}
.container{max-width:900px;margin:0 auto;padding:0 20px}
header{background:var(--primary-color);color:#fff;text-align:center;padding:1.5rem 0;margin-bottom:1.5rem}
header h1{font-size:2rem;margin-bottom:.25rem}
.subtitle{font-size:.95rem;opacity:.9}
.lang-switch{float:right;color:#fff;text-decoration:none;font-weight:700;padding:.2rem .7rem;border:2px solid #fff;border-radius:4px;font-size:.9rem}
.lang-switch:hover{background:#fff;color:var(--primary-color)}
section{background:#fff;margin:1.2rem 0;padding:1.2rem 1.5rem;border-radius:5px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h2{color:var(--primary-color);margin-bottom:.7rem;border-bottom:1px solid #eee;padding-bottom:.4rem;font-size:1.15rem}
h3{color:var(--secondary-color);margin:.7rem 0 .3rem;font-size:1rem}
p{margin:.4rem 0}
ul,ol{margin:.5rem 0 .5rem 1.5rem}
li{margin-bottom:.25rem}
code{font-family:'SF Mono',Menlo,monospace;font-size:.88em}
pre{background:#f8f8f8;padding:.8rem;border-radius:4px;overflow-x:auto;margin:.5rem 0;border-left:3px solid var(--primary-color)}
pre code{font-size:.82em;line-height:1.5}
.endpoint{display:inline-block;background:#fff3e8;padding:.1rem .5rem;margin:.1rem .15rem;border-radius:3px;font-family:monospace;font-size:.9em;border:1px solid #fdd5b0}
.btn{display:inline-block;background:var(--primary-color);color:#fff;padding:.5rem 1.2rem;border:none;border-radius:4px;cursor:pointer;font-weight:700;font-size:.9rem;transition:background .2s}
.btn:hover{background:#e67e22}
footer{text-align:center;padding:1.5rem 0;background:var(--dark-color);color:#fff;margin-top:1.5rem;font-size:.88rem}
footer a{color:var(--primary-color)}
.resolver-form{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.resolver-form input{flex:1;min-width:160px;padding:8px 12px;border:1px solid #ddd;border-radius:4px;font-size:.9rem}
.resolver-form select{padding:8px;border:1px solid #ddd;border-radius:4px;font-size:.9rem;background:#fff}
.resolver-form input:focus,.resolver-form select:focus{outline:none;border-color:var(--primary-color)}
#results{margin-top:12px}
#results table{width:100%;border-collapse:collapse}
#results th{border-bottom:2px solid var(--primary-color);padding:6px 10px;text-align:left;font-size:.85em}
#results td{padding:6px 10px;border-bottom:1px solid #eee;font-size:.88em}
#results tr:hover td{background:#fafafa}
.caps-table{width:100%;border-collapse:collapse;margin-top:8px}
.caps-table th{background:#f5f5f5;border-bottom:2px solid var(--primary-color);padding:6px 10px;text-align:left;font-size:.85em}
.caps-table td{padding:6px 10px;border-bottom:1px solid #eee;font-size:.88em}
.caps-table .yes{color:#27ae60;font-weight:700}
.caps-table .no{color:#e74c3c}
.row{display:flex;gap:20px;flex-wrap:wrap}
.row>section{flex:1;min-width:280px}
@media(max-width:600px){header h1{font-size:1.5rem}section{padding:1rem}.lang-switch{float:none;display:inline-block;margin-top:.5rem}.row{flex-direction:column}}
</style>
</head>
<body>
<header>
  <div class="container">
    <a href="/" class="lang-switch">中文</a>
    <h1>SuperDoH</h1>
    <p class="subtitle">DNS over HTTPS on Cloudflare Workers</p>
  </div>
</header>
<div class="container">
  <section>
    <h2>Introduction</h2>
    <p>A Cloudflare Worker based DoH proxy supporting multi-upstream concurrent queries and EDNS client-subnet injection. Request path determines the upstream target, preserving all original query parameters.</p>
    <h3>Key Features</h3>
    <ul>
      <li><strong>Multi-upstream race</strong>: /dns-query endpoint queries all upstreams concurrently, returns the fastest valid response</li>
      <li><strong>EDNS control</strong>: automatically injects ECS client-subnet for geo-optimized resolution</li>
      <li><strong>Flexible routing</strong>: Each upstream at its own dedicated path</li>
      <li><strong>Zero-config deploy</strong>: Cloudflare Worker/Pages, no server maintenance</li>
    </ul>
  </section>

  <section>
    <h2>Available Endpoints</h2>
    <p>__UPSTREAM_LIST__</p>
  </section>

  <div class="row">
  <section>
    <h2>Upstream EDNS Capabilities</h2>
    <p style="font-size:.85em;color:#666">Auto-detected or manually configured</p>
    __EDNS_CAPS_TABLE__
  </section>
  <section>
    <h2>DNS Lookup</h2>
    <div class="resolver-form">
      <input id="dns-name" type="text" placeholder="Enter domain, e.g. example.com">
      <select id="dns-type">
        <option value="1">A (IPv4)</option>
        <option value="28">AAAA (IPv6)</option>
        <option value="15">MX</option>
        <option value="16">TXT</option>
        <option value="5">CNAME</option>
        <option value="2">NS</option>
        <option value="65">HTTPS</option>
      </select>
      <button class="btn" onclick="resolveDomain()">Lookup</button>
    </div>
    <div id="results"><table><thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Data</th></tr></thead><tbody></tbody></table></div>
  </section>
</div>

  <section>
    <h2>Usage</h2>
    <p>Supports POST application/dns-message, GET ?name=&type=, and Accept: application/dns-json (RFC 8484 passthrough).</p>
    <h3>Concurrent mode</h3>
    <pre><code>curl "https://__HOST__/dns-query?name=example.com&type=A"
# Queries all upstreams, returns fastest response</code></pre>
    <h3>Single upstream</h3>
    <pre><code>curl "https://__HOST__/google/dns-query?name=example.com"
curl "https://__HOST__/cloudflare_Public/dns-query?name=example.com"</code></pre>
    <p style="font-size:.85em;color:#666;margin-top:.8rem">Enable more upstreams by editing <code>.env</code> (set <code>=true</code> then run <code>npm run build</code>)</p>
  </section>
</div>
<footer>
  <div class="container">
    <p>MIT License</p>
  </div>
</footer>
<script>
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
        var row=t.insertRow();
        var typeNames={1:'A',28:'AAAA',15:'MX',16:'TXT',5:'CNAME',2:'NS',65:'HTTPS'};
        row.innerHTML='<td>'+a.name+'</td><td>'+(typeNames[a.type]||a.type)+'</td><td>'+a.TTL+'</td><td style="word-break:break-all"><code>'+a.data+'</code></td>';
      });
    }else{
      var rcodes={0:'NOERROR（无记录）',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN（域名不存在）',4:'NOTIMP',5:'REFUSED'};
      t.innerHTML='<tr><td colspan=4 style="color:#999;text-align:center;padding:16px">'+((data.Status in rcodes)?rcodes[data.Status]:'状态码 '+data.Status)+'</td></tr>';
    }
  }catch(e){
    t.innerHTML='<tr><td colspan=4 style="color:#e74c3c;text-align:center;padding:16px">请求失败</td></tr>';
  }
}
document.getElementById('dns-name').addEventListener('keydown',function(e){if(e.key==='Enter')resolveDomain()});
</script>
</body>
</html>`;

// ── Shared helpers ─────────────────────────────────────────────────

function buildUpstreamList(names) {
  const entries = names.map((n) => '<span class="endpoint">/' + n + '/dns-query</span>').join(' ');
  return entries || '<em>none</em>';
}

function inject(html, host, upstreams, names) {
  return html
    .replaceAll('__HOST__', host)
    .replace('__UPSTREAM_LIST__', buildUpstreamList(names))
    .replace('__EDNS_CAPS_TABLE__', buildCapsTable(upstreams));
}

function buildCapsTable(upstreams) {
  if (!upstreams || Object.keys(upstreams).length === 0) return '<em>none</em>';
  let rows = '<table class="caps-table"><thead><tr><th>Upstream</th><th>ECS</th></tr></thead><tbody>';
  for (const [name, cfg] of Object.entries(upstreams)) {
    const ecs = cfg.ecs ? '<span class="yes">\u2705</span>' : '<span class="no">\u2716</span>';
    rows += `<tr><td><strong>${name}</strong></td><td>${ecs}</td></tr>`;
  }
  rows += '</tbody></table>';
  rows += '<p style="font-size:.78em;color:#888;margin-top:6px">ECS = EDNS Client-Subnet（地理位置优化 / geo-optimized resolution）</p>';
  return rows;
}

// ── Exports ────────────────────────────────────────────────────────

/**
 * Serve Chinese homepage.
 * @param {Request} request
 * @param {object} upstreams  UPSTREAMS config object
 * @returns {Response}
 */
export function serveHomepage(request, upstreams, names) {
  const host = new URL(request.url).host;
  return new Response(inject(HTML_CN, host, upstreams, names), {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=utf-8' },
  });
}

export function serveHomepageEn(request, upstreams, names) {
  const host = new URL(request.url).host;
  return new Response(inject(HTML_EN, host, upstreams, names), {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=utf-8' },
  });
}
