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
#targets{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
#targets label{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border:1px solid #ddd;border-radius:4px;cursor:pointer;font-size:.88rem;transition:all .15s}
#targets label:hover{border-color:var(--primary-color);background:#fff8f0}
#targets label.checked{background:var(--primary-color);color:#fff;border-color:var(--primary-color)}
#results{margin-top:12px;display:none}
#results table{width:100%;max-width:420px;border-collapse:collapse}
#results th{border-bottom:2px solid var(--primary-color);padding:6px 10px;text-align:left;font-size:.85em}
#results td{padding:6px 10px;border-bottom:1px solid #eee;font-size:.88em}
#results tr:hover td{background:#fafafa}
@media(max-width:600px){header h1{font-size:1.5rem}section{padding:1rem}.lang-switch{float:none;display:inline-block;margin-top:.5rem}}
</style>
</head>
<body>
<header>
  <div class="container">
    <a href="/en" class="lang-switch">EN</a>
    <h1>DoH 服务</h1>
    <p class="subtitle">轻量级 DNS over HTTPS 代理</p>
  </div>
</header>
<div class="container">
  <section>
    <h2>项目介绍</h2>
    <p>基于 Cloudflare Workers 的 DoH 代理，支持多上游并发查询和 EDNS 客户端子网注入。请求路径决定路由目标，完整保留原始查询参数。</p>
    <h3>主要功能</h3>
    <ul>
      <li><strong>多上游并发</strong>：/mix 端点同时查询所有上游，返回最快响应</li>
      <li><strong>EDNS 支持</strong>：mode=keep 透传原始 EDNS，mode=plus 强制补全客户端子网</li>
      <li><strong>灵活路由</strong>：每个上游独立路径，可单独使用</li>
      <li><strong>零配置部署</strong>：基于 Cloudflare Worker/Pages，无需服务器</li>
    </ul>
  </section>

  <section>
    <h2>可用端点</h2>
    <p>__UPSTREAM_LIST__</p>
  </section>

  <section>
    <h2>使用方法</h2>
    <p>所有端点均支持 JSON 查询和 DNS wire-format 请求（POST application/dns-message）。</p>
    <h3>并发模式</h3>
    <pre><code>curl "https://__HOST__/mix/query-dns?name=example.com&type=A"
# 全部上游并发，返回最快有效响应</code></pre>
    <h3>透传模式</h3>
    <pre><code>curl "https://__HOST__/mix/query-dns?name=example.com&mode=keep"
# 保留请求中的原始 EDNS 数据</code></pre>
    <h3>补全 EDNS</h3>
    <pre><code>curl "https://__HOST__/mix/query-dns?name=example.com&mode=plus"
# 自动注入客户端子网 EDNS</code></pre>
    <h3>单上游查询</h3>
    <pre><code>curl "https://__HOST__/google/query-dns?name=example.com"
curl "https://__HOST__/cloudflare/query-dns?name=example.com"</code></pre>
    <p style="font-size:.85em;color:#666;margin-top:.8rem">更多可选上游：<span class="endpoint">/quad9/query-dns</span> <span class="endpoint">/adguard/query-dns</span> <span class="endpoint">/opendns/query-dns</span>（在 config.js 中取消注释即可启用）</p>
  </section>

  <section>
    <h2>延迟检测</h2>
    <p>选择上游端点，点击按钮测试延迟：</p>
    <div id="targets">__UPSTREAM_CHECKBOXES__</div>
    <p><button class="btn" onclick="runLatencyTest()">开始检测</button></p>
    <div id="results"><table><thead><tr><th>端点</th><th>延迟</th><th>状态</th></tr></thead><tbody></tbody></table></div>
  </section>
</div>
<footer>
  <div class="container">
    <p>Forked from <a href="https://github.com/jqknono/cloudflare-doh">jqknono/cloudflare-doh</a> | MIT License</p>
  </div>
</footer>
<script>
const FIXED_QUERY='AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=';
function b64toBytes(b64){const b=atob(b64),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
document.querySelectorAll('#targets input').forEach(cb=>{cb.addEventListener('change',e=>e.target.parentElement.classList.toggle('checked',e.target.checked));cb.parentElement.classList.add('checked')});
async function runLatencyTest(){
  const r=document.getElementById('results'),t=r.querySelector('tbody');
  r.style.display='block';t.innerHTML='';
  const cs=document.querySelectorAll('#targets input:checked');
  if(!cs.length){t.innerHTML='<tr><td colspan=3 style="color:#999;text-align:center;padding:16px">未选择端点</td></tr>';return}
  const tasks=[...cs].map(async cb=>{
    const n=cb.value,row=t.insertRow();
    row.innerHTML='<td><strong>'+n+'</strong></td><td style="color:#999">...</td><td style="color:#999">...</td>';
    const s=performance.now();
    try{const res=await fetch('/'+n+'/query-dns',{method:'POST',headers:{'Content-Type':'application/dns-message'},body:b64toBytes(FIXED_QUERY)});row.cells[1].textContent=(performance.now()-s).toFixed(0)+'ms';row.cells[2].textContent=res.ok?'\u2705':'\u274C '+res.status}
    catch(e){row.cells[1].textContent='-';row.cells[2].textContent='\u274C'}
  });
  await Promise.all(tasks);
}
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
#targets{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
#targets label{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border:1px solid #ddd;border-radius:4px;cursor:pointer;font-size:.88rem;transition:all .15s}
#targets label:hover{border-color:var(--primary-color);background:#fff8f0}
#targets label.checked{background:var(--primary-color);color:#fff;border-color:var(--primary-color)}
#results{margin-top:12px;display:none}
#results table{width:100%;max-width:420px;border-collapse:collapse}
#results th{border-bottom:2px solid var(--primary-color);padding:6px 10px;text-align:left;font-size:.85em}
#results td{padding:6px 10px;border-bottom:1px solid #eee;font-size:.88em}
#results tr:hover td{background:#fafafa}
@media(max-width:600px){header h1{font-size:1.5rem}section{padding:1rem}.lang-switch{float:none;display:inline-block;margin-top:.5rem}}
</style>
</head>
<body>
<header>
  <div class="container">
    <a href="/" class="lang-switch">中文</a>
    <h1>DoH Service</h1>
    <p class="subtitle">A lightweight DNS over HTTPS proxy</p>
  </div>
</header>
<div class="container">
  <section>
    <h2>Introduction</h2>
    <p>A Cloudflare Worker based DoH proxy supporting multi-upstream concurrent queries and EDNS client-subnet injection. Request path determines the upstream target, preserving all original query parameters.</p>
    <h3>Key Features</h3>
    <ul>
      <li><strong>Multi-upstream race</strong>: /mix endpoint queries all upstreams concurrently, returns the fastest valid response</li>
      <li><strong>EDNS control</strong>: mode=keep passes through original EDNS, mode=plus injects client-subnet</li>
      <li><strong>Flexible routing</strong>: Each upstream at its own dedicated path</li>
      <li><strong>Zero-config deploy</strong>: Cloudflare Worker/Pages, no server maintenance</li>
    </ul>
  </section>

  <section>
    <h2>Available Endpoints</h2>
    <p>__UPSTREAM_LIST__</p>
  </section>

  <section>
    <h2>Usage</h2>
    <p>All endpoints support JSON queries and DNS wire-format requests (POST application/dns-message).</p>
    <h3>Concurrent mode</h3>
    <pre><code>curl "https://__HOST__/mix/query-dns?name=example.com&type=A"
# Queries all upstreams, returns fastest response</code></pre>
    <h3>Passthrough mode</h3>
    <pre><code>curl "https://__HOST__/mix/query-dns?name=example.com&mode=keep"
# Preserves original EDNS from the request</code></pre>
    <h3>EDNS injection</h3>
    <pre><code>curl "https://__HOST__/mix/query-dns?name=example.com&mode=plus"
# Injects client-subnet EDNS automatically</code></pre>
    <h3>Single upstream</h3>
    <pre><code>curl "https://__HOST__/google/query-dns?name=example.com"
curl "https://__HOST__/cloudflare/query-dns?name=example.com"</code></pre>
    <p style="font-size:.85em;color:#666;margin-top:.8rem">More optional upstreams: <span class="endpoint">/quad9/query-dns</span> <span class="endpoint">/adguard/query-dns</span> <span class="endpoint">/opendns/query-dns</span> (uncomment in config.js to enable)</p>
  </section>

  <section>
    <h2>Latency Test</h2>
    <p>Select upstream endpoints and click to measure latency:</p>
    <div id="targets">__UPSTREAM_CHECKBOXES__</div>
    <p><button class="btn" onclick="runLatencyTest()">Start Test</button></p>
    <div id="results"><table><thead><tr><th>Endpoint</th><th>Latency</th><th>Status</th></tr></thead><tbody></tbody></table></div>
  </section>
</div>
<footer>
  <div class="container">
    <p>Forked from <a href="https://github.com/jqknono/cloudflare-doh">jqknono/cloudflare-doh</a> | MIT License</p>
  </div>
</footer>
<script>
const FIXED_QUERY='AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=';
function b64toBytes(b64){const b=atob(b64),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
document.querySelectorAll('#targets input').forEach(cb=>{cb.addEventListener('change',e=>e.target.parentElement.classList.toggle('checked',e.target.checked));cb.parentElement.classList.add('checked')});
async function runLatencyTest(){
  const r=document.getElementById('results'),t=r.querySelector('tbody');
  r.style.display='block';t.innerHTML='';
  const cs=document.querySelectorAll('#targets input:checked');
  if(!cs.length){t.innerHTML='<tr><td colspan=3 style="color:#999;text-align:center;padding:16px">No endpoints selected</td></tr>';return}
  const tasks=[...cs].map(async cb=>{
    const n=cb.value,row=t.insertRow();
    row.innerHTML='<td><strong>'+n+'</strong></td><td style="color:#999">...</td><td style="color:#999">...</td>';
    const s=performance.now();
    try{const res=await fetch('/'+n+'/query-dns',{method:'POST',headers:{'Content-Type':'application/dns-message'},body:b64toBytes(FIXED_QUERY)});row.cells[1].textContent=(performance.now()-s).toFixed(0)+'ms';row.cells[2].textContent=res.ok?'\u2705':'\u274C '+res.status}
    catch(e){row.cells[1].textContent='-';row.cells[2].textContent='\u274C'}
  });
  await Promise.all(tasks);
}
</script>
</body>
</html>`;

// ── Shared helpers ─────────────────────────────────────────────────

function buildUpstreamList(names) {
  if (!names || names.length === 0) return '<em>none</em>';
  return names
    .map((n) => '<span class="endpoint">/' + n + '/query-dns</span>')
    .join(' ');
}

function buildCheckboxes(names) {
  if (!names || names.length === 0) return '';
  return names
    .map(
      (n) =>
        '<label><input type="checkbox" value="' + n + '" checked> <strong>' + n + '</strong></label>'
    )
    .join('');
}

function inject(html, host, upstreamNames) {
  return html
    .replaceAll('__HOST__', host)
    .replace('__UPSTREAM_LIST__', buildUpstreamList(upstreamNames))
    .replace('__UPSTREAM_CHECKBOXES__', buildCheckboxes(upstreamNames));
}

// ── Exports ────────────────────────────────────────────────────────

/**
 * Serve Chinese homepage.
 * @param {Request} request
 * @param {string[]} upstreamNames  e.g. ['mix', 'google', 'cloudflare']
 * @returns {Response}
 */
export function serveHomepage(request, upstreamNames) {
  const host = new URL(request.url).host;
  return new Response(inject(HTML_CN, host, upstreamNames), {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=utf-8' },
  });
}

/**
 * Serve English homepage.
 * @param {Request} request
 * @param {string[]} upstreamNames  e.g. ['mix', 'google', 'cloudflare']
 * @returns {Response}
 */
export function serveHomepageEn(request, upstreamNames) {
  const host = new URL(request.url).host;
  return new Response(inject(HTML_EN, host, upstreamNames), {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=utf-8' },
  });
}
