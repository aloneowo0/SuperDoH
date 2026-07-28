/**
 * SuperDoH 配置向导 (config-wizard.js)
 * 纯 vanilla JS，无依赖。渲染到 #config-wizard。
 * configured:0 时用默认值显示可编辑表单；configured:1 时从 /config.json 预填当前值后显示可编辑表单。
 */
(function () {
  'use strict';

  var root = document.getElementById('config-wizard');
  if (!root) return;

  // ── 预设上游 ─────────────────────────────────────────
  var PRESETS = {
    google: { url: 'https://dns.google/dns-query', ecs: true },
    cloudflare_Public: { url: 'https://cloudflare-dns.com/dns-query', ecs: false },
    quad9: { url: 'https://dns11.quad9.net/dns-query', ecs: true },
    adguard: { url: 'https://dns.adguard-dns.com/dns-query', ecs: true },
    opendns: { url: 'https://dns.opendns.com/dns-query', ecs: true },
    yandex: { url: 'https://common.dot.dns.yandex.net/dns-query', ecs: false },
    dnspod: { url: 'https://sm2.doh.pub/dns-query', ecs: true },
    alidns: { url: 'https://dns.alidns.com/dns-query', ecs: true },
    '360': { url: 'https://doh.360.cn/dns-query', ecs: true },
    nextdns: { url: 'https://dns.nextdns.io', ecs: true }
  };
  var PRESET_ORDER = ['google', 'cloudflare_Public', 'quad9', 'adguard', 'opendns', 'yandex', 'dnspod', 'alidns', '360', 'nextdns'];

  // ── 语言检测 + i18n ─────────────────────────────────
  var LANG = (document.documentElement.lang === 'en' || location.pathname.indexOf('/en') === 0) ? 'en' : 'zh';
  var i18n = {
    // Section titles
    securitySection: { zh: '安全入口', en: 'Security' },
    upstreamsSection: { zh: '上游配置', en: 'Upstreams' },
    tuningSection: { zh: 'DNS 调优', en: 'DNS Tuning' },
    regionsSection: { zh: '地区优化', en: 'Region Optimization' },
    advancedSection: { zh: '构建抓取 — 高级 (通常无需修改)', en: 'Build Fetch — Advanced (usually no changes needed)' },
    generateSection: { zh: '生成配置', en: 'Generate Config' },
    // Toggle
    toggleCollapse: { zh: '收起 ▴', en: 'Collapse ▴' },
    toggleExpand: { zh: '展开 ▾', en: 'Expand ▾' },
    // Upstream section
    upstreamBadgeNoEcs: { zh: '无 ECS', en: 'No ECS' },
    securityHomepageNote: { zh: '伪装入口：设置 ENTRANCE 和 PROXY 环境变量后，只有访问 ENTRANCE 路径（如 /abc123）才显示主页，其他路径反向代理 PROXY 网站。两个变量都设置才生效。', en: 'Camouflage: set both ENTRANCE and PROXY env vars — only the ENTRANCE path (e.g. /abc123) shows the homepage; all other paths reverse-proxy to the PROXY URL. Both must be set to take effect.' },
    securityProxyNote: { zh: '示例：ENTRANCE=/abc123，PROXY=https://baidu.com → 访问 / 显示百度，访问 /abc123 显示主页，DoH 端点变为 /abc123/dns-query。', en: 'Example: ENTRANCE=/abc123, PROXY=https://baidu.com → visiting / shows baidu.com, visiting /abc123 shows homepage, DoH endpoint becomes /abc123/dns-query.' },

    upstreamNote: { zh: '自定义上游：在 Cloudflare Dashboard → Worker → Variables 添加 CUSTOM_名称 = https://example.com/dns-query，即时生效。', en: 'Custom upstreams: add CUSTOM_<NAME>=https://... in Cloudflare Dashboard → Worker → Variables, takes effect instantly.' },
    // Tuning fields
    ecsPrefix4Label: { zh: 'ECS IPv4 前缀', en: 'ECS IPv4 Prefix' },
    ecsPrefix4Hint: { zh: 'EDNS Client Subnet IPv4 掩码（通常 24）', en: 'EDNS Client Subnet IPv4 mask (usually 24)' },
    ecsPrefix6Label: { zh: 'ECS IPv6 前缀', en: 'ECS IPv6 Prefix' },
    ecsPrefix6Hint: { zh: 'EDNS Client Subnet IPv6 掩码（通常 56）', en: 'EDNS Client Subnet IPv6 mask (usually 56)' },
    autoConcurrencyLabel: { zh: 'AUTO 并发数', en: 'AUTO Concurrency' },
    autoConcurrencyHint: { zh: '竞速上游数（0=全部；Free 计划建议 4-6）', en: 'Number of racing upstreams (0=all; Free plan recommends 4-6)' },
    ecsProtectMsLabel: { zh: 'ECS 保护 (ms)', en: 'ECS Protect (ms)' },
    ecsProtectMsHint: { zh: 'ECS 注入保护窗口', en: 'ECS injection protection window' },
    hardTimeoutMsLabel: { zh: '硬超时 (ms)', en: 'Hard Timeout (ms)' },
    hardTimeoutMsHint: { zh: '单上游硬超时', en: 'Per-upstream hard timeout' },
    metaHardTimeoutMsLabel: { zh: 'Meta 硬超时 (ms)', en: 'Meta Hard Timeout (ms)' },
    metaHardTimeoutMsHint: { zh: 'Meta 查询硬超时', en: 'Meta query hard timeout' },
    metaCollectWindowMsLabel: { zh: 'Meta 收集窗口 (ms)', en: 'Meta Collect Window (ms)' },
    metaCollectWindowMsHint: { zh: 'Meta 应答收集窗口', en: 'Meta answer collection window' },
    metaMaxIpsLabel: { zh: 'Meta 最大 IP', en: 'Meta Max IPs' },
    metaMaxIpsHint: { zh: 'Meta 最多保留 IP 数', en: 'Max IPs kept by Meta' },
    preferredTimeoutMsLabel: { zh: 'Preferred 超时 (ms)', en: 'Preferred Timeout (ms)' },
    preferredTimeoutMsHint: { zh: 'Preferred 上游超时', en: 'Preferred upstream timeout' },
    blockedCidrsLabel: { zh: '应答 IP 黑名单 (CIDR，空格分隔)', en: 'Answer IP Blocklist (CIDR, space-separated)' },
    blockedCidrsHint: { zh: '每项须为合法 CIDR，如 127.0.0.0/8 或 ::1/128', en: 'Each entry must be a valid CIDR, e.g. 127.0.0.0/8 or ::1/128' },
    logLevelLabel: { zh: '日志级别', en: 'Log Level' },
    logLevelHint: { zh: '生产环境建议 info', en: 'Production recommends info' },
    // Regions section
    regionsNote: { zh: '空 = 不启用地区优化。每地区一块，键为 ISO 国家码（实际匹配由 request.cf.country 决定）。键为 * 时表示全球通配，未命中具体国家码时回退到此配置。', en: 'Empty = no region optimization. Each entry is one region, key is ISO country code or * (global wildcard), matched by request.cf.country.' },
    addRegionBtn: { zh: '+ 添加地区', en: '+ Add Region' },
    removeBtn: { zh: '删除', en: 'Remove' },
    regionTitle: { zh: '地区 #', en: 'Region #' },
    ccLabel: { zh: '国家码 (2 字母大写，或 * 表示全球)', en: 'Country code (2-letter uppercase, or * for global)' },
    ccPlaceholder: { zh: 'CN 或 *', en: 'CN or *' },
    preferredCfLabel: { zh: 'Cloudflare 优选域名', en: 'Cloudflare preferred domain' },
    preferredCftLabel: { zh: 'CloudFront 优选域名', en: 'CloudFront preferred domain' },
    preferredVrcLabel: { zh: 'Vercel 优选域名', en: 'Vercel preferred domain' },
    remapLabel: { zh: 'remap (空格分隔域名)', en: 'remap (space-separated domains)' },
    echLabel: { zh: '尽力 ECH 支持', en: 'Best-effort ECH' },
    googleLabel: { zh: 'google 加速（规则来源 Cealing-Host，仅对 CN 地区有效）', en: 'Google acceleration (Cealing-Host rules, CN region only)' },
    // Advanced section
    geoipUrlHint: { zh: 'GeoIP CIDR 列表源', en: 'GeoIP CIDR list source' },
    cealingHostUrlHint: { zh: 'Cealing-Host Google 代理列表源', en: 'Cealing-Host Google proxy source' },
    fetchGoogleProxyLabel: { zh: 'fetchGoogleProxy (构建时抓取 Cealing-Host)', en: 'fetchGoogleProxy (fetch Cealing-Host at build time)' },
    // Generate section
    generateBtn: { zh: '生成配置文件', en: 'Generate Config File' },
    downloadBtn: { zh: '下载 superdoh.config.js', en: 'Download superdoh.config.js' },
    copyBtn: { zh: '复制到剪贴板', en: 'Copy to clipboard' },
    generateNote: { zh: '生成后请将下载的 superdoh.config.js 覆盖你 fork 仓库中的同名文件，然后推送以触发 Workers Builds 重新部署。', en: 'After generating, overwrite the same-named file in your forked repo, then push to trigger a Workers Builds redeploy.' },
    previewPlaceholder: { zh: '// 点击「生成配置文件」以预览', en: '// Click "Generate Config File" to preview' },
    // Validation errors
    errAtLeastOneUpstream: { zh: '至少启用 1 个上游', en: 'At least 1 upstream required' },
    errNonNegInt: { zh: '须为非负整数', en: 'Must be a non-negative integer' },
    errInvalidCidr: { zh: '无效 CIDR: ', en: 'Invalid CIDR: ' },
    errBlockedCidrsInvalid: { zh: 'blockedCidrs 含无效 CIDR', en: 'blockedCidrs contains invalid CIDR' },
    errCcInvalid: { zh: '须为 2 字母大写国家码或 *', en: 'Must be 2-letter uppercase country code or *' },
    errCcDuplicate: { zh: '国家码重复', en: 'Duplicate country code' },
    errRegionInvalid: { zh: ' 国家码无效', en: ' invalid country code' },
    errRegionDuplicate: { zh: ' 国家码重复: ', en: ' duplicate country code: ' },
    errNotEmpty: { zh: '不能为空', en: 'Cannot be empty' },
    errGeoipUrlEmpty: { zh: 'geoipUrl 不能为空', en: 'geoipUrl cannot be empty' },
    errCealingHostUrlEmpty: { zh: 'cealingHostUrl 不能为空', en: 'cealingHostUrl cannot be empty' },
    // Generate messages
    msgErrorsPrefix: { zh: '配置有 ', en: 'Config has ' },
    msgErrorsSuffix: { zh: ' 处错误，已标红，请修正后重试：\n• ', en: ' error(s), marked in red, please fix and retry:\n• ' },
    msgPreviewFixFirst: { zh: '// 修正错误后再生成', en: '// Fix errors before generating' },
    msgGenerated: { zh: '配置已生成，可下载或复制。', en: 'Config generated, you can download or copy.' },
    msgCopied: { zh: '已复制到剪贴板。', en: 'Copied to clipboard.' },
    msgCopyFailed: { zh: '复制失败：', en: 'Copy failed: ' },
    msgClipboardUnsupported: { zh: '当前浏览器不支持 clipboard API。', en: 'Current browser does not support the clipboard API.' },
    // Loading
    loadingText: { zh: '正在加载当前配置…', en: 'Loading current configuration…' },
    loadErrorPrefix: { zh: '无法加载 /config.json：', en: 'Failed to load /config.json: ' },
    // Generated config comments
    cfgHeaderTitle: { zh: 'SuperDoH 用户配置文件', en: 'SuperDoH User Config File' },
    cfgHeaderDesc1: { zh: '这是 SuperDoH 唯一的人类可编辑配置源。', en: 'This is the only human-editable config source for SuperDoH.' },
    cfgHeaderDesc2: { zh: 'scripts/build-config.cjs 读取本文件 → 生成 src/config.js（机器产物）→ 打包进 Worker。', en: 'scripts/build-config.cjs reads this file → generates src/config.js (machine product) → bundled into the Worker.' },
    cfgHeaderDesc3: { zh: '改完本文件后必须重新部署（Workers Builds 会自动触发）才生效。', en: 'After editing this file you must redeploy (Workers Builds triggers automatically) for it to take effect.' },
    cfgHeaderConfigured1: { zh: 'configured: 1 = 正式运行模式。Worker 使用下面你填写的配置。', en: 'configured: 1 = production mode. Worker uses the config you fill in below.' },
    cfgHeaderConfigured0: { zh: '   0 = 首次配置模式（Worker 用内置默认跑，首页「配置」tab 显示向导）。', en: '   0 = first-time setup mode (Worker runs with built-in defaults, homepage "Config" tab shows the wizard).' },
    cfgHeaderFormatTitle: { zh: '格式说明：', en: 'Format notes:' },
    cfgHeaderFormat1: { zh: '   - upstreams: 预设名设 true 启用；自定义上游通过 Workers 环境变量注入（CUSTOM_<NAME>=https://...）', en: '   - upstreams: set preset name to true to enable; custom upstreams injected via Workers env vars (CUSTOM_<NAME>=https://...)' },
    cfgHeaderFormat2: { zh: '   - regions: 空对象 = 不启用地区优化；每地区一块，键为 ISO 国家码或 * (全球通配)；实际匹配由 request.cf.country 决定', en: '   - regions: empty object = no region optimization; each entry is one region, key is ISO country code or * (global wildcard); matched by request.cf.country' },
    cfgHeaderFormat3: { zh: '   - geoipUrl / cealingHostUrl: 构建时自动抓取大列表的源，普通用户无需改', en: '   - geoipUrl / cealingHostUrl: sources auto-fetched at build time for large lists; ordinary users need not change' },
    cfgCommentUpstreams: { zh: '── 上游', en: '── Upstreams' },
    cfgCommentTuning: { zh: '── ECS / DNS 调优', en: '── ECS / DNS Tuning' },
    cfgCommentBlockedCidrs: { zh: '应答 IP 黑名单（CIDR，空格分隔）', en: 'Answer IP blocklist (CIDR, space-separated)' },
    cfgCommentAutoConcurrency: { zh: 'AUTO 竞速并发上游数（0 = 全部上游；Free 计划建议 4-6）', en: 'AUTO racing concurrency (0 = all upstreams; Free plan recommends 4-6)' },
    cfgCommentMsNoChange: { zh: '以下均为毫秒，通常无需改动', en: 'All values below are in ms; usually no changes needed' },
    cfgCommentLogLevel: { zh: '日志级别：debug / info / warn / error / none', en: 'Log level: debug / info / warn / error / none' },
    cfgCommentRegions: { zh: '── 地区优化', en: '── Region Optimization' },
    cfgCommentBuildFetch: { zh: '── 构建时远程抓取', en: '── Build-time Remote Fetch' },
    cfgCommentGeoip: { zh: 'GeoIP CIDR 列表源（8 个分类，构建时自动抓取并编译进 config.js）', en: 'GeoIP CIDR list source (8 categories, auto-fetched at build time and compiled into config.js)' },
    cfgCommentCealing: { zh: 'Cealing-Host Google 代理列表源（regions.*.google=true 时抓取）', en: 'Cealing-Host Google proxy source (fetched when regions.*.google=true)' },
    cfgCommentSkipCealing: { zh: '设为 false 可跳过 Cealing-Host 抓取', en: 'Set to false to skip Cealing-Host fetch' }
  };
  function t(key) { return (i18n[key] && i18n[key][LANG]) || key; }

  // ── 默认值 ───────────────────────────────────────────
  var DEFAULTS = {
    ecsPrefix4: 24,
    ecsPrefix6: 56,
    blockedCidrs: '127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128',
    autoConcurrency: 6,
    ecsProtectMs: 20,
    hardTimeoutMs: 800,
    metaHardTimeoutMs: 800,
    metaCollectWindowMs: 50,
    metaMaxIps: 4,
    preferredTimeoutMs: 300,
    logLevel: 'info',
    geoipUrl: 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/',
    cealingHostUrl: 'https://gitlab.com/SpaceTimee/Cealing-Host/raw/main/Cealing-Host.json',
    fetchGoogleProxy: true
  };

  // ── 调优字段定义 ─────────────────────────────────────
  var TUNING_FIELDS = [
    { key: 'ecsPrefix4', label: t('ecsPrefix4Label'), hint: t('ecsPrefix4Hint') },
    { key: 'ecsPrefix6', label: t('ecsPrefix6Label'), hint: t('ecsPrefix6Hint') },
    { key: 'autoConcurrency', label: t('autoConcurrencyLabel'), hint: t('autoConcurrencyHint') },
    { key: 'ecsProtectMs', label: t('ecsProtectMsLabel'), hint: t('ecsProtectMsHint') },
    { key: 'hardTimeoutMs', label: t('hardTimeoutMsLabel'), hint: t('hardTimeoutMsHint') },
    { key: 'metaHardTimeoutMs', label: t('metaHardTimeoutMsLabel'), hint: t('metaHardTimeoutMsHint') },
    { key: 'metaCollectWindowMs', label: t('metaCollectWindowMsLabel'), hint: t('metaCollectWindowMsHint') },
    { key: 'metaMaxIps', label: t('metaMaxIpsLabel'), hint: t('metaMaxIpsHint') },
    { key: 'preferredTimeoutMs', label: t('preferredTimeoutMsLabel'), hint: t('preferredTimeoutMsHint') }
  ];

  // ── 注入样式 ─────────────────────────────────────────
  var STYLE = [
    '.sw-wrap{font-size:.92rem;color:#333}',
    '.sw-section{background:#fff;margin:1rem 0;padding:1rem 1.2rem;border-radius:5px;box-shadow:0 1px 4px rgba(0,0,0,.08);border:1px solid #eee}',
    '.sw-section-h{display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none}',
    '.sw-section-h h2{color:var(--primary-color);font-size:1.1rem;margin:0;border:none;padding:0}',
    '.sw-toggle{color:var(--secondary-color);font-size:.8rem;font-weight:700;background:none;border:none;cursor:pointer;padding:.2rem .4rem}',
    '.sw-toggle:hover{text-decoration:underline}',
    '.sw-body{margin-top:.8rem}',
    '.sw-section.collapsed .sw-body{display:none}',
    '.sw-section.collapsed .sw-toggle:before{content:"' + t('toggleExpand') + '"}',
    '.sw-toggle:before{content:"' + t('toggleCollapse') + '"}',
    '.sw-row{display:grid;grid-template-columns:1fr 1fr;gap:.7rem 1rem;margin-bottom:.6rem}',
    '@media(max-width:600px){.sw-row{grid-template-columns:1fr}}',
    '.sw-field{display:flex;flex-direction:column;gap:.2rem}',
    '.sw-field label{font-size:.82rem;color:#555;font-weight:600}',
    '.sw-field .sw-hint{font-size:.72rem;color:#999}',
    '.sw-input,.sw-select,.sw-textarea{padding:.45rem .6rem;border:1px solid #ddd;border-radius:4px;font-size:.88rem;font-family:inherit;background:#fff;color:#333;transition:border-color .15s}',
    '.sw-input:focus,.sw-select:focus,.sw-textarea:focus{outline:none;border-color:var(--primary-color)}',
    '.sw-textarea{resize:vertical;min-height:60px;font-family:"SF Mono",Menlo,monospace;font-size:.82em}',
    '.sw-checkbox-row{display:flex;align-items:center;gap:.5rem;padding:.35rem 0}',
    '.sw-checkbox-row input[type=checkbox]{width:18px;height:18px;cursor:pointer;accent-color:var(--primary-color)}',
    '.sw-checkbox-row label{cursor:pointer;font-size:.88rem;color:#333}',
    '.sw-upstream-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:.4rem}',
    '.sw-upstream{display:flex;align-items:flex-start;gap:.6rem;padding:.5rem .6rem;border:1px solid #eee;border-radius:4px;background:#fafafa}',
    '@media(max-width:600px){.sw-upstream-grid{grid-template-columns:1fr}}',
    '.sw-upstream input[type=checkbox]{margin-top:.2rem;width:18px;height:18px;cursor:pointer;accent-color:var(--primary-color)}',
    '.sw-upstream-info{flex:1;min-width:0}',
    '.sw-upstream-name{font-weight:700;color:#333;font-size:.9rem}',
    '.sw-upstream-url{font-family:"SF Mono",Menlo,monospace;font-size:.78rem;color:#666;word-break:break-all}',
    '.sw-badge{display:inline-block;font-size:.68rem;padding:.1rem .4rem;border-radius:3px;font-weight:700;margin-left:.4rem;vertical-align:middle}',
    '.sw-badge-ecs{background:#e8f5e9;color:#2e7d32;border:1px solid #a5d6a7}',
    '.sw-badge-noecs{background:#fce4ec;color:#c62828;border:1px solid #f48fb1}',
    '.sw-badge-custom{background:#e3f2fd;color:#1565c0;border:1px solid #90caf9}',
    '.sw-upstream-actions{display:flex;gap:.3rem;align-items:center}',
    '.sw-icon-btn{background:none;border:1px solid #ddd;border-radius:3px;cursor:pointer;padding:.15rem .4rem;font-size:.78rem;color:#888}',
    '.sw-icon-btn:hover{color:#e74c3c;border-color:#e74c3c}',
    '.sw-custom-row{display:grid;grid-template-columns:120px 1fr auto;gap:.4rem;margin-bottom:.4rem;align-items:start}',
    '@media(max-width:600px){.sw-custom-row{grid-template-columns:1fr}}',
    '.sw-btn{display:inline-block;background:var(--primary-color);color:#fff;padding:.45rem 1rem;border:none;border-radius:4px;cursor:pointer;font-weight:700;font-size:.85rem;transition:background .2s}',
    '.sw-btn:hover{background:#e67e22}',
    '.sw-btn-secondary{background:var(--secondary-color)}',
    '.sw-btn-secondary:hover{background:#2c7aa8}',
    '.sw-btn-ghost{background:transparent;color:var(--secondary-color);border:1px solid var(--secondary-color)}',
    '.sw-btn-ghost:hover{background:var(--secondary-color);color:#fff}',
    '.sw-btn-sm{padding:.3rem .7rem;font-size:.78rem}',
    '.sw-error{color:#e74c3c;font-size:.78rem;margin-top:.3rem;display:none}',
    '.sw-error.show{display:block}',
    '.sw-field.invalid .sw-input,.sw-field.invalid .sw-select,.sw-field.invalid .sw-textarea{border-color:#e74c3c;background:#fff5f5}',
    '.sw-region{border:1px solid #e0e0e0;border-radius:5px;padding:.7rem .8rem;margin-bottom:.6rem;background:#fcfcfc}',
    '.sw-region-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem}',
    '.sw-region-h .sw-region-title{font-weight:700;color:var(--secondary-color);font-size:.9rem}',
    '.sw-region-grid{display:grid;grid-template-columns:1fr 1fr;gap:.5rem .8rem}',
    '@media(max-width:600px){.sw-region-grid{grid-template-columns:1fr}}',
    '.sw-actions{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem;padding-top:1rem;border-top:1px solid #eee}',
    '.sw-preview{background:#f8f8f8;border:1px solid #eee;border-left:3px solid var(--primary-color);border-radius:4px;padding:.8rem;margin-top:1rem;overflow-x:auto}',
    '.sw-preview pre{margin:0;background:none;border:none;padding:0}',
    '.sw-preview code{font-family:"SF Mono",Menlo,monospace;font-size:.78rem;line-height:1.55;color:#333;white-space:pre}',
    '.sw-summary{font-size:.9rem;line-height:1.7}',
    '.sw-summary h3{color:var(--secondary-color);margin:.8rem 0 .3rem;font-size:.95rem}',
    '.sw-summary table{width:100%;border-collapse:collapse;margin:.3rem 0}',
    '.sw-summary th{background:#f5f5f5;border-bottom:2px solid var(--primary-color);padding:.35rem .5rem;text-align:left;font-size:.8rem}',
    '.sw-summary td{padding:.35rem .5rem;border-bottom:1px solid #eee;font-size:.82rem}',
    '.sw-summary .sw-kv{display:grid;grid-template-columns:200px 1fr;gap:.2rem .6rem;font-size:.85rem}',
    '.sw-summary .sw-kv dt{color:#666}',
    '.sw-summary .sw-kv dd{color:#333;font-family:"SF Mono",Menlo,monospace;font-size:.82rem;word-break:break-all}',
    '.sw-msg{padding:.6rem .8rem;border-radius:4px;margin:.5rem 0;font-size:.85rem}',
    '.sw-msg-error{background:#fff5f5;color:#c62828;border:1px solid #f5c6cb}',
    '.sw-msg-ok{background:#f0faf0;color:#2e7d32;border:1px solid #a5d6a7}',
    '.sw-note{font-size:.78rem;color:#999;margin-top:.4rem}',
    '.sw-loading{padding:2rem;text-align:center;color:#999}'
  ].join('\n');

  // ── 工具函数 ─────────────────────────────────────────
  function el(tag, attrs, children) {
    var n = document.createElement(tag), k, v;
    if (attrs) {
      for (k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        v = attrs[k];
        if (k === 'class') n.className = v;
        else if (k === 'text') n.textContent = v;
        else if (k === 'html') n.innerHTML = v;
        else if (k === 'style') n.setAttribute('style', v);
        else if (k.indexOf('on') === 0 && typeof v === 'function') n.addEventListener(k.slice(2), v);
        else if (v !== null && v !== undefined) n.setAttribute(k, v);
      }
    }
    if (children) {
      if (!Array.isArray(children)) children = [children];
      children.forEach(function (c) {
        if (c == null) return;
        n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      });
    }
    return n;
  }

  function clearErr(field) {
    field.classList.remove('invalid');
    var e = field.querySelector('.sw-error');
    if (e) e.classList.remove('show');
  }

  function showErr(field, msg) {
    field.classList.add('invalid');
    var e = field.querySelector('.sw-error');
    if (!e) {
      e = el('div', { class: 'sw-error' });
      field.appendChild(e);
    }
    e.textContent = msg;
    e.classList.add('show');
  }

  function isValidCidr(token) {
    if (!token || token.indexOf('/') < 0) return false;
    var parts = token.split('/'), ip, mask, m, octs, i, o;
    if (parts.length !== 2) return false;
    ip = parts[0];
    mask = parts[1];
    if (!/^\d+$/.test(mask)) return false;
    m = parseInt(mask, 10);
    if (ip.indexOf(':') >= 0) {
      // IPv6
      if (m < 0 || m > 128) return false;
      // 简单校验：含 hex 和 :
      if (!/^([0-9a-fA-F:]+)$/.test(ip)) return false;
    } else {
      // IPv4
      if (m < 0 || m > 32) return false;
      octs = ip.split('.');
      if (octs.length !== 4) return false;
      for (i = 0; i < 4; i++) {
        if (!/^\d+$/.test(octs[i])) return false;
        o = parseInt(octs[i], 10);
        if (o < 0 || o > 255) return false;
      }
    }
    return true;
  }

  // ── 状态 ─────────────────────────────────────────────
  var state = {
    mode: 'edit',
    regions: [], // [{cc, preferredCf, preferredCft, preferredVrc, remap, ech, google}]
    configData: null // 来自 /config.json
  };

  // ── 注入样式 ─────────────────────────────────────────
  var styleEl = el('style', {});
  styleEl.textContent = STYLE;
  root.appendChild(styleEl);

  var wrap = el('div', { class: 'sw-wrap' });
  root.appendChild(wrap);

  // ── 启动 ─────────────────────────────────────────────
  if (window.__CONFIGURED__ === 1) {
    renderLoading();
    fetch((window.__BASE_PATH__ || '') + '/config.json', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (cfg) {
        state.configData = cfg;
        prefillFromConfig(cfg);
        state.mode = 'edit';
        renderEdit();
      })
      .catch(function (err) {
        renderLoadError(err);
      });
  } else {
    initEditDefaults();
    renderEdit();
  }

  function renderLoading() {
    wrap.innerHTML = '';
    wrap.appendChild(el('div', { class: 'sw-loading' }, t('loadingText')));
  }

  function renderLoadError(err) {
    wrap.innerHTML = '';
    wrap.appendChild(el('div', { class: 'sw-msg sw-msg-error' }, t('loadErrorPrefix') + (err && err.message ? err.message : err)));
    initEditDefaults();
    renderEdit();
  }

  function initEditDefaults() {
    state.regions = [];
  }

  function prefillFromConfig(cfg) {
    // 地区
    state.regions = [];
    if (cfg.regionConfig) {
      Object.keys(cfg.regionConfig).forEach(function (cc) {
        var rc = cfg.regionConfig[cc];
        state.regions.push({
          cc: cc,
          preferredCf: rc.preferredCf || '',
          preferredCft: rc.preferredCft || '',
          preferredVrc: rc.preferredVrc || '',
          remap: Array.isArray(rc.remap) ? rc.remap.join(' ') : (rc.remap || ''),
          ech: !!rc.ech,
          google: Array.isArray(rc.google) ? true : !!rc.google
        });
      });
    }
  }

  // ── 编辑视图 ─────────────────────────────────────────
  function renderEdit() {
    wrap.innerHTML = '';
    state.mode = 'edit';

    wrap.appendChild(buildSecuritySection());
    wrap.appendChild(buildUpstreamSection());
    wrap.appendChild(buildTuningSection());
    wrap.appendChild(buildRegionsSection());
    wrap.appendChild(buildAdvancedSection());
    wrap.appendChild(buildGenerateSection());
  }

  // ── 安全入口 section ─────────────────────────────────
  function buildSecuritySection() {
    var sec = el('section', { class: 'sw-section' });

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: t('securitySection') }),
      el('button', { class: 'sw-toggle', type: 'button' })
    ]));

    var body = el('div', { class: 'sw-body' });

    body.appendChild(el('div', { class: 'sw-note', text: t('securityHomepageNote') }));
    body.appendChild(el('div', { class: 'sw-note', text: t('securityProxyNote') }));

    sec.appendChild(body);
    return sec;
  }

  // ── 上游 section ─────────────────────────────────────
  function buildUpstreamSection() {
    var sec = el('section', { class: 'sw-section' });
    var cfg = state.configData;

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: t('upstreamsSection') }),
      el('button', { class: 'sw-toggle', type: 'button' })
    ]));

    var body = el('div', { class: 'sw-body' });

    // 预设上游
    var upGrid = el('div', { class: 'sw-upstream-grid' });
    PRESET_ORDER.forEach(function (name) {
      var p = PRESETS[name], checked = false, found;
      if (cfg && cfg.upstreams) {
        // 只读模式切回编辑时，根据 /config.json 判断预设是否启用
        found = cfg.upstreams.find(function (u) { return u.name === name; });
        if (found) checked = true;
      } else {
        // 默认：google + cloudflare_Public
        checked = (name === 'google' || name === 'cloudflare_Public');
      }
      var row = el('div', { class: 'sw-upstream' }, [
        el('input', { type: 'checkbox', id: 'sw-up-' + name, 'data-preset': name, checked: checked ? 'checked' : null }),
        el('div', { class: 'sw-upstream-info' }, [
          el('div', {}, [
            el('span', { class: 'sw-upstream-name', text: name }),
            el('span', { class: 'sw-badge ' + (p.ecs ? 'sw-badge-ecs' : 'sw-badge-noecs'), text: p.ecs ? 'ECS' : t('upstreamBadgeNoEcs') })
          ]),
          el('div', { class: 'sw-upstream-url', text: p.url })
        ])
      ]);
      upGrid.appendChild(row);
    });
    body.appendChild(upGrid);

    body.appendChild(el('div', { class: 'sw-note', text: t('upstreamNote') }));

    sec.appendChild(body);
    return sec;
  }

  // ── 调优 section ─────────────────────────────────────
  function buildTuningSection() {
    var sec = el('section', { class: 'sw-section' });
    var cfg = state.configData;

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: t('tuningSection') }),
      el('button', { class: 'sw-toggle', type: 'button' })
    ]));

    var body = el('div', { class: 'sw-body' });
    var row = el('div', { class: 'sw-row' });

    TUNING_FIELDS.forEach(function (f) {
      var val = cfg ? cfg[f.key] : DEFAULTS[f.key];
      if (val === undefined || val === null) val = DEFAULTS[f.key];
      var field = el('div', { class: 'sw-field', 'data-field': f.key });
      field.appendChild(el('label', { text: f.label }));
      field.appendChild(el('input', {
        class: 'sw-input', type: 'number', min: '0', step: '1', value: val,
        'data-tuning': f.key,
        oninput: function () { clearErr(field); }
      }));
      field.appendChild(el('div', { class: 'sw-hint', text: f.hint }));
      field.appendChild(el('div', { class: 'sw-error' }));
      row.appendChild(field);
    });

    body.appendChild(row);

    // blockedCidrs
    var bcField = el('div', { class: 'sw-field', 'data-field': 'blockedCidrs' });
    bcField.appendChild(el('label', { text: t('blockedCidrsLabel') }));
    var bcVal = cfg ? (cfg.blockedCidrs || DEFAULTS.blockedCidrs) : DEFAULTS.blockedCidrs;
    bcField.appendChild(el('textarea', {
      class: 'sw-textarea', 'data-tuning': 'blockedCidrs',
      oninput: function () { clearErr(bcField); }
    }, bcVal));
    bcField.appendChild(el('div', { class: 'sw-hint', text: t('blockedCidrsHint') }));
    bcField.appendChild(el('div', { class: 'sw-error' }));
    body.appendChild(bcField);

    // logLevel
    var llField = el('div', { class: 'sw-field', 'data-field': 'logLevel' });
    llField.appendChild(el('label', { text: t('logLevelLabel') }));
    var llVal = cfg ? (cfg.logLevel || DEFAULTS.logLevel) : DEFAULTS.logLevel;
    var sel = el('select', { class: 'sw-select', 'data-tuning': 'logLevel' });
    ['debug', 'info', 'warn', 'error', 'none'].forEach(function (lv) {
      var o = el('option', { value: lv, text: lv });
      if (lv === llVal) o.setAttribute('selected', 'selected');
      sel.appendChild(o);
    });
    llField.appendChild(sel);
    llField.appendChild(el('div', { class: 'sw-hint', text: t('logLevelHint') }));
    body.appendChild(llField);

    sec.appendChild(body);
    return sec;
  }

  // ── 地区 section ─────────────────────────────────────
  function buildRegionsSection() {
    var sec = el('section', { class: 'sw-section' });

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: t('regionsSection') }),
      el('button', { class: 'sw-toggle', type: 'button' })
    ]));

    var body = el('div', { class: 'sw-body' });
    body.appendChild(el('p', { class: 'sw-note', text: t('regionsNote') }));

    var list = el('div', { id: 'sw-region-list' });
    body.appendChild(list);
    renderRegions(list);

    body.appendChild(el('button', {
      class: 'sw-btn sw-btn-secondary sw-btn-sm', type: 'button',
      onclick: function () {
        state.regions.push({ cc: '', preferredCf: '', preferredCft: '', preferredVrc: '', remap: '', ech: true, google: false });
        renderRegions(list);
      }
    }, t('addRegionBtn')));

    sec.appendChild(body);
    return sec;
  }

  function renderRegions(container) {
    container.innerHTML = '';
    state.regions.forEach(function (r, idx) {
      container.appendChild(buildRegionBlock(r, idx, container));
    });
  }

  function buildRegionBlock(r, idx, container) {
    var block = el('div', { class: 'sw-region', 'data-region': idx });

    var header = el('div', { class: 'sw-region-h' }, [
      el('span', { class: 'sw-region-title', text: t('regionTitle') + (idx + 1) }),
      el('button', {
        class: 'sw-icon-btn', type: 'button',
        onclick: function () {
          state.regions.splice(idx, 1);
          renderRegions(container);
        }
      }, t('removeBtn'))
    ]);
    block.appendChild(header);

    var grid = el('div', { class: 'sw-region-grid' });

    // CC
    var ccField = el('div', { class: 'sw-field', 'data-rfield': 'cc' });
    ccField.appendChild(el('label', { text: t('ccLabel') }));
    ccField.appendChild(el('input', {
      class: 'sw-input', type: 'text', maxlength: '2', placeholder: t('ccPlaceholder'),
      value: r.cc,
      oninput: function (e) { state.regions[idx].cc = e.target.value.trim().toUpperCase(); clearErr(ccField); }
    }));
    ccField.appendChild(el('div', { class: 'sw-error' }));
    grid.appendChild(ccField);

    // preferredCf
    var cfField = el('div', { class: 'sw-field' });
    cfField.appendChild(el('label', { text: t('preferredCfLabel') }));
    cfField.appendChild(el('input', {
      class: 'sw-input', type: 'text', placeholder: 'cf.090227.xyz',
      value: r.preferredCf,
      oninput: function (e) { state.regions[idx].preferredCf = e.target.value.trim(); }
    }));
    grid.appendChild(cfField);

    // preferredCft
    var cftField = el('div', { class: 'sw-field' });
    cftField.appendChild(el('label', { text: t('preferredCftLabel') }));
    cftField.appendChild(el('input', {
      class: 'sw-input', type: 'text', placeholder: 'worker.cloudfront.182682.xyz',
      value: r.preferredCft,
      oninput: function (e) { state.regions[idx].preferredCft = e.target.value.trim(); }
    }));
    grid.appendChild(cftField);

    // preferredVrc
    var vrcField = el('div', { class: 'sw-field' });
    vrcField.appendChild(el('label', { text: t('preferredVrcLabel') }));
    vrcField.appendChild(el('input', {
      class: 'sw-input', type: 'text', placeholder: 'worker.vercel.182682.xyz',
      value: r.preferredVrc,
      oninput: function (e) { state.regions[idx].preferredVrc = e.target.value.trim(); }
    }));
    grid.appendChild(vrcField);

    block.appendChild(grid);

    // remap (full width)
    var remapField = el('div', { class: 'sw-field' });
    remapField.appendChild(el('label', { text: t('remapLabel') }));
    remapField.appendChild(el('input', {
      class: 'sw-input', type: 'text', placeholder: 'twimg.com twitter.com x.com',
      value: r.remap,
      oninput: function (e) { state.regions[idx].remap = e.target.value.trim(); }
    }));
    block.appendChild(remapField);

    // ech + google checkboxes
    var cbRow = el('div', { style: 'display:flex;gap:1.2rem;margin-top:.5rem' });
    var echWrap = el('div', { class: 'sw-checkbox-row' });
    echWrap.appendChild(el('input', {
      type: 'checkbox', id: 'sw-ech-' + idx, checked: r.ech ? 'checked' : null,
      onchange: function (e) { state.regions[idx].ech = e.target.checked; }
    }));
    echWrap.appendChild(el('label', { text: t('echLabel'), for: 'sw-ech-' + idx }));
    cbRow.appendChild(echWrap);

    var gWrap = el('div', { class: 'sw-checkbox-row' });
    gWrap.appendChild(el('input', {
      type: 'checkbox', id: 'sw-g-' + idx, checked: r.google ? 'checked' : null,
      onchange: function (e) { state.regions[idx].google = e.target.checked; }
    }));
    gWrap.appendChild(el('label', { text: t('googleLabel'), for: 'sw-g-' + idx }));
    cbRow.appendChild(gWrap);
    block.appendChild(cbRow);

    return block;
  }

  // ── 高级 section ─────────────────────────────────────
  function buildAdvancedSection() {
    var sec = el('section', { class: 'sw-section collapsed' });

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: t('advancedSection') }),
      el('button', { class: 'sw-toggle', type: 'button' })
    ]));

    var body = el('div', { class: 'sw-body' });
    var row = el('div', { class: 'sw-row' });

    var geoField = el('div', { class: 'sw-field', 'data-field': 'geoipUrl' });
    geoField.appendChild(el('label', { text: 'geoipUrl' }));
    geoField.appendChild(el('input', {
      class: 'sw-input', type: 'text', 'data-adv': 'geoipUrl',
      value: DEFAULTS.geoipUrl,
      oninput: function () { clearErr(geoField); }
    }));
    geoField.appendChild(el('div', { class: 'sw-hint', text: t('geoipUrlHint') }));
    geoField.appendChild(el('div', { class: 'sw-error' }));
    row.appendChild(geoField);

    var chField = el('div', { class: 'sw-field', 'data-field': 'cealingHostUrl' });
    chField.appendChild(el('label', { text: 'cealingHostUrl' }));
    chField.appendChild(el('input', {
      class: 'sw-input', type: 'text', 'data-adv': 'cealingHostUrl',
      value: DEFAULTS.cealingHostUrl,
      oninput: function () { clearErr(chField); }
    }));
    chField.appendChild(el('div', { class: 'sw-hint', text: t('cealingHostUrlHint') }));
    chField.appendChild(el('div', { class: 'sw-error' }));
    row.appendChild(chField);

    body.appendChild(row);

    var fgWrap = el('div', { class: 'sw-checkbox-row' });
    fgWrap.appendChild(el('input', {
      type: 'checkbox', id: 'sw-fgp', checked: DEFAULTS.fetchGoogleProxy ? 'checked' : null,
      'data-adv': 'fetchGoogleProxy'
    }));
    fgWrap.appendChild(el('label', { text: t('fetchGoogleProxyLabel'), for: 'sw-fgp' }));
    body.appendChild(fgWrap);

    sec.appendChild(body);
    return sec;
  }

  // ── 生成 section ─────────────────────────────────────
  function buildGenerateSection() {
    var sec = el('section', { class: 'sw-section' });

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: t('generateSection') }),
      el('button', { class: 'sw-toggle', type: 'button' })
    ]));

    var body = el('div', { class: 'sw-body' });

    var msgBox = el('div', { id: 'sw-gen-msg' });
    body.appendChild(msgBox);

    var actions = el('div', { class: 'sw-actions' });
    actions.appendChild(el('button', {
      class: 'sw-btn', type: 'button',
      onclick: function () { doGenerate(); }
    }, t('generateBtn')));
    actions.appendChild(el('button', {
      class: 'sw-btn sw-btn-secondary', type: 'button', id: 'sw-download-btn',
      onclick: function () { doDownload(); }
    }, t('downloadBtn')));
    actions.appendChild(el('button', {
      class: 'sw-btn sw-btn-ghost', type: 'button',
      onclick: function () { doCopy(); }
    }, t('copyBtn')));
    body.appendChild(actions);

    body.appendChild(el('div', { class: 'sw-note', text: t('generateNote') }));

    var preview = el('div', { class: 'sw-preview' });
    preview.appendChild(el('pre', {}, [el('code', { id: 'sw-preview-code', text: t('previewPlaceholder') })]));
    body.appendChild(preview);

    sec.appendChild(body);
    return sec;
  }

  function toggleSection(sec, e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
    sec.classList.toggle('collapsed');
  }

  // ── 收集 + 校验 + 生成 ───────────────────────────────
  function collectAndValidate() {
    var errors = [];
    var config = {
      configured: 1,
      upstreams: {},
      ecsPrefix4: 0,
      ecsPrefix6: 0,
      blockedCidrs: '',
      autoConcurrency: 0,
      ecsProtectMs: 0,
      hardTimeoutMs: 0,
      metaHardTimeoutMs: 0,
      metaCollectWindowMs: 0,
      metaMaxIps: 0,
      preferredTimeoutMs: 0,
      logLevel: 'info',
      regions: {},
      geoipUrl: '',
      cealingHostUrl: '',
      fetchGoogleProxy: true
    };

    // 上游预设
    var enabledCount = 0;
    PRESET_ORDER.forEach(function (name) {
      var cb = document.getElementById('sw-up-' + name);
      if (cb && cb.checked) {
        config.upstreams[name] = true;
        enabledCount++;
      }
    });

    if (enabledCount === 0) {
      errors.push(t('errAtLeastOneUpstream'));
    }

    // 调优数值字段
    TUNING_FIELDS.forEach(function (f) {
      var fieldEl = wrap.querySelector('[data-field="' + f.key + '"]');
      if (fieldEl) clearErr(fieldEl);
      var input = wrap.querySelector('[data-tuning="' + f.key + '"]');
      var raw = input ? input.value : '';
      var n = parseInt(raw, 10);
      if (!/^\d+$/.test(String(raw).trim()) || isNaN(n) || n < 0) {
        if (fieldEl) showErr(fieldEl, t('errNonNegInt'));
        errors.push(f.label + ' ' + t('errNonNegInt'));
        return;
      }
      config[f.key] = n;
    });

    // blockedCidrs
    var bcField = wrap.querySelector('[data-field="blockedCidrs"]');
    if (bcField) clearErr(bcField);
    var bcInput = wrap.querySelector('[data-tuning="blockedCidrs"]');
    var bcRaw = bcInput ? bcInput.value : '';
    var bcTokens = bcRaw.trim().split(/\s+/).filter(Boolean);
    var bcBad = [];
    bcTokens.forEach(function (tok) {
      if (!isValidCidr(tok)) bcBad.push(tok);
    });
    if (bcBad.length) {
      if (bcField) showErr(bcField, t('errInvalidCidr') + bcBad.join(' '));
      errors.push(t('errBlockedCidrsInvalid'));
    }
    config.blockedCidrs = bcRaw.trim();

    // logLevel
    var llSel = wrap.querySelector('[data-tuning="logLevel"]');
    config.logLevel = llSel ? llSel.value : 'info';

    // 地区
    var regionCCs = {};
    state.regions.forEach(function (r, idx) {
      var ccFieldEl = wrap.querySelector('[data-region="' + idx + '"] [data-rfield="cc"]');
      if (ccFieldEl) clearErr(ccFieldEl);
      var cc = r.cc.trim().toUpperCase();
      if (!cc) return; // 空地区块跳过
    if (!/^([A-Z]{2}|\*)$/.test(cc)) {
      if (ccFieldEl) showErr(ccFieldEl, t('errCcInvalid'));
      errors.push(t('regionTitle') + (idx + 1) + t('errRegionInvalid'));
        return;
      }
      if (regionCCs[cc]) {
        if (ccFieldEl) showErr(ccFieldEl, t('errCcDuplicate'));
        errors.push(t('regionTitle') + (idx + 1) + t('errRegionDuplicate') + cc);
        return;
      }
      regionCCs[cc] = true;
      config.regions[cc] = {
        preferredCf: r.preferredCf.trim(),
        preferredCft: r.preferredCft.trim(),
        preferredVrc: r.preferredVrc.trim(),
        remap: r.remap.trim(),
        ech: !!r.ech,
        google: !!r.google
      };
    });

    // 高级
    var geoField = wrap.querySelector('[data-field="geoipUrl"]');
    if (geoField) clearErr(geoField);
    var geoInput = wrap.querySelector('[data-adv="geoipUrl"]');
    config.geoipUrl = geoInput ? geoInput.value.trim() : DEFAULTS.geoipUrl;
    if (!config.geoipUrl) {
      if (geoField) showErr(geoField, t('errNotEmpty'));
      errors.push(t('errGeoipUrlEmpty'));
    }

    var chField = wrap.querySelector('[data-field="cealingHostUrl"]');
    if (chField) clearErr(chField);
    var chInput = wrap.querySelector('[data-adv="cealingHostUrl"]');
    config.cealingHostUrl = chInput ? chInput.value.trim() : DEFAULTS.cealingHostUrl;
    if (!config.cealingHostUrl) {
      if (chField) showErr(chField, t('errNotEmpty'));
      errors.push(t('errCealingHostUrlEmpty'));
    }

    var fgpCb = wrap.querySelector('[data-adv="fetchGoogleProxy"]');
    config.fetchGoogleProxy = fgpCb ? !!fgpCb.checked : true;

    return { config: config, errors: errors };
  }

  function genConfigText(config) {
    var lines = [];
    lines.push('/**');
    lines.push(' * ' + t('cfgHeaderTitle'));
    lines.push(' *');
    lines.push(' * ' + t('cfgHeaderDesc1'));
    lines.push(' * ' + t('cfgHeaderDesc2'));
    lines.push(' * ' + t('cfgHeaderDesc3'));
    lines.push(' *');
    lines.push(' * ' + t('cfgHeaderConfigured1'));
    lines.push(' * ' + t('cfgHeaderConfigured0'));
    lines.push(' *');
    lines.push(' * ' + t('cfgHeaderFormatTitle'));
    lines.push(' * ' + t('cfgHeaderFormat1'));
    lines.push(' * ' + t('cfgHeaderFormat2'));
    lines.push(' * ' + t('cfgHeaderFormat3'));
    lines.push(' */');
    lines.push('export default {');
    lines.push('  configured: 1,');
    lines.push('');
    lines.push('  // ' + t('cfgCommentUpstreams') + ' ──────────────────────────────────────────');
    lines.push('  upstreams: {');
    // 预设按 PRESET_ORDER 输出（启用的），未启用的注释
    PRESET_ORDER.forEach(function (name) {
      if (config.upstreams[name] === true) {
        lines.push('    ' + (isIdent(name) ? name : JSON.stringify(name)) + ': true,');
      } else {
        lines.push('    // ' + name + ': false,');
      }
    });
    lines.push('  },');
    lines.push('');
    lines.push('  // ' + t('cfgCommentTuning') + ' ───────────────────────────────');
    lines.push('  ecsPrefix4: ' + config.ecsPrefix4 + ',');
    lines.push('  ecsPrefix6: ' + config.ecsPrefix6 + ',');
    lines.push('  // ' + t('cfgCommentBlockedCidrs'));
    lines.push('  blockedCidrs: ' + JSON.stringify(config.blockedCidrs) + ',');
    lines.push('  // ' + t('cfgCommentAutoConcurrency'));
    lines.push('  autoConcurrency: ' + config.autoConcurrency + ',');
    lines.push('  // ' + t('cfgCommentMsNoChange'));
    lines.push('  ecsProtectMs: ' + config.ecsProtectMs + ',');
    lines.push('  hardTimeoutMs: ' + config.hardTimeoutMs + ',');
    lines.push('  metaHardTimeoutMs: ' + config.metaHardTimeoutMs + ',');
    lines.push('  metaCollectWindowMs: ' + config.metaCollectWindowMs + ',');
    lines.push('  metaMaxIps: ' + config.metaMaxIps + ',');
    lines.push('  preferredTimeoutMs: ' + config.preferredTimeoutMs + ',');
    lines.push('  // ' + t('cfgCommentLogLevel'));
    lines.push('  logLevel: ' + JSON.stringify(config.logLevel) + ',');
    lines.push('');
    lines.push('  // ' + t('cfgCommentRegions') + ' ──────────────────────────────────────');
    if (Object.keys(config.regions).length === 0) {
      lines.push('  regions: {},');
    } else {
      lines.push('  regions: {');
      Object.keys(config.regions).forEach(function (cc) {
        var r = config.regions[cc];
        lines.push('    ' + JSON.stringify(cc) + ': {');
        lines.push('      preferredCf: ' + JSON.stringify(r.preferredCf) + ',');
        lines.push('      preferredCft: ' + JSON.stringify(r.preferredCft) + ',');
        lines.push('      preferredVrc: ' + JSON.stringify(r.preferredVrc) + ',');
        lines.push('      remap: ' + JSON.stringify(r.remap) + ',');
        lines.push('      ech: ' + r.ech + ',');
        lines.push('      google: ' + r.google + ',');
        lines.push('    },');
      });
      lines.push('  },');
    }
    lines.push('');
    lines.push('  // ' + t('cfgCommentBuildFetch') + ' ───────────────────────────────');
    lines.push('  // ' + t('cfgCommentGeoip'));
    lines.push('  geoipUrl: ' + JSON.stringify(config.geoipUrl) + ',');
    lines.push('  // ' + t('cfgCommentCealing'));
    lines.push('  cealingHostUrl: ' + JSON.stringify(config.cealingHostUrl) + ',');
    lines.push('  // ' + t('cfgCommentSkipCealing'));
    lines.push('  fetchGoogleProxy: ' + config.fetchGoogleProxy + ',');
    lines.push('};');
    return lines.join('\n');
  }

  function isIdent(name) {
    return /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(name);
  }

  var lastGeneratedText = '';

  function doGenerate() {
    var result = collectAndValidate();
    var msgBox = document.getElementById('sw-gen-msg');
    msgBox.innerHTML = '';
    if (result.errors.length) {
      msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-error' }, t('msgErrorsPrefix') + result.errors.length + t('msgErrorsSuffix') + result.errors.join('\n• ')));
      document.getElementById('sw-preview-code').textContent = t('msgPreviewFixFirst');
      lastGeneratedText = '';
      return;
    }
    lastGeneratedText = genConfigText(result.config);
    document.getElementById('sw-preview-code').textContent = lastGeneratedText;
    msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-ok' }, t('msgGenerated')));
  }

  function doDownload() {
    if (!lastGeneratedText) {
      doGenerate();
      if (!lastGeneratedText) return;
    }
    var blob = new Blob([lastGeneratedText], { type: 'application/javascript' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'superdoh.config.js';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function doCopy() {
    if (!lastGeneratedText) {
      doGenerate();
      if (!lastGeneratedText) return;
    }
    var msgBox = document.getElementById('sw-gen-msg');
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(lastGeneratedText).then(function () {
        msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-ok' }, t('msgCopied')));
      }, function (err) {
        msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-error' }, t('msgCopyFailed') + (err && err.message ? err.message : err)));
      });
    } else {
      msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-error' }, t('msgClipboardUnsupported')));
    }
  }
})();