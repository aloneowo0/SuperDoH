/**
 * SuperDoH 配置向导 (config-wizard.js)
 * 纯 vanilla JS，无依赖。渲染到 #config-wizard。
 * 根据 window.__CONFIGURED__ 决定只读摘要 / 可编辑向导。
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
    { key: 'ecsPrefix4', label: 'ECS IPv4 前缀', hint: 'EDNS Client Subnet IPv4 掩码（通常 24）' },
    { key: 'ecsPrefix6', label: 'ECS IPv6 前缀', hint: 'EDNS Client Subnet IPv6 掩码（通常 56）' },
    { key: 'autoConcurrency', label: 'AUTO 并发数', hint: '竞速上游数（0=全部；Free 计划建议 4-6）' },
    { key: 'ecsProtectMs', label: 'ECS 保护 (ms)', hint: 'ECS 注入保护窗口' },
    { key: 'hardTimeoutMs', label: '硬超时 (ms)', hint: '单上游硬超时' },
    { key: 'metaHardTimeoutMs', label: 'Meta 硬超时 (ms)', hint: 'Meta 查询硬超时' },
    { key: 'metaCollectWindowMs', label: 'Meta 收集窗口 (ms)', hint: 'Meta 应答收集窗口' },
    { key: 'metaMaxIps', label: 'Meta 最大 IP', hint: 'Meta 最多保留 IP 数' },
    { key: 'preferredTimeoutMs', label: 'Preferred 超时 (ms)', hint: 'Preferred 上游超时' }
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
    '.sw-section.collapsed .sw-toggle:before{content:"展开 ▾"}',
    '.sw-toggle:before{content:"收起 ▴"}',
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
    mode: 'edit', // 'edit' | 'readonly'
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
    fetch('/config.json', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (cfg) {
        state.configData = cfg;
        renderReadOnly(cfg);
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
    wrap.appendChild(el('div', { class: 'sw-loading' }, '正在加载当前配置…'));
  }

  function renderLoadError(err) {
    wrap.innerHTML = '';
    wrap.appendChild(el('div', { class: 'sw-msg sw-msg-error' }, '无法加载 /config.json：' + (err && err.message ? err.message : err)));
    initEditDefaults();
    renderEdit();
  }

  function initEditDefaults() {
    state.regions = [];
  }

  // ── 只读视图 ─────────────────────────────────────────
  function renderReadOnly(cfg) {
    var sec, body, t, tb;
    wrap.innerHTML = '';
    state.mode = 'readonly';

    sec = el('section', { class: 'sw-section' });
    sec.appendChild(el('div', { class: 'sw-section-h' }, [
      el('h2', { text: '当前配置（只读）' })
    ]));
    body = el('div', { class: 'sw-body' });

    // 上游列表
    body.appendChild(el('h3', { text: '上游 (' + (cfg.upstreams ? cfg.upstreams.length : 0) + ')' }));
    if (cfg.upstreams && cfg.upstreams.length) {
      t = el('table', { class: 'sw-summary' });
      t.appendChild(el('thead', {}, [el('tr', {}, [el('th', { text: '名称' }), el('th', { text: 'URL' }), el('th', { text: 'ECS' })])]));
      tb = el('tbody', {});
      cfg.upstreams.forEach(function (u) {
        tb.appendChild(el('tr', {}, [
          el('td', { text: u.name }),
          el('td', { text: u.url }),
          el('td', { text: u.ecs ? '是' : '否' })
        ]));
      });
      t.appendChild(tb);
      body.appendChild(t);
    }

    // 关键参数
    body.appendChild(el('h3', { text: '关键参数' }));
    var kv = el('dl', { class: 'sw-kv' });
    var kvRows = [
      ['autoConcurrency', cfg.autoConcurrency],
      ['ecsPrefix4 / ecsPrefix6', cfg.ecsPrefix4 + ' / ' + cfg.ecsPrefix6],
      ['hardTimeoutMs', cfg.hardTimeoutMs],
      ['metaHardTimeoutMs', cfg.metaHardTimeoutMs],
      ['metaCollectWindowMs', cfg.metaCollectWindowMs],
      ['metaMaxIps', cfg.metaMaxIps],
      ['preferredTimeoutMs', cfg.preferredTimeoutMs],
      ['ecsProtectMs', cfg.ecsProtectMs],
      ['logLevel', cfg.logLevel],
      ['region (CF country)', cfg.region || '(未匹配)']
    ];
    kvRows.forEach(function (r) {
      kv.appendChild(el('dt', { text: r[0] }));
      kv.appendChild(el('dd', { text: String(r[1]) }));
    });
    body.appendChild(kv);

    // 地区配置
    if (cfg.regionConfig && Object.keys(cfg.regionConfig).length) {
      body.appendChild(el('h3', { text: '地区优化 (' + Object.keys(cfg.regionConfig).length + ')' }));
      Object.keys(cfg.regionConfig).forEach(function (cc) {
        var rc = cfg.regionConfig[cc];
        var rdiv = el('div', { class: 'sw-region' });
        rdiv.appendChild(el('div', { class: 'sw-region-h' }, [el('span', { class: 'sw-region-title', text: cc })]));
        var rkv = el('dl', { class: 'sw-kv' });
        var rows = [
          ['preferredCf', rc.preferredCf || ''],
          ['preferredCft', rc.preferredCft || ''],
          ['preferredVrc', rc.preferredVrc || ''],
          ['remap', Array.isArray(rc.remap) ? rc.remap.join(' ') : (rc.remap || '')],
          ['ech', rc.ech ? '是' : '否'],
          ['google', rc.google ? (Array.isArray(rc.google) ? ('是 (' + rc.google.length + ' 条)') : '是') : '否']
        ];
        rows.forEach(function (r) {
          rkv.appendChild(el('dt', { text: r[0] }));
          rkv.appendChild(el('dd', { text: r[1] }));
        });
        rdiv.appendChild(rkv);
        body.appendChild(rdiv);
      });
    } else {
      body.appendChild(el('p', { class: 'sw-note', text: '未启用地区优化。' }));
    }

    sec.appendChild(body);
    wrap.appendChild(sec);

    // 重新配置按钮
    var actions = el('div', { class: 'sw-actions' });
    actions.appendChild(el('button', {
      class: 'sw-btn',
      onclick: function () {
        prefillFromConfig(cfg);
        state.mode = 'edit';
        renderEdit();
      }
    }, '重新配置（切换到编辑模式）'));
    wrap.appendChild(actions);
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

    wrap.appendChild(buildUpstreamSection());
    wrap.appendChild(buildTuningSection());
    wrap.appendChild(buildRegionsSection());
    wrap.appendChild(buildAdvancedSection());
    wrap.appendChild(buildGenerateSection());
  }

  // ── 上游 section ─────────────────────────────────────
  function buildUpstreamSection() {
    var sec = el('section', { class: 'sw-section' });
    var cfg = state.configData;

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: '上游配置' }),
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
            el('span', { class: 'sw-badge ' + (p.ecs ? 'sw-badge-ecs' : 'sw-badge-noecs'), text: p.ecs ? 'ECS' : '无 ECS' })
          ]),
          el('div', { class: 'sw-upstream-url', text: p.url })
        ])
      ]);
      upGrid.appendChild(row);
    });
    body.appendChild(upGrid);

    body.appendChild(el('div', { class: 'sw-note', text: '自定义上游：在 Cloudflare Dashboard → Worker → Variables 添加 CUSTOM_名称 = https://example.com/dns-query，即时生效。' }));

    sec.appendChild(body);
    return sec;
  }

  // ── 调优 section ─────────────────────────────────────
  function buildTuningSection() {
    var sec = el('section', { class: 'sw-section' });
    var cfg = state.configData;

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: 'DNS 调优' }),
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
    bcField.appendChild(el('label', { text: '应答 IP 黑名单 (CIDR，空格分隔)' }));
    var bcVal = cfg ? (cfg.blockedCidrs || DEFAULTS.blockedCidrs) : DEFAULTS.blockedCidrs;
    bcField.appendChild(el('textarea', {
      class: 'sw-textarea', 'data-tuning': 'blockedCidrs',
      oninput: function () { clearErr(bcField); }
    }, bcVal));
    bcField.appendChild(el('div', { class: 'sw-hint', text: '每项须为合法 CIDR，如 127.0.0.0/8 或 ::1/128' }));
    bcField.appendChild(el('div', { class: 'sw-error' }));
    body.appendChild(bcField);

    // logLevel
    var llField = el('div', { class: 'sw-field', 'data-field': 'logLevel' });
    llField.appendChild(el('label', { text: '日志级别' }));
    var llVal = cfg ? (cfg.logLevel || DEFAULTS.logLevel) : DEFAULTS.logLevel;
    var sel = el('select', { class: 'sw-select', 'data-tuning': 'logLevel' });
    ['debug', 'info', 'warn', 'error', 'none'].forEach(function (lv) {
      var o = el('option', { value: lv, text: lv });
      if (lv === llVal) o.setAttribute('selected', 'selected');
      sel.appendChild(o);
    });
    llField.appendChild(sel);
    llField.appendChild(el('div', { class: 'sw-hint', text: '生产环境建议 info' }));
    body.appendChild(llField);

    sec.appendChild(body);
    return sec;
  }

  // ── 地区 section ─────────────────────────────────────
  function buildRegionsSection() {
    var sec = el('section', { class: 'sw-section' });

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: '地区优化' }),
      el('button', { class: 'sw-toggle', type: 'button' })
    ]));

    var body = el('div', { class: 'sw-body' });
    body.appendChild(el('p', { class: 'sw-note', text: '空 = 不启用地区优化。每地区一块，键为 ISO 国家码（实际匹配由 request.cf.country 决定）。' }));

    var list = el('div', { id: 'sw-region-list' });
    body.appendChild(list);
    renderRegions(list);

    body.appendChild(el('button', {
      class: 'sw-btn sw-btn-secondary sw-btn-sm', type: 'button',
      onclick: function () {
        state.regions.push({ cc: '', preferredCf: '', preferredCft: '', preferredVrc: '', remap: '', ech: true, google: false });
        renderRegions(list);
      }
    }, '+ 添加地区'));

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
      el('span', { class: 'sw-region-title', text: '地区 #' + (idx + 1) }),
      el('button', {
        class: 'sw-icon-btn', type: 'button',
        onclick: function () {
          state.regions.splice(idx, 1);
          renderRegions(container);
        }
      }, '删除')
    ]);
    block.appendChild(header);

    var grid = el('div', { class: 'sw-region-grid' });

    // CC
    var ccField = el('div', { class: 'sw-field', 'data-rfield': 'cc' });
    ccField.appendChild(el('label', { text: '国家码 (2 字母大写)' }));
    ccField.appendChild(el('input', {
      class: 'sw-input', type: 'text', maxlength: '2', placeholder: 'CN',
      value: r.cc,
      oninput: function (e) { state.regions[idx].cc = e.target.value.trim().toUpperCase(); clearErr(ccField); }
    }));
    ccField.appendChild(el('div', { class: 'sw-error' }));
    grid.appendChild(ccField);

    // preferredCf
    var cfField = el('div', { class: 'sw-field' });
    cfField.appendChild(el('label', { text: 'Cloudflare 优选域名' }));
    cfField.appendChild(el('input', {
      class: 'sw-input', type: 'text', placeholder: 'cf.example.com',
      value: r.preferredCf,
      oninput: function (e) { state.regions[idx].preferredCf = e.target.value.trim(); }
    }));
    grid.appendChild(cfField);

    // preferredCft
    var cftField = el('div', { class: 'sw-field' });
    cftField.appendChild(el('label', { text: 'CloudFront 优选域名' }));
    cftField.appendChild(el('input', {
      class: 'sw-input', type: 'text', placeholder: 'worker.cloudfront.example.com',
      value: r.preferredCft,
      oninput: function (e) { state.regions[idx].preferredCft = e.target.value.trim(); }
    }));
    grid.appendChild(cftField);

    // preferredVrc
    var vrcField = el('div', { class: 'sw-field' });
    vrcField.appendChild(el('label', { text: 'Vercel 优选域名' }));
    vrcField.appendChild(el('input', {
      class: 'sw-input', type: 'text', placeholder: 'worker.vercel.example.com',
      value: r.preferredVrc,
      oninput: function (e) { state.regions[idx].preferredVrc = e.target.value.trim(); }
    }));
    grid.appendChild(vrcField);

    block.appendChild(grid);

    // remap (full width)
    var remapField = el('div', { class: 'sw-field' });
    remapField.appendChild(el('label', { text: 'remap (空格分隔域名)' }));
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
    echWrap.appendChild(el('label', { text: 'ECH', for: 'sw-ech-' + idx }));
    cbRow.appendChild(echWrap);

    var gWrap = el('div', { class: 'sw-checkbox-row' });
    gWrap.appendChild(el('input', {
      type: 'checkbox', id: 'sw-g-' + idx, checked: r.google ? 'checked' : null,
      onchange: function (e) { state.regions[idx].google = e.target.checked; }
    }));
    gWrap.appendChild(el('label', { text: 'google (启用 Cealing-Host 抓取)', for: 'sw-g-' + idx }));
    cbRow.appendChild(gWrap);
    block.appendChild(cbRow);

    return block;
  }

  // ── 高级 section ─────────────────────────────────────
  function buildAdvancedSection() {
    var sec = el('section', { class: 'sw-section collapsed' });

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: '构建抓取 — 高级 (通常无需修改)' }),
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
    geoField.appendChild(el('div', { class: 'sw-hint', text: 'GeoIP CIDR 列表源' }));
    geoField.appendChild(el('div', { class: 'sw-error' }));
    row.appendChild(geoField);

    var chField = el('div', { class: 'sw-field', 'data-field': 'cealingHostUrl' });
    chField.appendChild(el('label', { text: 'cealingHostUrl' }));
    chField.appendChild(el('input', {
      class: 'sw-input', type: 'text', 'data-adv': 'cealingHostUrl',
      value: DEFAULTS.cealingHostUrl,
      oninput: function () { clearErr(chField); }
    }));
    chField.appendChild(el('div', { class: 'sw-hint', text: 'Cealing-Host Google 代理列表源' }));
    chField.appendChild(el('div', { class: 'sw-error' }));
    row.appendChild(chField);

    body.appendChild(row);

    var fgWrap = el('div', { class: 'sw-checkbox-row' });
    fgWrap.appendChild(el('input', {
      type: 'checkbox', id: 'sw-fgp', checked: DEFAULTS.fetchGoogleProxy ? 'checked' : null,
      'data-adv': 'fetchGoogleProxy'
    }));
    fgWrap.appendChild(el('label', { text: 'fetchGoogleProxy (构建时抓取 Cealing-Host)', for: 'sw-fgp' }));
    body.appendChild(fgWrap);

    sec.appendChild(body);
    return sec;
  }

  // ── 生成 section ─────────────────────────────────────
  function buildGenerateSection() {
    var sec = el('section', { class: 'sw-section' });

    sec.appendChild(el('div', { class: 'sw-section-h', onclick: function (e) { toggleSection(sec, e); } }, [
      el('h2', { text: '生成配置' }),
      el('button', { class: 'sw-toggle', type: 'button' })
    ]));

    var body = el('div', { class: 'sw-body' });

    var msgBox = el('div', { id: 'sw-gen-msg' });
    body.appendChild(msgBox);

    var actions = el('div', { class: 'sw-actions' });
    actions.appendChild(el('button', {
      class: 'sw-btn', type: 'button',
      onclick: function () { doGenerate(); }
    }, '生成配置文件'));
    actions.appendChild(el('button', {
      class: 'sw-btn sw-btn-secondary', type: 'button', id: 'sw-download-btn',
      onclick: function () { doDownload(); }
    }, '下载 superdoh.config.js'));
    actions.appendChild(el('button', {
      class: 'sw-btn sw-btn-ghost', type: 'button',
      onclick: function () { doCopy(); }
    }, '复制到剪贴板'));
    body.appendChild(actions);

    body.appendChild(el('div', { class: 'sw-note', text: '生成后请将下载的 superdoh.config.js 覆盖你 fork 仓库中的同名文件，然后推送以触发 Workers Builds 重新部署。' }));

    var preview = el('div', { class: 'sw-preview' });
    preview.appendChild(el('pre', {}, [el('code', { id: 'sw-preview-code', text: '// 点击「生成配置文件」以预览' })]));
    body.appendChild(preview);

    sec.appendChild(body);
    return sec;
  }

  function toggleSection(sec, e) {
    // 不在 input/button 上触发
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
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
      errors.push('至少启用 1 个上游');
    }

    // 调优数值字段
    TUNING_FIELDS.forEach(function (f) {
      var fieldEl = wrap.querySelector('[data-field="' + f.key + '"]');
      if (fieldEl) clearErr(fieldEl);
      var input = wrap.querySelector('[data-tuning="' + f.key + '"]');
      var raw = input ? input.value : '';
      var n = parseInt(raw, 10);
      if (!/^\d+$/.test(String(raw).trim()) || isNaN(n) || n < 0) {
        if (fieldEl) showErr(fieldEl, '须为非负整数');
        errors.push(f.label + ' 须为非负整数');
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
      if (bcField) showErr(bcField, '无效 CIDR: ' + bcBad.join(' '));
      errors.push('blockedCidrs 含无效 CIDR');
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
      if (!/^[A-Z]{2}$/.test(cc)) {
        if (ccFieldEl) showErr(ccFieldEl, '须为 2 字母大写国家码');
        errors.push('地区 #' + (idx + 1) + ' 国家码无效');
        return;
      }
      if (regionCCs[cc]) {
        if (ccFieldEl) showErr(ccFieldEl, '国家码重复');
        errors.push('地区 #' + (idx + 1) + ' 国家码重复: ' + cc);
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
      if (geoField) showErr(geoField, '不能为空');
      errors.push('geoipUrl 不能为空');
    }

    var chField = wrap.querySelector('[data-field="cealingHostUrl"]');
    if (chField) clearErr(chField);
    var chInput = wrap.querySelector('[data-adv="cealingHostUrl"]');
    config.cealingHostUrl = chInput ? chInput.value.trim() : DEFAULTS.cealingHostUrl;
    if (!config.cealingHostUrl) {
      if (chField) showErr(chField, '不能为空');
      errors.push('cealingHostUrl 不能为空');
    }

    var fgpCb = wrap.querySelector('[data-adv="fetchGoogleProxy"]');
    config.fetchGoogleProxy = fgpCb ? !!fgpCb.checked : true;

    return { config: config, errors: errors };
  }

  function genConfigText(config) {
    var lines = [];
    lines.push('/**');
    lines.push(' * SuperDoH 用户配置文件');
    lines.push(' *');
    lines.push(' * 这是 SuperDoH 唯一的人类可编辑配置源。');
    lines.push(' * scripts/build-config.cjs 读取本文件 → 生成 src/config.js（机器产物）→ 打包进 Worker。');
    lines.push(' * 改完本文件后必须重新部署（Workers Builds 会自动触发）才生效。');
    lines.push(' *');
    lines.push(' * configured: 1 = 正式运行模式。Worker 使用下面你填写的配置。');
    lines.push(' *   0 = 首次配置模式（Worker 用内置默认跑，首页「配置」tab 显示向导）。');
    lines.push(' *');
    lines.push(' * 格式说明：');
    lines.push(' *   - upstreams: 预设名设 true 启用；自定义上游通过 Workers 环境变量注入（CUSTOM_<NAME>=https://...）');
    lines.push(' *   - regions: 空对象 = 不启用地区优化；每地区一块，实际匹配由 request.cf.country 决定');
    lines.push(' *   - geoipUrl / cealingHostUrl: 构建时自动抓取大列表的源，普通用户无需改');
    lines.push(' */');
    lines.push('export default {');
    lines.push('  configured: 1,');
    lines.push('');
    lines.push('  // ── 上游 ──────────────────────────────────────────');
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
    lines.push('  // ── ECS / DNS 调优 ────────────────────────────────');
    lines.push('  ecsPrefix4: ' + config.ecsPrefix4 + ',');
    lines.push('  ecsPrefix6: ' + config.ecsPrefix6 + ',');
    lines.push('  // 应答 IP 黑名单（CIDR，空格分隔）');
    lines.push('  blockedCidrs: ' + JSON.stringify(config.blockedCidrs) + ',');
    lines.push('  // AUTO 竞速并发上游数（0 = 全部上游；Free 计划建议 4-6）');
    lines.push('  autoConcurrency: ' + config.autoConcurrency + ',');
    lines.push('  // 以下均为毫秒，通常无需改动');
    lines.push('  ecsProtectMs: ' + config.ecsProtectMs + ',');
    lines.push('  hardTimeoutMs: ' + config.hardTimeoutMs + ',');
    lines.push('  metaHardTimeoutMs: ' + config.metaHardTimeoutMs + ',');
    lines.push('  metaCollectWindowMs: ' + config.metaCollectWindowMs + ',');
    lines.push('  metaMaxIps: ' + config.metaMaxIps + ',');
    lines.push('  preferredTimeoutMs: ' + config.preferredTimeoutMs + ',');
    lines.push('  // 日志级别：debug / info / warn / error / none');
    lines.push('  logLevel: ' + JSON.stringify(config.logLevel) + ',');
    lines.push('');
    lines.push('  // ── 地区优化 ──────────────────────────────────────');
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
    lines.push('  // ── 构建时远程抓取 ────────────────────────────────');
    lines.push('  // GeoIP CIDR 列表源（8 个分类，构建时自动抓取并编译进 config.js）');
    lines.push('  geoipUrl: ' + JSON.stringify(config.geoipUrl) + ',');
    lines.push('  // Cealing-Host Google 代理列表源（regions.*.google=true 时抓取）');
    lines.push('  cealingHostUrl: ' + JSON.stringify(config.cealingHostUrl) + ',');
    lines.push('  // 设为 false 可跳过 Cealing-Host 抓取');
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
      msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-error' }, '配置有 ' + result.errors.length + ' 处错误，已标红，请修正后重试：\n• ' + result.errors.join('\n• ')));
      document.getElementById('sw-preview-code').textContent = '// 修正错误后再生成';
      lastGeneratedText = '';
      return;
    }
    lastGeneratedText = genConfigText(result.config);
    document.getElementById('sw-preview-code').textContent = lastGeneratedText;
    msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-ok' }, '配置已生成，可下载或复制。'));
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
        msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-ok' }, '已复制到剪贴板。'));
      }, function (err) {
        msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-error' }, '复制失败：' + (err && err.message ? err.message : err)));
      });
    } else {
      msgBox.appendChild(el('div', { class: 'sw-msg sw-msg-error' }, '当前浏览器不支持 clipboard API。'));
    }
  }
})();