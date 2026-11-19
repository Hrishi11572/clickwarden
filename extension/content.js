// ClickWarden content script
//  - reports clicks/keypresses so the background can spot downloads you didn't start
//  - pre-checks links when you hover them
//  - holds cross-site link clicks until the link has been checked

(() => {
  if (window.__clickWardenLoaded) return;
  window.__clickWardenLoaded = true;

  const send = (msg) => {
    try { return chrome.runtime.sendMessage(msg); } catch { return Promise.resolve(null); }
  };

  // ---------- user-gesture tracking ----------
  let lastGesture = 0;
  const onGesture = () => {
    const now = Date.now();
    if (now - lastGesture < 700) return;
    lastGesture = now;
    send({ type: 'gesture', origin: location.origin });
  };
  addEventListener('pointerdown', onGesture, true);
  addEventListener('keydown', onGesture, true);

  // ---------- settings ----------
  let intercept = true;
  send({ type: 'getSettings' }).then(s => { if (s && typeof s.interceptClicks === 'boolean') intercept = s.interceptClicks; }).catch(() => {});

  // ---------- link checking ----------
  const verdicts = new Map(); // url -> result | Promise

  function check(url) {
    const v = verdicts.get(url);
    if (v) return Promise.resolve(v);
    const p = send({ type: 'check', url })
      .then(r => { verdicts.set(url, r || { verdict: 'error' }); return r; })
      .catch(() => { verdicts.delete(url); return { verdict: 'error' }; });
    verdicts.set(url, p);
    return p;
  }

  const isBad = (r) => r && (r.verdict === 'malicious' || r.verdict === 'suspicious');

  function targetUrl(a) {
    let u;
    try { u = new URL(a.href, location.href); } catch { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (u.origin === location.origin) return null; // same-site navigation: leave alone
    u.hash = '';
    return u.href;
  }

  const anchorOf = (e) => (e.composedPath ? e.composedPath() : [e.target])
    .find(n => n && n.tagName && n.tagName.toLowerCase() === 'a' && n.href);

  // Hover pre-check (debounced) so clicks feel instant.
  let hoverTimer = null;
  document.addEventListener('mouseover', (e) => {
    const a = anchorOf(e);
    if (!a) return;
    const url = targetUrl(a);
    if (!url) return;
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => {
      check(url).then(r => { if (isBad(r)) markLink(a, r); });
    }, 150);
  }, { capture: true, passive: true });

  function markLink(a, r) {
    a.style.outline = `2px solid ${r.verdict === 'malicious' ? '#d93025' : '#e37400'}`;
    a.style.outlineOffset = '2px';
    a.title = `ClickWarden: ${r.verdict === 'malicious' ? 'DANGEROUS link' : 'suspicious link'} — ${(r.reasons[0] || (r.sources.find(s => s.status !== 'clean') || {}).detail || '')}`;
  }

  function go(url, a, newTab) {
    const target = a.getAttribute('target');
    if (newTab || target === '_blank') window.open(url, '_blank', 'noopener');
    else if (target && target !== '_self') window.open(url, target);
    else location.assign(url);
  }

  async function onClick(e) {
    if (!intercept || e.defaultPrevented) return;
    if (e.type === 'click' && e.button !== 0) return;
    if (e.type === 'auxclick' && e.button !== 1) return;
    const a = anchorOf(e);
    if (!a || a.hasAttribute('download')) return;
    const url = targetUrl(a);
    if (!url) return;

    const newTab = e.type === 'auxclick' || e.ctrlKey || e.metaKey || e.shiftKey;
    const known = verdicts.get(url);
    if (known && !(known instanceof Promise)) {
      if (!isBad(known)) return; // already checked & fine: let the browser handle it normally
      e.preventDefault(); e.stopImmediatePropagation();
      showWarning(known, () => go(url, a, newTab));
      return;
    }

    // Not checked yet: hold the click (max ~3.5s, within the browser's popup-gesture window).
    e.preventDefault(); e.stopImmediatePropagation();
    const r = await Promise.race([check(url), new Promise(res => setTimeout(() => res({ verdict: 'timeout' }), 3500))]);
    if (isBad(r)) showWarning(r, () => go(url, a, newTab));
    else go(url, a, newTab);
  }
  document.addEventListener('click', onClick, true);
  document.addEventListener('auxclick', onClick, true);

  // ---------- in-page warning ----------
  function showWarning(r, proceed) {
    const host = document.createElement('div');
    host.style.cssText = 'position:fixed;inset:0;z-index:2147483647;';
    const root = host.attachShadow({ mode: 'closed' });
    const danger = r.verdict === 'malicious';
    const color = danger ? '#d93025' : '#e37400';

    const style = document.createElement('style');
    style.textContent = `
      .bg{position:fixed;inset:0;background:rgba(15,15,20,.6);display:flex;align-items:center;justify-content:center;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
      .card{background:#fff;color:#1f1f1f;max-width:460px;width:calc(100% - 32px);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.35);overflow:hidden}
      .top{background:${color};color:#fff;padding:16px 20px;font-size:17px;font-weight:600}
      .body{padding:16px 20px}
      .url{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:#f3f3f3;padding:8px;border-radius:6px;word-break:break-all;margin-bottom:10px}
      ul{margin:6px 0 0;padding-left:18px} li{margin:3px 0}
      .row{display:flex;gap:8px;justify-content:flex-end;padding:0 20px 18px}
      button{font:inherit;border-radius:8px;padding:8px 14px;cursor:pointer;border:1px solid #ccc;background:#fff}
      .safe{background:#1a73e8;color:#fff;border-color:#1a73e8}
      .risk{color:${color};border-color:transparent;background:transparent;text-decoration:underline}`;
    root.appendChild(style);

    const bg = el('div', 'bg');
    const card = el('div', 'card');
    card.appendChild(el('div', 'top', danger ? '⛔ ClickWarden blocked a dangerous link' : '⚠️ ClickWarden: this link looks suspicious'));
    const body = el('div', 'body');
    body.appendChild(el('div', 'url', r.url));
    const ul = document.createElement('ul');
    for (const s of (r.sources || []).filter(s => s.status === 'malicious' || s.status === 'suspicious')) ul.appendChild(el('li', '', `${s.name}: ${s.detail}`));
    for (const why of (r.reasons || [])) ul.appendChild(el('li', '', why));
    body.appendChild(ul);
    card.appendChild(body);

    const row = el('div', 'row');
    const risk = el('button', 'risk', 'Open anyway');
    const safe = el('button', 'safe', 'Don\'t open');
    row.append(risk, safe);
    card.appendChild(row);
    bg.appendChild(card);
    root.appendChild(bg);

    const close = () => host.remove();
    safe.onclick = close;
    bg.onclick = (ev) => { if (ev.target === bg) close(); };
    risk.onclick = async () => { await send({ type: 'allowOnce', url: r.url }); close(); proceed(); };
    (document.body || document.documentElement).appendChild(host);
    safe.focus();
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
})();
