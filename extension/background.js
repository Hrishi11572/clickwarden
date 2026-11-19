import { analyzeUrl, registrableDomain } from './lib/heuristics.js';
import { analyzeFilename, baseName } from './lib/fileheuristics.js';
import { checkUrlIntel, checkHashIntel, testKeys } from './lib/intel.js';
import { getSettings, saveSettings, putDownload, getDownload, getDownloads } from './lib/store.js';

const CACHE_TTL = 30 * 60 * 1000;
const SUSPICIOUS_SCORE = 40;
const GESTURE_WINDOW_MS = 5000;

// ============================================================
// 1. LINK CHECKING
// ============================================================

const cache = new Map();    // key -> { result, t }
const pending = new Map();  // key -> Promise

function isAllowlisted(host, list) {
  host = host.toLowerCase();
  return list.some(d => {
    d = d.trim().toLowerCase().replace(/^\*\./, '');
    return d && (host === d || host.endsWith('.' + d));
  });
}

/** Full assessment of a URL: offline heuristics + blocklists. */
async function assessUrl(url, { deep = false } = {}) {
  let u;
  try { u = new URL(url); } catch { return { url, verdict: 'skipped' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { url, verdict: 'skipped' };
  u.hash = '';
  const clean = u.href;

  const s = await getSettings();
  if (isAllowlisted(u.hostname, s.allowlist)) {
    return { url: clean, verdict: 'safe', trusted: true, score: 0, reasons: ['On your trusted-sites list'], sources: [], errors: [], checkedWith: [] };
  }

  const key = (deep ? 'deep|' : 'fast|') + clean;
  const hit = cache.get(key) || (!deep && cache.get('deep|' + clean));
  if (hit && Date.now() - hit.t < CACHE_TTL) return hit.result;
  if (pending.has(key)) return pending.get(key);

  const p = (async () => {
    const h = analyzeUrl(u);
    const intel = await checkUrlIntel(clean, s, { useVt: deep || s.vtOnNavigation });
    let verdict = 'safe';
    if (intel.malicious) verdict = 'malicious';
    else if (intel.suspicious || h.score >= SUSPICIOUS_SCORE) verdict = 'suspicious';
    const result = {
      url: clean, verdict, score: h.score, reasons: h.reasons,
      sources: intel.sources, errors: intel.errors, checkedWith: intel.checkedWith,
      noKeys: !s.gsbKey && !s.abuseKey && !s.vtKey, at: Date.now()
    };
    cache.set(key, { result, t: Date.now() });
    if (cache.size > 2000) cache.delete(cache.keys().next().value);
    return result;
  })();
  pending.set(key, p);
  try { return await p; } finally { pending.delete(key); }
}

// "Open anyway" allowances: url -> expiry
async function allowOnce(url) {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  allowed[url] = Date.now() + 10 * 60 * 1000;
  await chrome.storage.session.set({ allowed });
}
async function isAllowedOnce(url) {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  const exp = allowed[url] || allowed[url.replace(/#.*$/, '')];
  return !!exp && exp > Date.now();
}

function setBadge(tabId, r) {
  if (tabId < 0) return;
  const text = r.verdict === 'malicious' ? '!' : r.verdict === 'suspicious' ? '?' : '';
  const color = r.verdict === 'malicious' ? '#d93025' : '#e37400';
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  if (text) chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}

// Safety net: catches links opened from anywhere (other apps, address bar,
// redirects) — the content script handles clicks earlier, on the page itself.
chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
  if (await isAllowedOnce(d.url)) return;
  const r = await assessUrl(d.url);
  setBadge(d.tabId, r);
  const s = await getSettings();
  if (r.verdict === 'malicious' || (r.verdict === 'suspicious' && s.blockSuspicious)) {
    chrome.tabs.update(d.tabId, { url: chrome.runtime.getURL('warning.html') + '?url=' + encodeURIComponent(d.url) });
    return;
  }
  // Unencrypted (http) sites: switch to https if the site has it, otherwise warn.
  if (s.warnHttp && d.url.startsWith('http:') && !r.trusted) {
    const host = new URL(d.url).hostname;
    if (isLocalHost(host) || (await isHostAllowed(host))) return;
    const secure = await httpsVersion(d.url);
    const target = secure || chrome.runtime.getURL('warning.html') + '?kind=http&url=' + encodeURIComponent(d.url);
    chrome.tabs.update(d.tabId, { url: target });
  }
});

// Router pages, localhost and other devices on your own network aren't exposed to the internet.
function isLocalHost(host) {
  return host === 'localhost' || host.endsWith('.local') || host.endsWith('.localhost') ||
    /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) || host === '[::1]';
}

// Does the same address work over https? (2.5 s limit; certificate errors count as "no")
async function httpsVersion(url) {
  const u = new URL(url);
  u.protocol = 'https:';
  if (u.port === '80') u.port = '';
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 2500);
  try {
    await fetch(u.href, { method: 'HEAD', redirect: 'follow', credentials: 'omit', cache: 'no-store', signal: ac.signal });
    return u.href;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// "Open anyway" on an http site trusts that site until the browser is closed.
async function allowHost(host) {
  const { allowedHosts = [] } = await chrome.storage.session.get('allowedHosts');
  if (!allowedHosts.includes(host)) allowedHosts.push(host);
  await chrome.storage.session.set({ allowedHosts });
}
async function isHostAllowed(host) {
  const { allowedHosts = [] } = await chrome.storage.session.get('allowedHosts');
  return allowedHosts.includes(host);
}

chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
  const hit = cache.get('fast|' + d.url.replace(/#.*$/, ''));
  if (hit) setBadge(d.tabId, hit.result);
});

// Right-click a link -> "Check this link"
chrome.runtime.onInstalled.addListener((details) => {
  chrome.contextMenus.create({ id: 'ls-check-link', title: 'Check this link with ClickWarden', contexts: ['link'] });
  if (details.reason === 'install') chrome.runtime.openOptionsPage();
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== 'ls-check-link' || !info.linkUrl) return;
  const r = await assessUrl(info.linkUrl, { deep: true });
  const title = { malicious: '⛔ Dangerous link', suspicious: '⚠️ Suspicious link', safe: '✅ No threats found', skipped: 'Not a web link' }[r.verdict];
  const lines = [...(r.sources || []).filter(x => x.status !== 'clean').map(x => `${x.name}: ${x.detail}`), ...(r.reasons || [])];
  if (r.verdict === 'safe') lines.unshift(`Checked with: ${(r.checkedWith || []).join(', ') || 'offline heuristics only'}`);
  notify('ls-link-' + Date.now(), title, `${shorten(r.url, 80)}\n${lines.slice(0, 3).join('\n')}`);
});

// ============================================================
// 2. SUSPICIOUS-DOWNLOAD MONITOR
// ============================================================

const inspected = new Set();
const recentDownloads = []; // { t, origin }

async function recordGesture(origin) {
  await chrome.storage.session.set({ lastGesture: { t: Date.now(), origin } });
}
async function lastGestureAge() {
  const { lastGesture } = await chrome.storage.session.get('lastGesture');
  return lastGesture ? Date.now() - lastGesture.t : Infinity;
}

// Fires before the file gets its final name — earliest point we see the name.
chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  suggest(); // keep Chrome's default name
  inspectDownload(item);
});
// Fallback in case another extension owns onDeterminingFilename.
chrome.downloads.onCreated.addListener((item) => {
  setTimeout(async () => {
    if (inspected.has(item.id)) return;
    const [fresh] = await chrome.downloads.search({ id: item.id });
    if (fresh) inspectDownload(fresh);
  }, 1500);
});

async function inspectDownload(item) {
  if (inspected.has(item.id) || item.byExtensionId === chrome.runtime.id) return;
  inspected.add(item.id);

  const s = await getSettings();
  const url = item.finalUrl || item.url || '';
  const name = baseName(item.filename) || baseName(new URL(url, 'https://x/').pathname) || 'download';
  const f = analyzeFilename(name, item.mime);
  let score = f.score;
  const reasons = [...f.reasons];

  let pageHost = '', pageOrigin = '', srcHost = '';
  try { const r = new URL(item.referrer); pageHost = r.hostname; pageOrigin = r.origin; } catch {}
  try { srcHost = new URL(url).hostname; } catch {}

  // a) Started with no click/keypress from you -> drive-by download
  if (pageOrigin && (await lastGestureAge()) > GESTURE_WINDOW_MS) {
    score += 35;
    reasons.push('Started by the website on its own — you didn\'t click anything (drive-by download)');
  }
  // b) File assembled inside the page (HTML smuggling)
  if (/^(blob|data):/.test(url) && (f.risky || f.ext === 'zip' || f.ext === 'iso')) {
    score += 25;
    reasons.push('Built inside the web page (blob/data URL) — a trick used to sneak malware past filters');
  }
  // c) Served from an unrelated site
  if (pageHost && srcHost && f.risky && registrableDomain(pageHost) !== registrableDomain(srcHost)) {
    score += 10;
    reasons.push(`Comes from ${srcHost}, a different site than the page you are on (${pageHost})`);
  }
  // d) Burst of automatic downloads
  const now = Date.now();
  recentDownloads.push({ t: now, origin: pageOrigin });
  while (recentDownloads.length && now - recentDownloads[0].t > 10000) recentDownloads.shift();
  if (pageOrigin && recentDownloads.filter(x => x.origin === pageOrigin).length >= 3) {
    score += 25;
    reasons.push('This site started several downloads within a few seconds');
  }
  // e) Download link itself on a blocklist
  if (/^https?:/.test(url)) {
    const r = await assessUrl(url);
    if (r.verdict === 'malicious') {
      score += 100;
      for (const x of r.sources.filter(x => x.status === 'malicious')) reasons.unshift(`${x.name}: ${x.detail}`);
    }
  }

  const severity = score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
  const rec = await putDownload({
    id: item.id, name, url, referrer: item.referrer || '', mime: item.mime || '',
    score, severity, reasons, state: item.state, paused: false, t: now,
    hashStatus: 'pending'
  });

  if (severity === 'high') {
    if (s.pauseRiskyDownloads && item.state === 'in_progress') {
      try { await chrome.downloads.pause(item.id); await putDownload({ id: item.id, paused: true }); } catch {}
    }
    openDownloadAlert(item.id);
  } else if (severity === 'medium') {
    notify(`ls-dl-${item.id}`, '⚠️ Unusual download', `${name}\n${reasons.slice(0, 2).join('\n')}`, [{ title: 'Details' }]);
  }
  return rec;
}

function openDownloadAlert(id) {
  chrome.windows.create({
    url: chrome.runtime.getURL('download-alert.html') + '?id=' + id,
    type: 'popup', width: 480, height: 620, focused: true
  });
}

// ============================================================
// 3. KNOWN-MALWARE CHECK ON FINISHED DOWNLOADS
// ============================================================

chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.paused) await putDownload({ id: delta.id, paused: delta.paused.current });
  if (!delta.state) return;
  await putDownload({ id: delta.id, state: delta.state.current });
  if (delta.state.current === 'complete') hashAndCheck(delta.id);
});

function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashAndCheck(id) {
  const s = await getSettings();
  const [item] = await chrome.downloads.search({ id });
  if (!item) return;
  if (!(await getDownload(id))) await inspectDownload(item);
  const set = (patch) => putDownload({ id, ...patch });

  if (!s.hashDownloads) return set({ hashStatus: 'off' });
  if (!s.abuseKey && !s.vtKey) return set({ hashStatus: 'skipped', hashNote: 'Add a MalwareBazaar or VirusTotal key in Settings to check files.' });

  const url = item.finalUrl || item.url;
  const size = item.fileSize > 0 ? item.fileSize : item.bytesReceived;
  if (!/^(https?|data):/.test(url)) {
    return set({ hashStatus: 'skipped', hashNote: 'The browser can\'t re-read this file (it was generated by the page). The desktop watcher will scan it.' });
  }
  if (size > s.maxHashMB * 1024 * 1024) {
    return set({ hashStatus: 'skipped', hashNote: `Larger than ${s.maxHashMB} MB — left to the desktop watcher.` });
  }

  await set({ hashStatus: 'running' });
  try {
    // Extensions can't read files on disk, so we fetch the same bytes again
    // (usually served from the HTTP cache) and hash those.
    const resp = await fetch(url, { credentials: 'include', cache: 'force-cache' });
    if (!resp.ok) throw new Error(`re-download failed (HTTP ${resp.status})`);
    const buf = await resp.arrayBuffer();
    const sha256 = toHex(await crypto.subtle.digest('SHA-256', buf));
    const mismatch = size > 0 && buf.byteLength !== size;
    const intel = await checkHashIntel(sha256, s);

    await set({
      sha256, hashStatus: 'done', hashVerdict: intel.verdict, hashSources: intel.sources, hashErrors: intel.errors,
      hashNote: mismatch ? 'The server sent different bytes the second time, so this hash may not match the saved file. Run the desktop watcher to be sure.' : ''
    });

    const rec = await getDownload(id);
    if (intel.verdict === 'malicious') {
      const why = intel.sources.find(x => x.status === 'malicious');
      notify(`ls-mal-${id}`, '⛔ Known malware downloaded', `${rec.name}\n${why ? why.detail : ''}`, [{ title: 'Delete file' }, { title: 'Details' }], true);
      openDownloadAlert(id);
    } else if (intel.verdict === 'suspicious') {
      notify(`ls-dl-${id}`, '⚠️ Some antivirus engines flag this file', rec.name, [{ title: 'Details' }]);
    }
  } catch (e) {
    await set({ hashStatus: 'error', hashNote: `Couldn't check the file: ${e.message}` });
  }
}

async function deleteDownloadedFile(id) {
  try { await chrome.downloads.removeFile(id); } catch {}
  try { await chrome.downloads.erase({ id }); } catch {}
  await putDownload({ id, state: 'deleted' });
}

// ============================================================
// Notifications + messaging
// ============================================================

function shorten(s, n) { return s && s.length > n ? s.slice(0, n - 1) + '…' : (s || ''); }

function notify(id, title, message, buttons, sticky = false) {
  chrome.notifications.create(id, {
    type: 'basic', iconUrl: 'icons/icon128.png', title, message: shorten(message, 300),
    ...(buttons ? { buttons } : {}), requireInteraction: sticky, priority: sticky ? 2 : 0
  });
}

chrome.notifications.onButtonClicked.addListener(async (nid, idx) => {
  const m = nid.match(/^ls-(dl|mal)-(\d+)$/);
  if (!m) return;
  const id = Number(m[2]);
  if (m[1] === 'mal' && idx === 0) await deleteDownloadedFile(id);
  else openDownloadAlert(id);
  chrome.notifications.clear(nid);
});
chrome.notifications.onClicked.addListener((nid) => {
  const m = nid.match(/^ls-(dl|mal)-(\d+)$/);
  if (m) openDownloadAlert(Number(m[2]));
  chrome.notifications.clear(nid);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'gesture') { recordGesture(msg.origin); return false; }
  (async () => {
    switch (msg.type) {
      case 'check': {
        const r = await assessUrl(msg.url, { deep: !!msg.deep });
        if (sender.tab && msg.isPage) setBadge(sender.tab.id, r);
        return r;
      }
      case 'allowOnce': await allowOnce(msg.url); return { ok: true };
      case 'allowHost': await allowHost(new URL(msg.url).hostname); return { ok: true };
      case 'getSettings': return getSettings();
      case 'saveSettings': cache.clear(); return saveSettings(msg.settings);
      case 'testKeys': return testKeys(msg.settings);
      case 'getDownload': return getDownload(msg.id);
      case 'listDownloads': return getDownloads();
      case 'resumeDownload': await chrome.downloads.resume(msg.id); await putDownload({ id: msg.id, paused: false, userKept: true }); return { ok: true };
      case 'cancelDownload': await chrome.downloads.cancel(msg.id).catch(() => {}); await putDownload({ id: msg.id, state: 'interrupted' }); return { ok: true };
      case 'deleteFile': await deleteDownloadedFile(msg.id); return { ok: true };
      case 'showFile': chrome.downloads.show(msg.id); return { ok: true };
      case 'recheckFile': await hashAndCheck(msg.id); return getDownload(msg.id);
      default: return { error: 'unknown message' };
    }
  })().then(sendResponse, (e) => sendResponse({ error: e.message }));
  return true;
});
