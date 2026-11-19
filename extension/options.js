const $ = (x) => document.getElementById(x);
const send = (m) => chrome.runtime.sendMessage(m);
const TEXT = ['gsbKey', 'abuseKey', 'vtKey'];
const BOOL = ['interceptClicks', 'blockSuspicious', 'warnHttp', 'vtOnNavigation', 'pauseRiskyDownloads', 'hashDownloads'];

function read() {
  const s = {};
  TEXT.forEach(k => { s[k] = $(k).value.trim(); });
  BOOL.forEach(k => { s[k] = $(k).checked; });
  s.maxHashMB = Math.max(1, Math.min(1024, Number($('maxHashMB').value) || 100));
  s.allowlist = $('allowlist').value.split(/[\s,]+/).map(x => x.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '')).filter(Boolean);
  return s;
}

(async () => {
  const s = await send({ type: 'getSettings' });
  TEXT.forEach(k => { $(k).value = s[k] || ''; });
  BOOL.forEach(k => { $(k).checked = !!s[k]; });
  $('maxHashMB').value = s.maxHashMB;
  $('allowlist').value = (s.allowlist || []).join('\n');
})();

$('save').onclick = async () => {
  await send({ type: 'saveSettings', settings: read() });
  $('saved').textContent = 'Saved ✓';
  setTimeout(() => { $('saved').textContent = ''; }, 2000);
};

$('test').onclick = async () => {
  ['r-gsb', 'r-abuse', 'r-vt'].forEach(id => { $(id).textContent = ''; });
  $('test').disabled = true; $('test').textContent = 'Testing…';
  const s = read();
  const r = await send({ type: 'testKeys', settings: s });
  const show = (id, key, val) => {
    if (!key) return;
    $(id).textContent = val || 'No response';
    $(id).style.color = /^OK|works/.test(val || '') ? 'var(--green)' : 'var(--red)';
  };
  show('r-gsb', s.gsbKey, r.gsb); show('r-abuse', s.abuseKey, r.abuse); show('r-vt', s.vtKey, r.vt);
  $('test').disabled = false; $('test').textContent = 'Test keys';
};
