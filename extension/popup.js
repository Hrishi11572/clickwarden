const $ = (x) => document.getElementById(x);
const send = (m) => chrome.runtime.sendMessage(m);
const openOpts = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };
$('opts').onclick = openOpts; $('opts2').onclick = openOpts;

function li(t) { const n = document.createElement('li'); n.textContent = t; return n; }
function label(v) { return { malicious: 'dangerous', suspicious: 'suspicious', safe: 'no threats', skipped: 'n/a' }[v] || v; }

(async () => {
  const s = await send({ type: 'getSettings' });
  if (!s.gsbKey && !s.abuseKey && !s.vtKey) $('warnkeys').style.display = 'block';

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && /^https?:/.test(tab.url)) {
    $('pagehost').textContent = new URL(tab.url).hostname;
    const r = await send({ type: 'check', url: tab.url });
    $('pagechip').className = 'chip ' + r.verdict;
    $('pagechip').textContent = r.trusted ? 'trusted' : label(r.verdict);
    for (const x of r.sources.filter(x => x.status !== 'clean')) $('pagereasons').appendChild(li(`${x.name}: ${x.detail}`));
    for (const x of r.reasons) $('pagereasons').appendChild(li(x));
  } else {
    $('pagechip').className = 'chip skipped'; $('pagechip').textContent = 'n/a';
    $('pagehost').textContent = 'Not a web page';
  }

  const all = await send({ type: 'listDownloads' });
  const list = Object.values(all || {}).sort((a, b) => b.t - a.t).slice(0, 8);
  if (list.length) $('dls').textContent = '';
  for (const d of list) {
    const row = document.createElement('div'); row.className = 'dl';
    const v = d.hashVerdict === 'malicious' ? 'malicious' : d.severity;
    const chip = document.createElement('span'); chip.className = 'chip ' + v;
    chip.textContent = d.hashVerdict === 'malicious' ? 'malware' : d.severity === 'low' ? (d.hashVerdict === 'clean' ? 'clean' : 'ok') : d.severity;
    const n = document.createElement('span'); n.className = 'n'; n.textContent = d.name; n.title = d.name;
    row.append(chip, n);
    row.onclick = () => chrome.windows.create({ url: chrome.runtime.getURL('download-alert.html') + '?id=' + d.id, type: 'popup', width: 480, height: 620 });
    $('dls').appendChild(row);
  }
})();

async function checkTyped() {
  let url = $('u').value.trim();
  if (!url) return;
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  $('result').textContent = 'Checking…';
  const r = await send({ type: 'check', url, deep: true });
  const box = $('result'); box.textContent = '';
  const chip = document.createElement('span'); chip.className = 'chip ' + r.verdict; chip.textContent = label(r.verdict);
  box.appendChild(chip);
  const ul = document.createElement('ul'); ul.className = 'reasons';
  for (const x of r.sources || []) ul.appendChild(li(`${x.name}: ${x.detail || x.status}`));
  for (const x of r.reasons || []) ul.appendChild(li(x));
  for (const x of r.errors || []) ul.appendChild(li('⚠ ' + x));
  if (r.verdict === 'safe' && !(r.checkedWith || []).length) ul.appendChild(li('Only offline checks ran — add API keys for blocklist lookups.'));
  box.appendChild(ul);
}
$('go').onclick = checkTyped;
$('u').addEventListener('keydown', (e) => { if (e.key === 'Enter') checkTyped(); });
