const params = new URLSearchParams(location.search);
const url = params.get('url') || '';
const kind = params.get('kind') || 'threat';
const $ = (id) => document.getElementById(id);
$('url').textContent = url;

function li(text) { const n = document.createElement('li'); n.textContent = text; return n; }

if (kind === 'http') {
  // Unencrypted site, and it has no secure (https) version.
  document.title = 'ClickWarden — not encrypted';
  $('banner').className = 'banner suspicious';
  $('title').textContent = '⚠️ This site isn\'t encrypted';
  $('subtitle').textContent = 'It only works over http, and has no secure (https) version.';
  $('why').textContent = 'What this means';
  const ul = $('reasons');
  ul.textContent = '';
  ul.appendChild(li('Anything you send or receive on this site travels as plain text.'));
  ul.appendChild(li('On shared Wi-Fi (hostel, café, campus), others on the network could read it, or change the page you see.'));
  ul.appendChild(li('Fine for just reading. Don\'t type passwords, OTPs, card or bank details here.'));
  $('checked').textContent = 'ClickWarden tried the secure https version first. It wasn\'t available.';
  $('proceed').textContent = 'Open anyway';
} else {
  chrome.runtime.sendMessage({ type: 'check', url }).then((r) => {
    const ul = $('reasons');
    ul.textContent = '';
    if (!r || r.error) { ul.appendChild(li('Could not load details.')); return; }
    if (r.verdict === 'suspicious') {
      $('banner').className = 'banner suspicious';
      $('title').textContent = '⚠️ ClickWarden: this page looks suspicious';
      $('subtitle').textContent = 'It isn\'t on a blocklist, but it shows several signs of phishing.';
    }
    for (const s of r.sources.filter(s => s.status === 'malicious' || s.status === 'suspicious')) ul.appendChild(li(`${s.name}: ${s.detail}`));
    for (const why of r.reasons) ul.appendChild(li(why));
    if (!ul.children.length) ul.appendChild(li('Flagged by a threat-intelligence source.'));
    $('checked').textContent = r.checkedWith.length ? `Checked with: ${r.checkedWith.join(', ')} + offline heuristics` : 'Checked with offline heuristics';
  });
}

$('back').onclick = async () => {
  const tab = await chrome.tabs.getCurrent();
  chrome.tabs.update(tab.id, { url: 'chrome://newtab/' });
};

$('proceed').onclick = async () => {
  if (kind === 'http') {
    // Trust this site until the browser is closed, so its other pages don't warn again.
    await chrome.runtime.sendMessage({ type: 'allowHost', url });
  } else {
    if (!confirm('This page may steal your passwords or install malware. Open it anyway?')) return;
    await chrome.runtime.sendMessage({ type: 'allowOnce', url });
  }
  location.replace(url);
};
