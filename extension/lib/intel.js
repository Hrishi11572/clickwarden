// Threat-intelligence lookups. Each provider returns
// { status: 'malicious' | 'suspicious' | 'clean' | 'unknown', detail?: string }.

const TIMEOUT_MS = 6000;

async function tfetch(url, opts = {}, ms = TIMEOUT_MS) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ac.signal, credentials: 'omit' });
  } catch (e) {
    throw new Error(e.name === 'AbortError' ? 'timed out' : e.message);
  } finally {
    clearTimeout(timer);
  }
}

function b64url(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function httpError(r, name) {
  if (r.status === 401 || r.status === 403) return new Error(`${name}: API key rejected (HTTP ${r.status})`);
  if (r.status === 429) return new Error(`${name}: rate limit reached`);
  return new Error(`${name}: HTTP ${r.status}`);
}

// ---------- URL providers ----------

async function googleSafeBrowsing(url, key) {
  const r = await tfetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client: { clientId: 'clickwarden', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    })
  });
  if (!r.ok) throw httpError(r, 'Google Safe Browsing');
  const j = await r.json();
  if (j.matches && j.matches.length) {
    const types = [...new Set(j.matches.map(m => m.threatType))]
      .map(t => ({ SOCIAL_ENGINEERING: 'phishing / deceptive site', MALWARE: 'malware', UNWANTED_SOFTWARE: 'unwanted software', POTENTIALLY_HARMFUL_APPLICATION: 'harmful app' }[t] || t));
    return { status: 'malicious', detail: `Flagged as ${types.join(', ')}` };
  }
  return { status: 'clean' };
}

async function urlhaus(url, key) {
  const r = await tfetch('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST',
    headers: { 'Auth-Key': key },
    body: new URLSearchParams({ url })
  });
  if (!r.ok) throw httpError(r, 'URLhaus');
  const j = await r.json();
  if (j.query_status === 'ok') {
    const tags = j.tags && j.tags.length ? ` — ${j.tags.join(', ')}` : '';
    return { status: 'malicious', detail: `Known malware-distribution URL (${j.threat || 'malware'}, currently ${j.url_status})${tags}` };
  }
  if (j.query_status === 'no_results') return { status: 'clean' };
  throw new Error(`URLhaus: ${j.query_status}`);
}

function vtStats(attrs) {
  const st = (attrs && attrs.last_analysis_stats) || {};
  const total = Object.values(st).reduce((a, b) => a + (b || 0), 0);
  return { mal: st.malicious || 0, sus: st.suspicious || 0, total };
}

async function virusTotalUrl(url, key) {
  const r = await tfetch(`https://www.virustotal.com/api/v3/urls/${b64url(url)}`, { headers: { 'x-apikey': key } });
  if (r.status === 404) return { status: 'unknown', detail: 'VirusTotal has not scanned this URL before' };
  if (!r.ok) throw httpError(r, 'VirusTotal');
  const j = await r.json();
  const { mal, sus, total } = vtStats(j.data && j.data.attributes);
  if (mal >= 2) return { status: 'malicious', detail: `${mal} of ${total} security vendors flag this URL` };
  if (mal >= 1 || sus >= 2) return { status: 'suspicious', detail: `${mal} malicious / ${sus} suspicious of ${total} vendors` };
  return { status: 'clean', detail: `0 of ${total} vendors flag it` };
}

// ---------- File-hash providers ----------

async function malwareBazaar(sha256, key) {
  const r = await tfetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Auth-Key': key },
    body: new URLSearchParams({ query: 'get_info', hash: sha256 })
  });
  if (!r.ok) throw httpError(r, 'MalwareBazaar');
  const j = await r.json();
  if (j.query_status === 'ok' && j.data && j.data[0]) {
    const d = j.data[0];
    const tags = d.tags && d.tags.length ? ` — tags: ${d.tags.slice(0, 5).join(', ')}` : '';
    return { status: 'malicious', detail: `Known malware sample: ${d.signature || 'unclassified'} (${d.file_type || 'file'})${tags}` };
  }
  if (j.query_status === 'hash_not_found' || j.query_status === 'no_results') return { status: 'unknown', detail: 'Not in MalwareBazaar' };
  throw new Error(`MalwareBazaar: ${j.query_status}`);
}

async function virusTotalFile(sha256, key) {
  const r = await tfetch(`https://www.virustotal.com/api/v3/files/${sha256}`, { headers: { 'x-apikey': key } });
  if (r.status === 404) return { status: 'unknown', detail: 'VirusTotal has never seen this file' };
  if (!r.ok) throw httpError(r, 'VirusTotal');
  const j = await r.json();
  const a = j.data && j.data.attributes;
  const { mal, sus, total } = vtStats(a);
  const label = a && a.popular_threat_classification && a.popular_threat_classification.suggested_threat_label;
  if (mal >= 3) return { status: 'malicious', detail: `${mal} of ${total} antivirus engines detect it${label ? ` (${label})` : ''}` };
  if (mal >= 1 || sus >= 2) return { status: 'suspicious', detail: `${mal} of ${total} engines detect it — possibly a false positive${label ? ` (${label})` : ''}` };
  return { status: 'clean', detail: `0 of ${total} engines detect it` };
}

// ---------- Aggregation ----------

async function runAll(jobs) {
  const out = { malicious: false, suspicious: false, sources: [], errors: [], checkedWith: [] };
  await Promise.all(jobs.map(async ([name, fn]) => {
    try {
      const r = await fn();
      out.checkedWith.push(name);
      if (r.status === 'malicious') out.malicious = true;
      if (r.status === 'suspicious') out.suspicious = true;
      out.sources.push({ name, status: r.status, detail: r.detail || '' });
    } catch (e) {
      out.errors.push(e.message.startsWith(name) ? e.message : `${name}: ${e.message}`);
    }
  }));
  out.verdict = out.malicious ? 'malicious' : out.suspicious ? 'suspicious'
    : out.sources.some(s => s.status === 'clean') ? 'clean' : 'unknown';
  return out;
}

export function checkUrlIntel(url, s, { useVt = false } = {}) {
  const jobs = [];
  if (s.gsbKey) jobs.push(['Google Safe Browsing', () => googleSafeBrowsing(url, s.gsbKey)]);
  if (s.abuseKey) jobs.push(['URLhaus', () => urlhaus(url, s.abuseKey)]);
  if (s.vtKey && useVt) jobs.push(['VirusTotal', () => virusTotalUrl(url, s.vtKey)]);
  return runAll(jobs);
}

export function checkHashIntel(sha256, s) {
  const jobs = [];
  if (s.abuseKey) jobs.push(['MalwareBazaar', () => malwareBazaar(sha256, s.abuseKey)]);
  if (s.vtKey) jobs.push(['VirusTotal', () => virusTotalFile(sha256, s.vtKey)]);
  return runAll(jobs);
}

// Used by the options page "Test keys" button.
export async function testKeys(s) {
  const res = {};
  const EICAR = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
  const tasks = [];
  if (s.gsbKey) tasks.push(googleSafeBrowsing('http://malware.testing.google.test/testing/malware/', s.gsbKey)
    .then(r => { res.gsb = r.status === 'malicious' ? 'OK — test URL correctly flagged' : 'Key works, but test URL not flagged'; })
    .catch(e => { res.gsb = e.message; }));
  if (s.abuseKey) tasks.push(urlhaus('https://example.com/', s.abuseKey)
    .then(() => { res.abuse = 'OK — URLhaus & MalwareBazaar key accepted'; })
    .catch(e => { res.abuse = e.message; }));
  if (s.vtKey) tasks.push(virusTotalFile(EICAR, s.vtKey)
    .then(r => { res.vt = r.status === 'malicious' ? 'OK — EICAR test file correctly detected' : `Key works (${r.detail})`; })
    .catch(e => { res.vt = e.message; }));
  await Promise.all(tasks);
  return res;
}
