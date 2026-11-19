// Settings + download records, persisted in chrome.storage.local.

export const DEFAULTS = {
  gsbKey: '',              // Google Safe Browsing API key
  abuseKey: '',            // abuse.ch Auth-Key (URLhaus + MalwareBazaar)
  vtKey: '',               // VirusTotal API key
  interceptClicks: true,   // hold cross-site link clicks until checked
  blockSuspicious: false,  // also block (not just flag) heuristic-only "suspicious" links
  warnHttp: true,          // warn before opening unencrypted (http) sites
  vtOnNavigation: false,   // use VirusTotal for every page load (free tier = 4/min, 500/day)
  pauseRiskyDownloads: true,
  hashDownloads: true,     // hash finished downloads and look them up
  maxHashMB: 100,
  allowlist: []            // trusted domains, e.g. ["iitkgp.ac.in"]
};

export async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULTS, ...(settings || {}) };
}

export async function saveSettings(patch) {
  const cur = await getSettings();
  const next = { ...cur, ...patch };
  await chrome.storage.local.set({ settings: next });
  return next;
}

const MAX_RECORDS = 50;

export async function getDownloads() {
  const { downloads } = await chrome.storage.local.get('downloads');
  return downloads || {};
}

export async function putDownload(rec) {
  const all = await getDownloads();
  all[rec.id] = { ...(all[rec.id] || {}), ...rec };
  const ids = Object.keys(all).sort((a, b) => (all[b].t || 0) - (all[a].t || 0));
  for (const id of ids.slice(MAX_RECORDS)) delete all[id];
  await chrome.storage.local.set({ downloads: all });
  return all[rec.id];
}

export async function getDownload(id) {
  return (await getDownloads())[id] || null;
}
