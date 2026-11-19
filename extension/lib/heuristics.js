// Offline URL heuristics. These never call the network; they catch common
// phishing tricks that blocklists haven't caught up with yet.

const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.in', 'ac.in', 'gov.in', 'org.in', 'net.in',
  'edu.in', 'res.in', 'nic.in', 'firm.in', 'com.au', 'net.au', 'org.au', 'co.jp', 'ne.jp',
  'com.br', 'co.nz', 'co.za', 'com.cn', 'com.sg', 'com.my', 'com.mx', 'co.kr', 'com.tr'
]);

export function registrableDomain(host) {
  host = (host || '').toLowerCase().replace(/\.$/, '');
  if (isIp(host)) return host;
  const p = host.split('.');
  if (p.length <= 2) return host;
  const last2 = p.slice(-2).join('.');
  return MULTI_PART_SUFFIXES.has(last2) ? p.slice(-3).join('.') : last2;
}

export function isIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || /^0x[0-9a-f]+$/i.test(host) || /^\d{8,10}$/.test(host);
}

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'click', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'country', 'kim',
  'loan', 'rest', 'support', 'cam', 'icu', 'monster', 'buzz', 'cfd', 'sbs', 'quest', 'bond', 'lol'
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly', 'shorturl.at',
  'tiny.cc', 'rebrand.ly', 'buff.ly', 's.id', 'v.gd'
]);

// brand -> domains that legitimately use it
const BRANDS = {
  paypal: ['paypal.com', 'paypal.me'],
  apple: ['apple.com', 'icloud.com', 'apple.news'],
  google: ['google.com', 'google.co.in', 'youtube.com', 'gmail.com', 'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'goo.gl', 'withgoogle.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'azure.com', 'windows.net', 'sharepoint.com', 'bing.com'],
  outlook: ['outlook.com', 'live.com', 'office.com'],
  office365: ['office.com', 'microsoft.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazonaws.com', 'amazon.co.uk', 'media-amazon.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'fb.com', 'fbcdn.net'],
  instagram: ['instagram.com', 'cdninstagram.com'],
  whatsapp: ['whatsapp.com', 'whatsapp.net', 'wa.me'],
  linkedin: ['linkedin.com', 'licdn.com'],
  github: ['github.com', 'github.io', 'githubusercontent.com'],
  dropbox: ['dropbox.com', 'dropboxusercontent.com'],
  sbi: ['onlinesbi.sbi', 'sbi.co.in', 'onlinesbi.com', 'sbi'],
  hdfcbank: ['hdfcbank.com'],
  icicibank: ['icicibank.com'],
  axisbank: ['axisbank.com'],
  paytm: ['paytm.com', 'paytm.in'],
  phonepe: ['phonepe.com'],
  flipkart: ['flipkart.com'],
  irctc: ['irctc.co.in'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
  steam: ['steampowered.com', 'steamcommunity.com']
};

function legitFor(brand, host, reg) {
  const list = BRANDS[brand];
  if (list.some(d => host === d || host.endsWith('.' + d))) return true;
  const firstLabel = reg.split('.')[0];
  const tld = reg.split('.').pop();
  return firstLabel === brand && !SUSPICIOUS_TLDS.has(tld); // e.g. google.de, amazon.co.jp
}

function deLeet(s) {
  return s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/1/g, 'l')
    .replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/\$/g, 's');
}

/**
 * @param {URL|string} input
 * @returns {{score:number, reasons:string[]}}
 */
export function analyzeUrl(input) {
  let u;
  try { u = input instanceof URL ? input : new URL(input); } catch { return { score: 0, reasons: [] }; }
  const reasons = [];
  let score = 0;
  const add = (pts, why) => { score += pts; reasons.push(why); };

  const host = u.hostname.toLowerCase();
  const reg = registrableDomain(host);
  const tld = host.split('.').pop();

  if (isIp(host)) add(30, 'Uses a raw IP address instead of a domain name');
  if (host.split('.').some(l => l.startsWith('xn--'))) add(25, 'Domain uses look-alike international characters (punycode)');
  if (u.username || u.password) add(40, 'Contains an "@" trick that hides the real destination');
  if (host.split('.').length > 5) add(15, 'Unusually many subdomains');
  if (host.length > 50) add(10, 'Very long domain name');
  if (SUSPICIOUS_TLDS.has(tld)) add(15, `".${tld}" domains are frequently used for scams`);
  if (u.port && !['80', '443', ''].includes(u.port)) add(10, `Non-standard port :${u.port}`);
  if (u.protocol === 'http:') add(5, 'Not encrypted (http, not https)');
  if (u.href.length > 250) add(5, 'Extremely long URL');
  if ((u.href.match(/%[0-9a-f]{2}/gi) || []).length > 15) add(5, 'Heavily encoded URL');
  if (/(^|[.-])(kyc|verify|verification|secure|login|signin|account|update|support|alert|suspend|unlock|wallet|refund|reward|helpdesk)([.-]|$)/.test(host.slice(0, host.length - tld.length - 1)) && host.includes('-')) {
    add(15, 'Domain name uses typical scam words (verify / support / kyc …)');
  }
  if (SHORTENERS.has(host)) add(5, 'Link shortener — the real destination is hidden');

  // Brand impersonation: brand in the hostname, but not the brand's own domain.
  const tokens = host.split(/[.-]/);
  const normHost = deLeet(host);
  for (const brand of Object.keys(BRANDS)) {
    if (legitFor(brand, host, reg)) continue;
    const literal = tokens.includes(brand) || (brand.length >= 5 && host.includes(brand));
    if (literal) { add(35, `Mentions "${brand}" but is not ${brand}'s real website`); break; }
    if (brand.length >= 5 && normHost.includes(brand) && !host.includes(brand)) { add(40, `Imitates "${brand}" using look-alike characters`); break; }
  }

  if (score > 0 && /(login|log-in|signin|sign-in|verify|account|update|secure|wallet|password|kyc|unlock|suspend)/i.test(u.pathname + u.search)) {
    add(10, 'Asks for login / verification on an already-questionable site');
  }

  return { score, reasons };
}
