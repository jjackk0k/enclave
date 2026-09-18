// VARVEL — native technology-stack fingerprinting (authorized engagements).
//
// The Wappalyzer slot, built native — and QUIETER than Wappalyzer-by-HTTP: this engine
// is a PURE FUNCTION over pages the engagement already fetched (crawl/webscan/apisurface
// bodies + headers). Zero additional requests to the target. The recon already paid for
// the evidence; this extracts every drop of signal from it.
//
// Signals, in descending reliability: headers (server/x-powered-by/x-generator), cookies
// (JSESSIONID/PHPSESSID/ARRAffinity…), meta generator tags, asset paths (wp-content,
// /sites/default/), script srcs, and inline HTML/JS markers. Every hit carries the
// EVIDENCE string that produced it — a VARVEL tech claim is explainable, never a vibe.
//
// The output feeds two consumers: the surface graph (`tech` nodes, optionally versioned)
// and vulncheck's template selection (check the stack you actually found, not everything).

// Signature table. Each tech: id, label, categories, and signal matchers.
// A signal = { where: 'headers'|'cookies'|'body', re } with optional version capture.
export const TECH_SIGNATURES = [
  // ——— platforms / CMS ———
  { id: 'wordpress', label: 'WordPress', cat: 'cms', sig: [
    { where: 'body', re: /\/wp-(?:content|includes)\//i },
    { where: 'body', re: /<meta name="generator" content="WordPress ([\d.]+)"/i, version: 1 },
  ]},
  { id: 'drupal', label: 'Drupal', cat: 'cms', sig: [
    { where: 'body', re: /\/sites\/default\/files|Drupal\.settings/i },
    { where: 'headers', re: /x-generator:\s*Drupal\s*([\d.]*)/i, version: 1 },
  ]},
  { id: 'joomla', label: 'Joomla', cat: 'cms', sig: [
    { where: 'body', re: /\/media\/jui\/|<meta name="generator" content="Joomla!?\s*-?\s*([\d.]*)/i, version: 1 },
  ]},
  { id: 'shopify', label: 'Shopify', cat: 'commerce', sig: [
    { where: 'body', re: /cdn\.shopify\.com|Shopify\.theme/i },
    { where: 'headers', re: /x-shopid|x-shopify-stage/i },
  ]},
  // ——— frameworks / runtimes ———
  { id: 'nextjs', label: 'Next.js', cat: 'framework', sig: [
    { where: 'body', re: /\/_next\/static\/|__NEXT_DATA__/i },
    { where: 'headers', re: /x-powered-by:\s*Next\.js/i },
  ]},
  { id: 'nuxt', label: 'Nuxt', cat: 'framework', sig: [
    { where: 'body', re: /\/_nuxt\/|__NUXT__/i },
  ]},
  { id: 'react', label: 'React', cat: 'frontend', sig: [
    { where: 'body', re: /data-reactroot|data-reactid|__REACT_DEVTOOLS/i },
  ]},
  { id: 'vue', label: 'Vue.js', cat: 'frontend', sig: [
    { where: 'body', re: /data-v-[0-9a-f]{8}|__VUE__/i },
  ]},
  { id: 'angular', label: 'Angular', cat: 'frontend', sig: [
    { where: 'body', re: /ng-version="([\d.]+)"|ng-app\b/i, version: 1 },
  ]},
  { id: 'jquery', label: 'jQuery', cat: 'frontend', sig: [
    { where: 'body', re: /jquery[-.]?(?:min\.)?js|jquery-([\d.]+)(?:\.min)?\.js/i, version: 1 },
  ]},
  { id: 'laravel', label: 'Laravel', cat: 'framework', sig: [
    { where: 'cookies', re: /laravel_session=/i },
    { where: 'body', re: /Laravel\.csrfToken|csrf-token" content=/i },
  ]},
  { id: 'django', label: 'Django', cat: 'framework', sig: [
    { where: 'cookies', re: /csrftoken=/i },
    { where: 'body', re: /csrfmiddlewaretoken/i },
  ]},
  { id: 'rails', label: 'Ruby on Rails', cat: 'framework', sig: [
    { where: 'cookies', re: /_session_id=|_rails/i },
    { where: 'headers', re: /x-powered-by:\s*Phusion Passenger/i },
  ]},
  { id: 'aspnet', label: 'ASP.NET', cat: 'framework', sig: [
    { where: 'headers', re: /x-powered-by:\s*ASP\.NET|x-aspnet-version:\s*([\d.]+)/i, version: 1 },
    { where: 'cookies', re: /ASP\.NET_SessionId=|\.AspNetCore\./i },
    { where: 'body', re: /__VIEWSTATE|__EVENTVALIDATION/i },
  ]},
  { id: 'spring', label: 'Spring (Java)', cat: 'framework', sig: [
    { where: 'cookies', re: /JSESSIONID=/i },
    { where: 'headers', re: /x-application-context/i },
  ]},
  { id: 'express', label: 'Express (Node.js)', cat: 'framework', sig: [
    { where: 'headers', re: /x-powered-by:\s*Express/i },
  ]},
  // ——— languages ———
  { id: 'php', label: 'PHP', cat: 'language', sig: [
    { where: 'headers', re: /x-powered-by:\s*PHP\/([\d.]+)/i, version: 1 },
    { where: 'cookies', re: /PHPSESSID=/i },
  ]},
  // ——— servers / infra ———
  { id: 'nginx', label: 'nginx', cat: 'server', sig: [
    { where: 'headers', re: /server:\s*nginx\/?([\d.]*)/i, version: 1 },
  ]},
  { id: 'apache', label: 'Apache httpd', cat: 'server', sig: [
    { where: 'headers', re: /server:\s*Apache\/?([\d.]*)/i, version: 1 },
  ]},
  { id: 'iis', label: 'Microsoft IIS', cat: 'server', sig: [
    { where: 'headers', re: /server:\s*Microsoft-IIS\/([\d.]+)/i, version: 1 },
    { where: 'cookies', re: /ARRAffinity=/i },
  ]},
  { id: 'tomcat', label: 'Apache Tomcat', cat: 'server', sig: [
    { where: 'headers', re: /server:\s*Apache-Coyote/i },
    // VERSION CAPTURE (2026-09-16 coverage audit): Tomcat's own error/status pages state the
    // version ("Apache Tomcat/9.0.65"), which is the only way a bare fingerprint can activate
    // the (large) Tomcat CVE pack — 3475 CPE nodes are otherwise inert. Presence-only stays
    // version:null, so cveCheck still refuses a versionless claim.
    { where: 'body', re: /Apache Tomcat\/([\d.]+)/i, version: 1 },
  ]},
  // phpMyAdmin (2026-09-16 coverage audit): one of the largest web-app product families in the
  // 2016-2026 NVD feeds (3732 CPE nodes) and a classic high-impact surface (auth bypass / SQLi /
  // RCE). Its login page identifies itself and usually states the version.
  { id: 'phpmyadmin', label: 'phpMyAdmin', cat: 'tool', sig: [
    { where: 'body', re: /phpMyAdmin\s+([\d]+\.[\d]+\.[\d]+)/i, version: 1 },
    { where: 'body', re: /id="pma_(?:username|password)"|name="pma_username"|phpMyAdmin/i },
    { where: 'cookies', re: /pma_lang=|phpMyAdmin=/i },
  ]},
  { id: 'cloudflare', label: 'Cloudflare', cat: 'cdn-waf', sig: [
    { where: 'headers', re: /server:\s*cloudflare|cf-ray:/i },
    { where: 'cookies', re: /__cf_bm=|cf_clearance=/i },
  ]},
  { id: 'akamai', label: 'Akamai', cat: 'cdn-waf', sig: [
    { where: 'headers', re: /x-akamai|akamai-ghost|server:\s*AkamaiGHost/i },
  ]},
  // ——— analytics / tag ———
  { id: 'ga', label: 'Google Analytics', cat: 'analytics', sig: [
    { where: 'body', re: /google-analytics\.com\/(?:analytics|ga)\.js|googletagmanager\.com\/gtag\/js\?id=(G-[\w]+)/i, version: 1 },
  ]},
  { id: 'gtm', label: 'Google Tag Manager', cat: 'analytics', sig: [
    { where: 'body', re: /googletagmanager\.com\/gtm\.js\?id=(GTM-[\w]+)/i, version: 1 },
  ]},
  { id: 'recaptcha', label: 'reCAPTCHA', cat: 'security', sig: [
    { where: 'body', re: /google\.com\/recaptcha\/api\.js|g-recaptcha/i },
  ]},
  { id: 'hcaptcha', label: 'hCaptcha', cat: 'security', sig: [
    { where: 'body', re: /hcaptcha\.com\/1\/api\.js|h-captcha/i },
  ]},
];

// Serialize a headers object into one scannable string ("name: value" lines).
function headerString(headers) {
  if (!headers || typeof headers !== 'object') return '';
  return Object.entries(headers).map(([k, v]) => k.toLowerCase() + ': ' + (Array.isArray(v) ? v.join('; ') : String(v))).join('\n');
}
function cookieString(headers) {
  if (!headers || typeof headers !== 'object') return '';
  return ([]).concat(headers['set-cookie'] || []).join('\n');
}

// Detect tech on ONE fetched page. Pure function — no I/O.
//   page: { headers: {...}, body: '...' }
// Returns hits: [{ id, label, cat, version|null, evidence }] — one per signature MATCH.
export function detectOnPage(page) {
  const hStr = headerString(page && page.headers);
  const cStr = cookieString(page && page.headers);
  const body = String((page && page.body) || '');
  const hits = [];
  for (const tech of TECH_SIGNATURES) {
    let best = null;
    for (const s of tech.sig) {
      const hay = s.where === 'headers' ? hStr : s.where === 'cookies' ? cStr : body;
      if (!hay) continue;
      const m = s.re.exec(hay);
      if (!m) continue;
      const hit = {
        id: tech.id, label: tech.label, cat: tech.cat,
        version: s.version != null && m[s.version] ? m[s.version] : null,
        evidence: m[0].replace(/\s+/g, ' ').slice(0, 80),
      };
      // Prefer the VERSION-BEARING match — a bare "/wp-content/" path shouldn't hide the
      // meta-generator version sitting right next to it in the same page.
      if (!best || (!best.version && hit.version)) best = hit;
      if (best.version) break;
    }
    if (best) hits.push(best);
  }
  return hits;
}

// Aggregate hits across MANY pages (a crawl's worth). Confidence rises with distinct
// pages confirming the same tech: 1 page = 'firm', ≥2 = 'confirmed'. Best version wins
// (first non-null seen). Returns [{ id, label, cat, version, confidence, pages, evidence }].
export function fingerprintPages(pages) {
  const agg = new Map();
  for (const page of Array.isArray(pages) ? pages : []) {
    for (const hit of detectOnPage(page)) {
      const cur = agg.get(hit.id) || { id: hit.id, label: hit.label, cat: hit.cat, version: null, pages: 0, evidence: hit.evidence };
      cur.pages++;
      if (!cur.version && hit.version) cur.version = hit.version;
      agg.set(hit.id, cur);
    }
  }
  return [...agg.values()]
    .map((t) => ({ ...t, confidence: t.pages >= 2 ? 'confirmed' : 'firm' }))
    .sort((a, b) => b.pages - a.pages || a.id.localeCompare(b.id));
}
