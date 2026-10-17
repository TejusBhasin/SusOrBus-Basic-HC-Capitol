const dns = require("node:dns").promises;
const https = require("node:https");
const net = require("node:net");

const MAX_HTML_BYTES = 1_000_000;
const MAX_REDIRECTS = 5;

function cleanTarget(raw) {
  let input = String(raw || "").trim();
  if (!input) return "";
  if (!/^https?:\/\//i.test(input)) input = "https://" + input;
  try {
    const url = new URL(input);
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) return "";
    return url.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "";
  }
}

function isPublicAddress(address) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split(".").map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127));
  }
  if (net.isIPv6(address)) {
    const ip = address.toLowerCase();
    const mapped = ip.match(/(?:^::ffff:|^0:0:0:0:0:ffff:)(\\d+\\.\\d+\\.\\d+\\.\\d+)$/);
    if (mapped) return isPublicAddress(mapped[1]);
    const first = parseInt(ip.split(":")[0] || "0", 16);
    // Accept only globally routable IPv6 unicast and exclude documentation space.
    return first >= 0x2000 && first < 0x4000 && !ip.startsWith("2001:db8:");
  }
  return false;
}

async function resolvePublic(hostname) {
  if (!hostname || hostname.length > 253 || hostname === "localhost" ||
      hostname.endsWith(".localhost") || hostname.endsWith(".local") ||
      net.isIP(hostname)) throw new Error("That address is not allowed.");
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some(record => !isPublicAddress(record.address))) {
    throw new Error("That address is not allowed.");
  }
  return records[0];
}

function requestOnce(url, address) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method: "GET",
      servername: url.hostname,
      lookup: (_host, options, callback) => {
        if (options && options.all) callback(null, [address]);
        else callback(null, address.address, address.family);
      },
      headers: {
        "User-Agent": "SusOrBus/1.0",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        "Host": url.host
      }
    }, response => {
      let body = "";
      let size = 0;
      response.setEncoding("utf8");
      response.on("data", chunk => {
        size += Buffer.byteLength(chunk, "utf8");
        if (Buffer.byteLength(body, "utf8") < MAX_HTML_BYTES) body += chunk;
      });
      response.on("end", () => resolve({ status: response.statusCode || 0,
        location: response.headers.location, headers: response.headers,
        body: body.slice(0, MAX_HTML_BYTES) }));
      response.on("error", reject);
    });
    req.setTimeout(10_000, () => req.destroy(new Error("Request timed out.")));
    req.on("error", reject);
    req.end();
  });
}

async function fetchPage(input) {
  let url = input instanceof URL ? input : new URL(input);
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    if (!["https:", "http:"].includes(url.protocol)) throw new Error("Unsupported redirect.");
    // Always use TLS, including redirects that request plain HTTP.
    url.protocol = "https:";
    const address = await resolvePublic(url.hostname);
    const result = await requestOnce(url, address);
    if ([301, 302, 303, 307, 308].includes(result.status) && result.location) {
      if (i === MAX_REDIRECTS) throw new Error("Too many redirects.");
      url = new URL(result.location, url);
      continue;
    }
    return { status: result.status, html: result.body, url: url.href, headers: result.headers };
  }
  throw new Error("Too many redirects.");
}

function analyze(html, host, finalUrl) {
  const low = html.toLowerCase();
  const findings = [];
  const add = (level, category, title, simple, nerd) =>
    findings.push({ level, category, title, simple, nerd });

  if (finalUrl.startsWith("https:")) add("good", "security", "HTTPS Transport",
    "The connection to this page is encrypted, keeping your information private from snoops.",
    "The final response URL is served over TLS.");
  else add("bad", "security", "Unencrypted Connection",
    "This page loads over a plain, unencrypted connection.",
    "The final response URL uses HTTP.");

  if (/<input[^>]+type=["']password["']/i.test(html))
    add("bad", "security", "Password Field Detected",
      "This page asks for a password. Double-check the address before typing anything.",
      "A password input was present in the fetched HTML.");
  else add("good", "security", "No Credential Fields",
    "We didn't find a password field on this page.",
    "No password input elements were found.");

  const words = ["urgent", "winner", "congratulations", "verify your account", "bitcoin", "free money", "click here to claim"];
  const hits = words.filter(word => low.includes(word));
  if (hits.length) add("bad", "content", "Scam Language Detected",
    "The page uses phrases commonly found in scams: " + hits.join(", ") + ".",
    "Matched phrases: " + hits.join(", ") + ".");
  else add("good", "content", "No Scam Keywords",
    "We didn't find common pressure tactics or scam phrases.",
    "No tracked scam keywords matched.");

  if (low.includes("<form")) add("warning", "content", "Form Collects Your Data",
    "This page has a form. Only submit it if you trust the site.",
    "A form element was present.");
  if (low.includes("<iframe")) add("warning", "code", "Embedded External Content",
    "This page shows content from another site inside a frame.",
    "An iframe element was present.");

  const scripts = (low.match(/<script[\s>]/g) || []).length;
  if (scripts === 0) add("good", "code", "Minimal Client-Side Code",
    "There's almost no code running on this page.",
    "Zero script elements were found.");
  else if (scripts > 15) add("warning", "code", "Heavy Scripting",
    "This page runs a lot of code, which can increase tracking or other risks.",
    scripts + " script elements were found.");

  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const freeTld = /\.(tk|ml|ga|cf|gq)$/.test(host);
  const hyphens = (host.match(/-/g) || []).length;
  if (isIp) add("bad", "reputation", "IP Address as URL",
    "This link is a raw IP address instead of a normal domain name.",
    "The host is a bare IPv4 address.");
  else if (freeTld || hyphens >= 2 || host.replace(/\./g, "").length > 30)
    add("warning", "reputation", "Unusual Domain Pattern",
      "The web address has a pattern often used by generated scam domains.",
      "The domain has a free TLD, several hyphens, or an unusually long name.");
  else add("good", "reputation", "Normal Domain Pattern",
    "The web address looks like a normal, human-chosen domain name.",
    "The host has a reasonable length and hyphen count.");

  return findings;
}

function extractPolicyLinks(html, base) {
  const found = { terms: null, privacy: null };
  const re = /<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = re.exec(html))) {
    const text = match[2].replace(/<[^>]+>/g, " ").toLowerCase();
    const hay = (match[1] + " " + text).toLowerCase();
    let url;
    try { url = new URL(match[1], base).href; } catch { continue; }
    if (!found.terms && /terms|conditions|\btos\b/.test(hay)) found.terms = url;
    if (!found.privacy && /privacy|data[ -]?policy/.test(hay)) found.privacy = url;
    if (found.terms && found.privacy) break;
  }
  return found;
}

function buildTermsFindings(policies) {
  if (!policies.length) return [{ level: "warning", category: "content",
    title: "No Terms or Privacy Link Found",
    simple: "We couldn't find links to Terms of Service or a Privacy Policy.",
    nerd: "No terms or privacy links matched the page scan." }];
  return policies.map(policy => policy.ok
    ? { level: "good", category: "content", title: policy.kind + " Available",
        simple: "The page links to a " + policy.kind + " you can read.",
        nerd: "Fetched " + policy.url + " (HTTP " + policy.status + ")." }
    : { level: "warning", category: "content", title: policy.kind + " Link Not Loading",
        simple: "The page links to a " + policy.kind + " but it could not be loaded.",
        nerd: "The policy page did not load successfully." });
}

module.exports = { cleanTarget, fetchPage, analyze, extractPolicyLinks, buildTermsFindings };
