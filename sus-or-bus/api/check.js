const { cleanTarget, fetchPage, analyze, extractPolicyLinks, buildTermsFindings } = require("../lib/site");

const rateLimits = new Map();
const ALLOWED_ORIGIN = "https://tejusbhasin.github.io";

function setHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin === ALLOWED_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Cache-Control", "no-store");
}

function limited(req) {
  const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",").pop().trim();
  const now = Date.now();
  const entry = rateLimits.get(ip);
  if (!entry || now - entry.start > 60_000) {
    rateLimits.set(ip, { start: now, count: 1 });
    return false;
  }
  entry.count++;
  return entry.count > 20;
}

module.exports = async function handler(req, res) {
  setHeaders(req, res);
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed." });
  if (limited(req)) return res.status(429).json({ error: "Too many checks. Please wait a minute and try again." });

  const target = cleanTarget(Array.isArray(req.query.site) ? req.query.site[0] : req.query.site);
  if (!target) return res.status(400).json({ error: "Enter a valid website address." });

  try {
    const { status, html, url, headers, chain } = await fetchPage("https://" + target);
    const findings = analyze(html, target, url);
    const links = extractPolicyLinks(html, url);
    const policies = [];
    for (const [kind, policyUrl] of [["Terms of Service", links.terms], ["Privacy Policy", links.privacy]]) {
      if (!policyUrl) continue;
      try {
        const policy = await fetchPage(policyUrl);
        policies.push({ kind, url: policy.url, ok: policy.status >= 200 && policy.status < 400 && policy.html.length > 400, status: policy.status });
      } catch {
        policies.push({ kind, url: policyUrl, ok: false });
      }
    }
    const termsFindings = buildTermsFindings(policies);
    const secHeaders = {};
    for (const h of ["content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options", "server"]) {
      const v = headers && headers[h];
      if (v) secHeaders[h] = v;
    }
    const counts = { good: 0, warning: 0, bad: 0 };
    for (const finding of findings.concat(termsFindings)) counts[finding.level]++;
    const score = Math.max(0, 100 - counts.bad * 30 - counts.warning * 10);
    const verdict = score >= 70 ? "BUS" : score >= 40 ? "MILDLY SUS" : "SUS";
    return res.status(200).json({
      site: target, url, status, checkedAt: new Date().toISOString(),
      score, verdict, counts, findings, policies, termsFindings, chain: chain || [], headers: secHeaders, source: html.slice(0, 20_000)
    });
  } catch (error) {
    return res.status(400).json({ error: "Could not check " + target + " (" + error.message + ")" });
  }
};
