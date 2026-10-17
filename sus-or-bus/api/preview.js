const { cleanTarget, fetchPage } = require("../lib/site");

const rateLimits = new Map();
const ALLOWED_ORIGIN = "https://tejusbhasin.github.io";

module.exports = async function handler(req, res) {
  const origin = req.headers.origin;
  if (origin === ALLOWED_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }
  if (req.method !== "GET") return res.status(405).send("Method not allowed.");
  const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",").pop().trim();
  const now = Date.now();
  const entry = rateLimits.get(ip);
  if (!entry || now - entry.start > 60_000) rateLimits.set(ip, { start: now, count: 1 });
  else if (++entry.count > 20) return res.status(429).send("Too many previews. Please wait a minute.");
  const target = cleanTarget(Array.isArray(req.query.site) ? req.query.site[0] : req.query.site);
  if (!target) return res.status(400).send("Invalid website address.");
  try {
    const page = await fetchPage("https://" + target);
    const xfo = (page.headers && page.headers["x-frame-options"]) || "";
    const csp = (page.headers && page.headers["content-security-policy"]) || "";
    if (/deny|sameorigin/i.test(xfo) || /frame-ancestors/i.test(csp)) {
      res.setHeader("Content-Type", "application/json");
      return res.status(409).send(JSON.stringify({ embeddable: false }));
    }
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(page.status >= 400 ? 502 : 200).send(page.html);
  } catch (error) {
    return res.status(400).send("Preview failed: " + error.message);
  }
};
