"use strict";

const { cleanTarget, fetchPage } = require("../lib/site");

const rateLimits = new Map();
const ALLOWED_ORIGINS = new Set([
  "https://tejusbhasin.github.io",
  "http://localhost:3000",
  "http://127.0.0.1:3000"
]);

module.exports = async function handler(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }
  if (req.method !== "GET") {
    return res.status(405).send("Method not allowed.");
  }

  const ip = String(req.headers["x-forwarded-for"] || (req.socket && req.socket.remoteAddress) || "unknown")
    .split(",")
    .pop()
    .trim();
  const now = Date.now();
  const entry = rateLimits.get(ip);
  if (!entry || now - entry.start > 60_000) {
    rateLimits.set(ip, { start: now, count: 1 });
  } else if (++entry.count > 30) {
    return res.status(429).send("Too many previews. Please wait a minute.");
  }

  const rawSite = Array.isArray(req.query.site) ? req.query.site[0] : req.query.site;
  const target = cleanTarget(rawSite);
  if (!target) {
    return res.status(400).send("Invalid website address.");
  }

  try {
    const page = await fetchPage("https://" + target);
    const xfo = (page.headers && page.headers["x-frame-options"]) || "";
    const csp = (page.headers && page.headers["content-security-policy"]) || "";

    if (/deny|sameorigin/i.test(xfo) || /frame-ancestors/i.test(csp)) {
      let reason = "this site blocks embedding";
      if (/deny/i.test(xfo)) reason = "it sends X-Frame-Options: DENY";
      else if (/sameorigin/i.test(xfo)) reason = "it sends X-Frame-Options: SAMEORIGIN";
      else if (/frame-ancestors/i.test(csp)) reason = "its Content-Security-Policy blocks framing";

      res.setHeader("Content-Type", "application/json");
      return res.status(409).send(JSON.stringify({ embeddable: false, reason }));
    }

    // Security isolation boundary: sandbox remote HTML to prevent script execution in app origin
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data: https:; script-src 'none'; object-src 'none'; base-uri 'none';");
    res.setHeader("X-Content-Type-Options", "nosniff");
    return res.status(page.status >= 400 ? 502 : 200).send(page.html);
  } catch (error) {
    return res.status(400).send("Preview failed: " + error.message);
  }
};
