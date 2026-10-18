"use strict";

const { runFullScan, cleanTarget } = require("../lib/site");
const { messages } = require("../lib/knowledge");

const rateLimits = new Map();
const ALLOWED_ORIGINS = new Set([
  "https://tejusbhasin.github.io",
  "http://localhost:3000",
  "http://127.0.0.1:3000"
]);

function setHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Cache-Control", "no-store");
}

function limited(req) {
  const ip = String(req.headers["x-forwarded-for"] || (req.socket && req.socket.remoteAddress) || "unknown")
    .split(",")
    .pop()
    .trim();
  const now = Date.now();
  const entry = rateLimits.get(ip);
  if (!entry || now - entry.start > 60_000) {
    rateLimits.set(ip, { start: now, count: 1 });
    return false;
  }
  entry.count++;
  return entry.count > 30;
}

module.exports = async function handler(req, res) {
  setHeaders(req, res);
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed." });
  }
  if (limited(req)) {
    return res.status(429).json({
      error: messages.errors.RATE_LIMIT_EXCEEDED.text,
      errorCode: messages.errors.RATE_LIMIT_EXCEEDED.code
    });
  }

  const rawSite = Array.isArray(req.query.site) ? req.query.site[0] : req.query.site;
  const target = cleanTarget(rawSite);
  if (!target) {
    return res.status(400).json({
      error: messages.errors.INVALID_URL.text,
      errorCode: messages.errors.INVALID_URL.code
    });
  }

  try {
    const scanResult = await runFullScan(target);
    return res.status(200).json(scanResult);
  } catch (error) {
    const isSecurityError = error.name === "DnsSecurityError" || error.code === "SSRF_BLOCKED" || error.name === "UrlValidationError";
    const statusCode = isSecurityError ? 400 : 502;
    return res.status(statusCode).json({
      error: `Could not check ${target} (${error.message})`,
      errorCode: error.code || "SCAN_FAILED"
    });
  }
};
