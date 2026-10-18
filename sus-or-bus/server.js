"use strict";

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { runFullScan, cleanTarget, fetchPage } = require("./lib/site");
const { messages, verdicts, metadata } = require("./lib/knowledge");

const PORT = Number.parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "127.0.0.1";
const publicSearches = [];

function setCorsHeaders(res, origin) {
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  } else {
    res.setHeader("Access-Control-Allow-Origin", "*");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || "127.0.0.1:3000"}`);
  const origin = req.headers.origin;

  if (req.method === "OPTIONS") {
    setCorsHeaders(res, origin);
    res.statusCode = 204;
    return res.end();
  }

  // Root frontend page
  if (reqUrl.pathname === "/") {
    const htmlPath = path.join(__dirname, "index.html");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.statusCode = 200;
    return res.end(fs.readFileSync(htmlPath));
  }

  // Central Knowledge Base Catalog Endpoint
  if (reqUrl.pathname === "/catalog" || reqUrl.pathname === "/api/catalog") {
    setCorsHeaders(res, origin);
    res.setHeader("Content-Type", "application/json");
    res.statusCode = 200;
    return res.end(JSON.stringify({
      version: metadata.version,
      messages,
      verdicts: verdicts.verdicts
    }));
  }

  // Unified check endpoint
  if (reqUrl.pathname === "/check" || reqUrl.pathname === "/api/check") {
    setCorsHeaders(res, origin);
    res.setHeader("Content-Type", "application/json");

    const rawSite = reqUrl.searchParams.get("site");
    const target = cleanTarget(rawSite);
    if (!target) {
      res.statusCode = 400;
      return res.end(JSON.stringify({
        error: messages.errors.INVALID_URL.text,
        errorCode: messages.errors.INVALID_URL.code
      }));
    }

    try {
      const result = await runFullScan(target);
      res.statusCode = 200;
      return res.end(JSON.stringify(result));
    } catch (err) {
      const isSecurityError = err.name === "DnsSecurityError" || err.code === "SSRF_BLOCKED" || err.name === "UrlValidationError";
      res.statusCode = isSecurityError ? 400 : 502;
      return res.end(JSON.stringify({
        error: `Could not check ${target} (${err.message})`,
        errorCode: err.code || "SCAN_FAILED"
      }));
    }
  }

  // Unified preview endpoint
  if (reqUrl.pathname === "/preview" || reqUrl.pathname === "/api/preview") {
    setCorsHeaders(res, origin);
    const rawSite = reqUrl.searchParams.get("site");
    const target = cleanTarget(rawSite);
    if (!target) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      return res.end(messages.errors.INVALID_URL.text);
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

        res.statusCode = 409;
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify({ embeddable: false, reason }));
      }

      // Safe isolated preview headers
      res.statusCode = page.status >= 400 ? 502 : 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data: https:; script-src 'none'; object-src 'none'; base-uri 'none';");
      res.setHeader("X-Content-Type-Options", "nosniff");
      return res.end(page.html);
    } catch (err) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      return res.end("Preview failed: " + err.message);
    }
  }

  // Publish to public searches
  if (reqUrl.pathname === "/publish" && req.method === "POST") {
    setCorsHeaders(res, origin);
    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", () => {
      try {
        const item = JSON.parse(body || "{}");
        if (item.site && !publicSearches.some(s => s.site === item.site)) {
          publicSearches.unshift({
            site: item.site,
            score: item.score,
            verdict: item.verdict,
            at: Date.now()
          });
        }
      } catch {}
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end("{}");
    });
    return;
  }

  // Retrieve public searches
  if (reqUrl.pathname === "/public") {
    setCorsHeaders(res, origin);
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify(publicSearches.slice(0, 20)));
  }

  res.statusCode = 404;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end("Not found");
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`Server successfully running at http://${HOST}:${PORT}`);
  });
}

module.exports = server;
