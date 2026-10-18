"use strict";

const http = require("node:http");
const { normalizeUrl } = require("./url");
const { resolveAndValidate } = require("./dns");
const { classifyThirdParty, sanitizeUrlForLogging } = require("./trackers");

const PORT = Number.parseInt(process.env.BROWSER_WORKER_PORT || "4000", 10);
const SECRET = process.env.BROWSER_WORKER_SECRET || "";

/**
 * Attempts to analyze a page using Playwright if available in the execution environment.
 */
async function analyzeWithBrowser(targetUrl, options = {}) {
  let playwright;
  try {
    playwright = require("playwright");
  } catch {
    throw new Error("Playwright is not installed in this runtime container.");
  }

  const normalized = normalizeUrl(targetUrl);
  // SSRF check on primary destination before navigation
  await resolveAndValidate(normalized.hostname);

  const browser = await playwright.chromium.launch({
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--disable-software-rasterizer"
    ]
  });

  const context = await browser.newContext({
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 SusOrBus/2.0",
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: true
  });

  const page = await context.newPage();

  const observedRequests = [];
  const thirdPartyRequests = [];
  const consoleErrors = [];
  const webSocketAttempts = [];

  page.on("request", req => {
    const reqUrl = req.url();
    const sanitized = sanitizeUrlForLogging(reqUrl);
    observedRequests.push({ url: sanitized, method: req.method(), resourceType: req.resourceType() });

    const classification = classifyThirdParty(reqUrl, normalized.hostname);
    if (classification.isThirdParty) {
      thirdPartyRequests.push({
        url: sanitized,
        domain: classification.domain,
        provider: classification.provider,
        category: classification.category,
        isTracker: classification.isTracker
      });
    }
  });

  page.on("websocket", ws => {
    webSocketAttempts.push({ url: sanitizeUrlForLogging(ws.url()) });
  });

  page.on("pageerror", err => {
    consoleErrors.push(err.message ? err.message.slice(0, 150) : "Unknown page error");
  });

  try {
    const response = await page.goto(normalized.href, {
      waitUntil: "domcontentloaded",
      timeout: options.timeoutMs || 6_000
    });

    const finalUrl = page.url();
    const title = await page.title();
    const status = response ? response.status() : 0;

    // Cookie metadata extraction - NEVER collect raw values for privacy
    const rawCookies = await context.cookies();
    const cookieMetadata = rawCookies.map(c => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      session: c.session
    }));

    // Storage key names extraction - NEVER collect values
    const storageKeys = await page.evaluate(() => {
      try {
        return {
          localStorage: Object.keys(window.localStorage || {}),
          sessionStorage: Object.keys(window.sessionStorage || {})
        };
      } catch {
        return { localStorage: [], sessionStorage: [] };
      }
    }).catch(() => ({ localStorage: [], sessionStorage: [] }));

    return {
      status,
      finalUrl,
      title,
      totalRequests: observedRequests.length,
      thirdPartyRequestsCount: thirdPartyRequests.length,
      thirdPartyRequests: thirdPartyRequests.slice(0, 25),
      cookieMetadata,
      storageKeys,
      consoleErrors: consoleErrors.slice(0, 10),
      webSocketAttempts
    };
  } finally {
    await page.close().catch(() => {});
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
}

/**
 * Worker HTTP server for isolated container deployment.
 */
function createWorkerServer() {
  const server = http.createServer(async (req, res) => {
    // Bearer token authentication
    if (SECRET) {
      const authHeader = req.headers["authorization"] || "";
      const token = authHeader.replace(/^Bearer\s+/i, "");
      if (token !== SECRET) {
        res.statusCode = 401;
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify({ error: "Unauthorized" }));
      }
    }

    if (req.method === "POST" && req.url === "/analyze") {
      let body = "";
      req.on("data", c => (body += c));
      req.on("end", async () => {
        try {
          const payload = JSON.parse(body || "{}");
          if (!payload.url) {
            res.statusCode = 400;
            return res.end(JSON.stringify({ error: "Missing required 'url' parameter" }));
          }

          const result = await analyzeWithBrowser(payload.url, { timeoutMs: payload.timeoutMs || 6_000 });
          res.statusCode = 200;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify(result));
        } catch (err) {
          res.statusCode = 500;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }

    if (req.method === "GET" && req.url === "/health") {
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ status: "healthy", timestamp: Date.now() }));
    }

    res.statusCode = 404;
    res.end("Not Found");
  });

  return server;
}

if (require.main === module) {
  const server = createWorkerServer();
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Isolated browser worker running on port ${PORT}`);
  });
}

module.exports = {
  createWorkerServer,
  analyzeWithBrowser
};

