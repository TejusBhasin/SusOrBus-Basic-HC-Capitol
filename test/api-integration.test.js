"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const server = require("../sus-or-bus/server");
const checkHandler = require("../sus-or-bus/api/check");
const previewHandler = require("../sus-or-bus/api/preview");

/**
 * Invokes server request listener directly without opening raw TCP sockets,
 * perfectly compatible with sandboxed CI environments.
 */
function invokeServer(method, path, body = null, headers = {}) {
  return new Promise(resolve => {
    const req = new EventEmitter();
    req.method = method;
    req.url = path;
    req.headers = { host: "127.0.0.1:3000", ...headers };

    const res = new EventEmitter();
    const resHeaders = {};
    const chunks = [];
    res.statusCode = 200;
    res.setHeader = (k, v) => { resHeaders[k.toLowerCase()] = v; };
    res.getHeader = k => resHeaders[k.toLowerCase()];
    res.end = chunk => {
      if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      const text = Buffer.concat(chunks).toString("utf8");
      resolve({
        statusCode: res.statusCode,
        headers: resHeaders,
        text
      });
    };

    server.emit("request", req, res);
    if (body) {
      req.emit("data", typeof body === "string" ? body : JSON.stringify(body));
    }
    req.emit("end");
  });
}

describe("Layer G: API and Server Integration", () => {
  test("serves index.html on root GET /", async () => {
    const res = await invokeServer("GET", "/");
    assert.equal(res.statusCode, 200);
    assert.ok(res.headers["content-type"].includes("text/html"));
    assert.ok(res.text.includes("Sus or Bus"), "Should serve main HTML page");
  });

  test("rejects invalid site parameter with 400 status on /check", async () => {
    const res = await invokeServer("GET", "/check?site=");
    assert.equal(res.statusCode, 400);
    const data = JSON.parse(res.text);
    assert.ok(data.error.includes("valid website address"));
  });

  test("blocks SSRF target localhost with 400 status on /check", async () => {
    const res = await invokeServer("GET", "/check?site=localhost");
    assert.equal(res.statusCode, 400);
    const data = JSON.parse(res.text);
    assert.ok(data.error);
    assert.ok(data.errorCode);
  });

  test("maintains backward-compatible JSON shape in api/check", async () => {
    const req = {
      method: "GET",
      query: { site: "invalid..host" },
      headers: { origin: "http://localhost:3000" }
    };
    let responseStatus = 0;
    let responseBody = null;
    const res = {
      setHeader: () => {},
      status: code => {
        responseStatus = code;
        return {
          json: data => { responseBody = data; return data; },
          end: () => {}
        };
      }
    };

    await checkHandler(req, res);
    assert.equal(responseStatus, 400);
    assert.ok(responseBody.error);
  });

  test("preview endpoint blocks prohibited hostnames with 400", async () => {
    const req = {
      method: "GET",
      query: { site: "127.0.0.1" },
      headers: {}
    };
    let responseStatus = 0;
    let responseText = "";
    const res = {
      setHeader: () => {},
      status: code => {
        responseStatus = code;
        return {
          send: text => { responseText = text; return text; },
          end: () => {}
        };
      }
    };

    await previewHandler(req, res);
    assert.equal(responseStatus, 400);
    assert.ok(responseText.includes("prohibited") || responseText.includes("Invalid"));
  });

  test("public searches feed stores and returns search items", async () => {
    const postRes = await invokeServer("POST", "/publish", {
      site: "example.com",
      score: 85,
      verdict: "BUS"
    });
    assert.equal(postRes.statusCode, 200);

    const getRes = await invokeServer("GET", "/public");
    assert.equal(getRes.statusCode, 200);
    const list = JSON.parse(getRes.text);
    assert.ok(Array.isArray(list));
    assert.ok(list.some(s => s.site === "example.com"));
  });
});

