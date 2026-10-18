"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeUrl, cleanTarget, UrlValidationError } = require("../sus-or-bus/lib/url");

describe("Layer A: URL Normalization and Validation", () => {
  test("normalizes clean domain inputs with default https protocol", () => {
    const res = normalizeUrl("example.com");
    assert.equal(res.protocol, "https:");
    assert.equal(res.hostname, "example.com");
    assert.equal(res.href, "https://example.com/");
  });

  test("preserves existing https protocol", () => {
    const res = normalizeUrl("https://example.com/test");
    assert.equal(res.protocol, "https:");
    assert.equal(res.hostname, "example.com");
  });

  test("accepts plain http protocol", () => {
    const res = normalizeUrl("http://example.com");
    assert.equal(res.protocol, "http:");
    assert.equal(res.hostname, "example.com");
  });

  test("rejects unsupported protocols (ftp, file, javascript, data)", () => {
    assert.throws(() => normalizeUrl("ftp://example.com"), UrlValidationError);
    assert.throws(() => normalizeUrl("file:///etc/passwd"), UrlValidationError);
    assert.throws(() => normalizeUrl("javascript:alert(1)"), UrlValidationError);
    assert.throws(() => normalizeUrl("data:text/html,<b>hi</b>"), UrlValidationError);
  });

  test("rejects URLs with embedded credentials", () => {
    assert.throws(() => normalizeUrl("https://admin:secret@example.com"), {
      name: "UrlValidationError",
      code: "CREDENTIALS_DISALLOWED"
    });
    assert.throws(() => normalizeUrl("admin:secret@example.com"), {
      name: "UrlValidationError",
      code: "CREDENTIALS_DISALLOWED"
    });
  });

  test("permits standard web ports 80 and 443", () => {
    const httpsRes = normalizeUrl("https://example.com:443");
    assert.equal(httpsRes.hostname, "example.com");

    const httpRes = normalizeUrl("http://example.com:80");
    assert.equal(httpRes.hostname, "example.com");
  });

  test("rejects non-standard ports to prevent SSRF port scanning", () => {
    assert.throws(() => normalizeUrl("https://example.com:8080"), {
      name: "UrlValidationError",
      code: "UNSUPPORTED_PORT"
    });
    assert.throws(() => normalizeUrl("http://example.com:22"), {
      name: "UrlValidationError",
      code: "UNSUPPORTED_PORT"
    });
  });

  test("handles internationalized domain names (IDN / punycode)", () => {
    // München domain: münchen.de -> xn--mnchen-3ya.de
    const res = normalizeUrl("https://münchen.de");
    assert.equal(res.hostname, "xn--mnchen-3ya.de");
    assert.equal(res.displayHostname, "münchen.de");
    assert.equal(res.isPunycode, true);
  });

  test("rejects overlong hostnames (>253 characters)", () => {
    // 5 segments of 55 characters = 275 chars > 253
    const longDomain = "a".repeat(55) + "." + "b".repeat(55) + "." + "c".repeat(55) + "." + "d".repeat(55) + "." + "e".repeat(55) + ".com";
    assert.throws(() => normalizeUrl(longDomain), {
      name: "UrlValidationError",
      code: "HOSTNAME_TOO_LONG"
    });
  });

  test("rejects label segments exceeding 63 characters", () => {
    const longLabel = "a".repeat(64) + ".com";
    assert.throws(() => normalizeUrl(longLabel), {
      name: "UrlValidationError",
      code: "HOSTNAME_LABEL_TOO_LONG"
    });
  });

  test("cleanTarget returns normalized hostname and empty string on invalid inputs", () => {
    assert.equal(cleanTarget("https://Example.COM/page"), "example.com");
    assert.equal(cleanTarget("https://admin:password@bad.com"), "");
    assert.equal(cleanTarget(""), "");
    assert.equal(cleanTarget(null), "");
  });
});

