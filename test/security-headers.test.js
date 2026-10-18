"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { analyzeSecurityHeaders } = require("../sus-or-bus/lib/security-headers");

describe("Layer I: Security Headers Analysis", () => {
  test("identifies HTTPS transport vs unencrypted HTTP", () => {
    const httpsFindings = analyzeSecurityHeaders({}, "https://secure.example.com");
    const transportGood = httpsFindings.find(f => f.id === "SEC_TRANSPORT_HTTPS" || f.legacyId === "transport-https");
    assert.ok(transportGood);
    assert.equal(transportGood.level, "good");

    const httpFindings = analyzeSecurityHeaders({}, "http://insecure.example.com");
    const transportBad = httpFindings.find(f => f.id === "SEC_TRANSPORT_HTTP_INSECURE" || f.legacyId === "transport-http-insecure");
    assert.ok(transportBad);
    assert.equal(transportBad.level, "bad");
  });

  test("evaluates strong HSTS header", () => {
    const headers = {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
    };
    const findings = analyzeSecurityHeaders(headers, "https://example.com");
    const hstsFinding = findings.find(f => f.id === "SEC_HEADER_HSTS_STRONG" || f.legacyId === "header-hsts-strong");
    assert.ok(hstsFinding);
    assert.equal(hstsFinding.level, "good");
  });

  test("flags short or missing HSTS header", () => {
    const shortHeaders = {
      "strict-transport-security": "max-age=300"
    };
    const shortFindings = analyzeSecurityHeaders(shortHeaders, "https://example.com");
    assert.ok(shortFindings.some(f => f.id === "SEC_HEADER_HSTS_SHORT" || f.legacyId === "header-hsts-short"));

    const missingFindings = analyzeSecurityHeaders({}, "https://example.com");
    assert.ok(missingFindings.some(f => f.id === "SEC_HEADER_HSTS_MISSING" || f.legacyId === "header-hsts-missing"));
  });

  test("evaluates Content-Security-Policy presence", () => {
    const headers = {
      "content-security-policy": "default-src 'self'; script-src 'self' https://trusted.cdn.com;"
    };
    const findings = analyzeSecurityHeaders(headers, "https://example.com");
    const cspFinding = findings.find(f => f.id === "SEC_HEADER_CSP_PRESENT" || f.legacyId === "header-csp-present");
    assert.ok(cspFinding);
    assert.equal(cspFinding.level, "good");
  });

  test("flags missing Content-Security-Policy", () => {
    const findings = analyzeSecurityHeaders({}, "https://example.com");
    assert.ok(findings.some(f => f.id === "SEC_HEADER_CSP_MISSING" || f.legacyId === "header-csp-missing"));
  });

  test("detects nosniff X-Content-Type-Options", () => {
    const headers = { "x-content-type-options": "nosniff" };
    const findings = analyzeSecurityHeaders(headers, "https://example.com");
    assert.ok(findings.some(f => f.id === "SEC_HEADER_XCTO_PRESENT" || f.legacyId === "header-xcto-present"));
  });

  test("flags detailed server version disclosure", () => {
    const headers = { "server": "Apache/2.4.41 (Ubuntu)" };
    const findings = analyzeSecurityHeaders(headers, "https://example.com");
    const bannerFinding = findings.find(f => f.id === "SEC_HEADER_VERSION_DISCLOSURE" || f.legacyId === "header-version-disclosure");
    assert.ok(bannerFinding);
    assert.equal(bannerFinding.level, "warning");
  });
});

