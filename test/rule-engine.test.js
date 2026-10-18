"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { evaluateObservationRules, evaluateConditions } = require("../sus-or-bus/lib/engine");

describe("General-Purpose Deterministic Rule Engine", () => {
  test("evaluates simple condition equality", () => {
    assert.equal(evaluateConditions({ protocolEquals: "https:" }, { protocol: "https:" }), true);
    assert.equal(evaluateConditions({ protocolEquals: "https:" }, { protocol: "http:" }), false);
  });

  test("evaluates numeric comparisons (HSTS duration, script count)", () => {
    assert.equal(evaluateConditions({ hstsMaxAgeGte: 10368000 }, { hstsMaxAge: 31536000 }), true);
    assert.equal(evaluateConditions({ hstsMaxAgeGte: 10368000 }, { hstsMaxAge: 300 }), false);
    assert.equal(evaluateConditions({ externalScriptsGt: 20 }, { scripts: { external: 25 } }), true);
    assert.equal(evaluateConditions({ externalScriptsGt: 20 }, { scripts: { external: 5 } }), false);
  });

  test("evaluates complex multi-condition rules", () => {
    const conditions = {
      isIpLiteral: false,
      hasUnusualDomainStructure: false,
      hasBrandImpersonation: false
    };
    assert.equal(evaluateConditions(conditions, {
      isIpLiteral: false,
      hasUnusualDomainStructure: false,
      hasBrandImpersonation: false
    }), true);

    assert.equal(evaluateConditions(conditions, {
      isIpLiteral: true,
      hasUnusualDomainStructure: false,
      hasBrandImpersonation: false
    }), false);
  });

  test("generates catalog-backed findings with diagnostic mode", () => {
    const obs = {
      targetHost: "legit-site.com",
      finalUrl: "https://legit-site.com/",
      protocol: "https:",
      isHttps: true,
      hasPasswordInput: false,
      hasInsecureOrCrossOriginPasswordForm: false,
      hasMetaRefresh: false,
      scripts: { total: 0, external: 0, inline: 0, distinctOrigins: [] },
      hasScriptObfuscation: false,
      thirdPartyIframesCount: 0,
      isIpLiteral: false,
      hasUnusualDomainStructure: false,
      hasBrandImpersonation: false,
      hasScamKeywords: false,
      hasHsts: true,
      hstsMaxAge: 31536000,
      hstsValue: "max-age=31536000",
      hasCsp: true,
      cspSnippet: "default-src 'self'",
      hasXctoNosniff: true,
      hasFramingProtection: true,
      framingMechanism: "CSP frame-ancestors",
      hasServerVersionDisclosure: false
    };

    const { findings, diagnostics } = evaluateObservationRules(obs, { diagnostic: true });
    assert.ok(findings.length > 0);
    assert.ok(diagnostics.length > 0);

    const httpsFinding = findings.find(f => f.id === "SEC_TRANSPORT_HTTPS");
    assert.ok(httpsFinding, "Should emit SEC_TRANSPORT_HTTPS");
    assert.equal(httpsFinding.source, "HTTP Response");
    assert.equal(httpsFinding.severity, "informational");
    assert.equal(httpsFinding.level, "good");

    const matchedDiag = diagnostics.find(d => d.outputFindingId === "SEC_TRANSPORT_HTTPS");
    assert.ok(matchedDiag);
    assert.equal(matchedDiag.matched, true);
  });
});

