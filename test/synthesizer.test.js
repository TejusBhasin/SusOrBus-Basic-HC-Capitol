"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { calculateRiskScore } = require("../sus-or-bus/lib/scorer");
const { generateAiSynthesis } = require("../sus-or-bus/lib/synthesizer");

describe("Calibrated Precision Scoring & AI Heuristic Synthesizer", () => {
  test("generates precise, non-multiple-of-5 scores for catalog findings", () => {
    // Missing CSP (-7 pts) and missing HSTS (-9 pts) -> 100 - 16 = 84 (not multiple of 5)
    const findings = [
      { id: "SEC_HEADER_CSP_MISSING", level: "warning", severity: "medium", confidence: "high" },
      { id: "SEC_HEADER_HSTS_MISSING", level: "warning", severity: "medium", confidence: "high" }
    ];
    const result = calculateRiskScore(findings);
    assert.equal(result.score, 84);
    assert.notEqual(result.score % 5, 0);
    assert.equal(result.verdict, "BUS");
  });

  test("calculates fine-grained scores across multiple risk tiers", () => {
    // Insecure HTTP (-33 pts) -> 100 - 33 = 67 (MILDLY SUS, not multiple of 5)
    const findings = [
      { id: "SEC_TRANSPORT_HTTP_INSECURE", level: "bad", severity: "high", confidence: "high" }
    ];
    const result = calculateRiskScore(findings);
    assert.equal(result.score, 67);
    assert.notEqual(result.score % 5, 0);
    assert.equal(result.verdict, "MILDLY SUS");
  });

  test("computes 4 discrete multi-dimensional risk vectors", () => {
    const findings = [
      { id: "SEC_HEADER_CSP_MISSING", subcategory: "headers", category: "security", level: "warning", severity: "medium", confidence: "high" },
      { id: "SEC_IFRAME_THIRD_PARTY", subcategory: "elements", category: "content", level: "warning", severity: "low", confidence: "high" },
      { id: "POL_TRACKER_DISCLOSURE_GAP", subcategory: "tracking_transparency", category: "policy", level: "warning", severity: "low", confidence: "high" }
    ];
    const result = calculateRiskScore(findings, {
      trackers: [{ provider: "Meta Pixel", domain: "facebook.net" }]
    });

    assert.ok(result.vectors.transport);
    assert.ok(result.vectors.content);
    assert.ok(result.vectors.telemetry);
    assert.ok(result.vectors.governance);

    assert.equal(typeof result.vectors.transport.score, "number");
    assert.equal(typeof result.vectors.content.score, "number");
    assert.equal(typeof result.vectors.telemetry.score, "number");
    assert.equal(typeof result.vectors.governance.score, "number");
  });

  test("generates rich, deterministic AI synthesis narrative without external LLMs", () => {
    const scanContext = {
      site: "portal.example-corp.com",
      url: "https://portal.example-corp.com/login",
      score: 73,
      verdict: "BUS",
      counts: { good: 3, warning: 2, bad: 0 },
      findings: [
        { id: "SEC_TRANSPORT_HTTPS", subcategory: "transport", level: "good", severity: "informational", confidence: "high" },
        { id: "SEC_HEADER_HSTS_SHORT", subcategory: "headers", level: "warning", severity: "low", confidence: "high" },
        { id: "SEC_HEADER_CSP_MISSING", subcategory: "headers", level: "warning", severity: "medium", confidence: "high" }
      ],
      trackers: [
        { provider: "Google Analytics", domain: "google-analytics.com" },
        { provider: "Hotjar", domain: "hotjar.com" }
      ],
      policies: [
        { kind: "Privacy Policy", ok: true }
      ],
      coverage: {
        staticHtml: "completed",
        securityHeaders: "completed",
        trackers: "completed",
        privacyPolicy: "completed",
        termsOfService: "not_found"
      }
    };

    const ai = generateAiSynthesis(scanContext);

    assert.ok(ai.badge.includes("SECURITY ASSESSMENT"));
    assert.ok(ai.summaryBullets.length >= 4);
    assert.ok(ai.executiveSummary.includes("portal.example-corp.com"));
    assert.ok(ai.executiveSummary.includes("Google Analytics"));
    assert.ok(ai.paragraphs.length >= 3);
    assert.ok(ai.actionableRecommendations.length > 0);
    assert.equal(typeof ai.confidenceScore, "number");
    assert.ok(ai.confidenceScore >= 80);
  });
});

