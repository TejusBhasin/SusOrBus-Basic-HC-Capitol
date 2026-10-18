"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeAndDeduplicateFindings,
  calculateRiskScore
} = require("../sus-or-bus/lib/scorer");

describe("Layer F: Evidence-Based Findings and Risk Scoring", () => {
  test("normalizes legacy findings into standardized evidence schema", () => {
    const raw = [{
      category: "security",
      title: "Password Detected",
      level: "bad",
      simple: "Simple text",
      nerd: "Technical detail"
    }];
    const normalized = normalizeAndDeduplicateFindings(raw);
    assert.equal(normalized.length, 1);
    assert.equal(normalized[0].severity, "high");
    assert.equal(normalized[0].summary, "Simple text");
    assert.equal(normalized[0].evidence, "Technical detail");
    assert.equal(normalized[0].level, "bad");
  });

  test("deduplicates findings with the same ID", () => {
    const raw = [
      { id: "transport-https", level: "good", title: "HTTPS Transport", category: "security" },
      { id: "transport-https", level: "good", title: "HTTPS Transport Duplicate", category: "security" }
    ];
    const normalized = normalizeAndDeduplicateFindings(raw);
    assert.equal(normalized.length, 1);
  });

  test("calculates deterministic score: 100 for zero risk findings", () => {
    const findings = [
      { id: "f1", level: "good", severity: "informational", confidence: "high" },
      { id: "f2", level: "good", severity: "informational", confidence: "high" }
    ];
    const { score, verdict, counts } = calculateRiskScore(findings);
    assert.equal(score, 100);
    assert.equal(verdict, "BUS");
    assert.equal(counts.good, 2);
    assert.equal(counts.warning, 0);
    assert.equal(counts.bad, 0);
  });

  test("calculates deterministic deductions based on severity and confidence", () => {
    // 1 high severity (weight 25 * 1.0 = 25 deduction) -> score 75
    const findings = [
      { id: "f1", level: "bad", severity: "high", confidence: "high" }
    ];
    const result = calculateRiskScore(findings);
    assert.equal(result.score, 75);
    assert.equal(result.verdict, "BUS"); // >= 70 is BUS

    // Add medium severity (weight 12 * 1.0 = 12 deduction) -> 100 - 37 = 63
    findings.push({ id: "f2", level: "warning", severity: "medium", confidence: "high" });
    const result2 = calculateRiskScore(findings);
    assert.equal(result2.score, 63);
    assert.equal(result2.verdict, "MILDLY SUS"); // 40-69 is MILDLY SUS

    // Add critical severity (weight 40 * 1.0 = 40 deduction) -> 100 - 77 = 23
    findings.push({ id: "f3", level: "bad", severity: "critical", confidence: "high" });
    const result3 = calculateRiskScore(findings);
    assert.equal(result3.score, 23);
    assert.equal(result3.verdict, "SUS"); // < 40 is SUS
  });

  test("ensures score never drops below 0", () => {
    const severeFindings = [
      { id: "f1", level: "bad", severity: "critical", confidence: "high" },
      { id: "f2", level: "bad", severity: "critical", confidence: "high" },
      { id: "f3", level: "bad", severity: "critical", confidence: "high" }
    ];
    const result = calculateRiskScore(severeFindings);
    assert.equal(result.score, 0);
    assert.equal(result.verdict, "SUS");
  });
});

