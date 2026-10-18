"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { validateKnowledgeBase } = require("../sus-or-bus/lib/knowledge");

describe("Knowledge Base Integrity & Validation", () => {
  test("validates all knowledge base records with 0 schema errors", () => {
    const report = validateKnowledgeBase();
    assert.equal(report.valid, true, `Validation failed with errors: ${JSON.stringify(report.errors)}`);
    assert.equal(report.errors.length, 0);
    assert.ok(report.counts.totalFindings > 20, "Should contain substantial finding catalog");
    assert.ok(report.counts.activeRules > 15, "Should contain substantial active rules catalog");
    assert.ok(report.counts.domainServices > 30, "Should contain substantial domain services catalog");
  });

  test("contains valid versioning and provenance metadata", () => {
    const report = validateKnowledgeBase();
    assert.ok(report.version);
    assert.ok(report.schemaVersion);
  });
});

