#!/usr/bin/env node
"use strict";

const { validateKnowledgeBase } = require("../sus-or-bus/lib/knowledge/validator");

console.log("=== SusOrBus Knowledge Base Validation Utility ===");
const report = validateKnowledgeBase();

console.log(`Knowledge Base Version: ${report.version}`);
console.log(`Schema Version:         ${report.schemaVersion}`);
console.log(`Findings:               ${report.counts.totalFindings}`);
console.log(`Declarative Rules:      ${report.counts.activeRules}`);
console.log(`Domain Classifications: ${report.counts.domainServices}`);
console.log(`Phishing Brands:        ${report.counts.phishingBrands}`);
console.log(`Scam Patterns:          ${report.counts.scamPhrases}`);
console.log(`Policy Categories:      ${report.counts.policyCategories}`);
console.log("--------------------------------------------------");

if (report.warnings.length > 0) {
  console.log(`\n[!] Warnings (${report.warnings.length}):`);
  for (const w of report.warnings) {
    console.log(`  - ${w}`);
  }
}

if (!report.valid) {
  console.error(`\n[X] Validation FAILED with ${report.errors.length} error(s):`);
  for (const err of report.errors) {
    console.error(`  - ${err}`);
  }
  process.exit(1);
}

console.log("\n[OK] Knowledge Base integrity verified: 0 errors detected.");
process.exit(0);

