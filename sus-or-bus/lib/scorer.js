"use strict";

const { scoring, verdicts, findings: kbFindings } = require("./knowledge");

const SEVERITY_WEIGHTS = scoring.severityWeights;
const CONFIDENCE_MULTIPLIERS = scoring.confidenceMultipliers;

const findingDefMap = new Map();
for (const f of kbFindings.findings) {
  findingDefMap.set(f.id, f);
}

/**
 * Deduplicates findings by stable identifier and guarantees standard schema fields.
 */
function normalizeAndDeduplicateFindings(rawFindings = []) {
  const seenIds = new Set();
  const result = [];

  for (const f of rawFindings) {
    if (!f || typeof f !== "object") continue;

    const findingId = f.id || `${f.category || "gen"}-${f.title}`;
    if (seenIds.has(findingId)) continue;
    seenIds.add(findingId);

    // Look up canonical definition if available
    const canonical = findingDefMap.get(findingId);

    let severity = f.severity || canonical?.severity;
    if (!severity) {
      if (f.level === "bad") severity = "high";
      else if (f.level === "warning") severity = "medium";
      else severity = "informational";
    }

    let level = f.level;
    if (!level) {
      if (severity === "critical" || severity === "high") level = "bad";
      else if (severity === "medium" || severity === "low") level = "warning";
      else level = "good";
    }

    const normalizedFinding = {
      id: findingId,
      category: f.category || canonical?.category || "security",
      subcategory: f.subcategory || canonical?.subcategory || "general",
      title: f.title || canonical?.titleTemplate || "Finding",
      severity,
      confidence: f.confidence || canonical?.confidence || "high",
      summary: f.summary || f.simple || "",
      evidence: f.evidence || f.nerd || "",
      whyItMatters: f.whyItMatters || canonical?.whyItMattersTemplate || "Affects page trust or privacy profile.",
      recommendation: f.recommendation || canonical?.recommendationTemplate || "Review and verify.",
      source: f.source || canonical?.source || "Static Analysis",
      status: f.status || "detected",
      limitations: f.limitations || canonical?.limitations || "",

      // Backward-compatible properties for frontend
      level,
      simple: f.simple || f.summary || "",
      nerd: f.nerd || f.evidence || ""
    };

    result.push(normalizedFinding);
  }

  return result;
}

/**
 * Computes deterministic score (0 - 100) and assigns verdict from knowledge base.
 */
function calculateRiskScore(findings = []) {
  const counts = { good: 0, warning: 0, bad: 0 };
  let totalDeduction = 0;

  for (const finding of findings) {
    counts[finding.level]++;

    const baseWeight = SEVERITY_WEIGHTS[finding.severity] ?? (
      finding.level === "bad" ? 25 : finding.level === "warning" ? 10 : 0
    );
    const confidenceMultiplier = CONFIDENCE_MULTIPLIERS[finding.confidence] ?? 1.0;

    totalDeduction += baseWeight * confidenceMultiplier;
  }

  // Calculate score bounded between minScore (0) and maxScore (100)
  const score = Math.max(scoring.minScore, Math.min(scoring.maxScore, Math.round(scoring.baseScore - totalDeduction)));

  // Resolve verdict from knowledge base
  let verdictObj = verdicts.verdicts.find(v => score >= v.minScore && score <= v.maxScore);
  if (!verdictObj) {
    verdictObj = verdicts.verdicts[verdicts.verdicts.length - 1]; // Fallback to SUS
  }

  return {
    score,
    verdict: verdictObj.code === "MILDLY_SUS" ? "MILDLY SUS" : verdictObj.code,
    verdictDetails: {
      code: verdictObj.code,
      label: verdictObj.label,
      summary: verdictObj.summary,
      explanation: verdictObj.explanation,
      color: verdictObj.color
    },
    counts,
    totalDeduction: Math.round(totalDeduction),
    scoringVersion: scoring.version
  };
}

module.exports = {
  SEVERITY_WEIGHTS,
  CONFIDENCE_MULTIPLIERS,
  normalizeAndDeduplicateFindings,
  calculateRiskScore
};
