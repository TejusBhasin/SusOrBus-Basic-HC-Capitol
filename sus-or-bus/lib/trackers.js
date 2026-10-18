"use strict";

const { domains } = require("./knowledge");

/**
 * Sanitizes URLs to remove sensitive query parameters (e.g. auth tokens, emails, session IDs)
 * before logging or returning evidence.
 */
function sanitizeUrlForLogging(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return String(rawUrl || "").split("?")[0];
  }
}

/**
 * Determines whether two hostnames belong to the same registered domain or site.
 */
function isSameSite(hostA, hostB) {
  if (!hostA || !hostB) return false;
  const a = hostA.toLowerCase();
  const b = hostB.toLowerCase();
  if (a === b) return true;
  if (a.endsWith("." + b) || b.endsWith("." + a)) return true;
  return false;
}

/**
 * Classifies an external request origin or script URL using the knowledge base domain database.
 * Enforces strict domain boundary matching, rejecting unsafe substring matches.
 */
function classifyThirdParty(rawUrl, targetHostname) {
  let hostname = "";
  try {
    const parsed = new URL(rawUrl, "https://" + targetHostname);
    hostname = parsed.hostname.toLowerCase();
  } catch {
    hostname = String(rawUrl || "").toLowerCase();
  }

  const isThirdParty = !isSameSite(hostname, targetHostname);

  // Match against knowledge base domain catalog
  for (const entry of domains.services) {
    let matched = false;
    const targetPattern = entry.pattern.toLowerCase();

    if (entry.method === "exact") {
      matched = hostname === targetPattern;
    } else if (entry.method === "suffix") {
      matched = hostname === targetPattern || hostname.endsWith("." + targetPattern);
    }

    if (matched) {
      return {
        domain: hostname,
        isThirdParty,
        category: entry.category,
        provider: entry.provider,
        isTracker: entry.isTracker,
        confidence: entry.confidence || "high",
        source: entry.source,
        description: entry.description
      };
    }
  }

  return {
    domain: hostname,
    isThirdParty,
    category: isThirdParty ? "unclassified-third-party" : "first-party",
    provider: hostname,
    isTracker: false,
    confidence: "low",
    source: "Domain Boundary Heuristic",
    description: "Third-party host not listed in current knowledge base catalog."
  };
}

module.exports = {
  classifyThirdParty,
  sanitizeUrlForLogging,
  isSameSite,
  KNOWN_SERVICES: domains.services
};
