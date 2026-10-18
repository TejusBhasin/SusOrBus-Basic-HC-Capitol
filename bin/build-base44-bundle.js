"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const KB_DIR = path.join(ROOT, "sus-or-bus", "lib", "knowledge");

// Read JSON catalogs
const metadata = JSON.parse(fs.readFileSync(path.join(KB_DIR, "metadata.json"), "utf8"));
const messages = JSON.parse(fs.readFileSync(path.join(KB_DIR, "messages.json"), "utf8"));
const verdicts = JSON.parse(fs.readFileSync(path.join(KB_DIR, "verdicts.json"), "utf8"));
const scoring = JSON.parse(fs.readFileSync(path.join(KB_DIR, "scoring.json"), "utf8"));
const domains = JSON.parse(fs.readFileSync(path.join(KB_DIR, "domains.json"), "utf8"));
const phishing = JSON.parse(fs.readFileSync(path.join(KB_DIR, "phishing.json"), "utf8"));
const policyLexicon = JSON.parse(fs.readFileSync(path.join(KB_DIR, "policy-lexicon.json"), "utf8"));
const findings = JSON.parse(fs.readFileSync(path.join(KB_DIR, "findings.json"), "utf8"));
const rules = JSON.parse(fs.readFileSync(path.join(KB_DIR, "rules.json"), "utf8"));

const bundleContent = `// ============================================================================
// SusOrBus Base44 Unified Scanner Engine (V2.6.0)
// Complete Deterministic, AI-Free Website Safety, Privacy & Risk Analysis Engine
// Ready for direct deployment into Base44 Functions (functions/check.js) or Node.js
// ============================================================================

"use strict";

// 1. EMBEDDED KNOWLEDGE BASE DATASETS
const KB = {
  metadata: ${JSON.stringify(metadata, null, 2)},
  messages: ${JSON.stringify(messages, null, 2)},
  verdicts: ${JSON.stringify(verdicts, null, 2)},
  scoring: ${JSON.stringify(scoring, null, 2)},
  domains: ${JSON.stringify(domains, null, 2)},
  phishing: ${JSON.stringify(phishing, null, 2)},
  policyLexicon: ${JSON.stringify(policyLexicon, null, 2)},
  findings: ${JSON.stringify(findings, null, 2)},
  rules: ${JSON.stringify(rules, null, 2)}
};

// 2. TEMPLATE RENDERER
function renderTemplate(template, variables = {}, placeholders = {}) {
  if (typeof template !== "string") return "";
  return template.replace(/\\{([a-zA-Z0-9_]+)\\}/g, (match, varName) => {
    let val = variables[varName];
    if (val === undefined || val === null) val = "";
    if (typeof val !== "string") val = String(val);
    return val
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  });
}

// 3. URL NORMALIZATION & VALIDATION
function cleanTarget(input) {
  if (!input || typeof input !== "string") return "";
  let s = input.trim();
  s = s.replace(/^https?:\\/\\//i, "");
  s = s.replace(/^\\/\\//, "");
  s = s.split("/")[0].split("?")[0].split("#")[0];
  s = s.split(":")[0];
  s = s.toLowerCase();
  if (s.includes("..") || s.startsWith(".") || s.endsWith(".")) return "";
  return s;
}

function normalizeUrl(rawInput) {
  if (!rawInput || typeof rawInput !== "string") throw new Error("Invalid URL input");
  let input = rawInput.trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\//i.test(input)) {
    input = "https://" + input;
  }
  const parsed = new URL(input);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS protocols are permitted");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Credentials in URLs are rejected");
  }
  const port = parsed.port ? Number.parseInt(parsed.port, 10) : (parsed.protocol === "https:" ? 443 : 80);
  if (port !== 80 && port !== 443) {
    throw new Error("Only standard web ports 80 and 443 are supported");
  }
  return {
    normalizedUrl: parsed.href,
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    port,
    pathname: parsed.pathname || "/",
    search: parsed.search || ""
  };
}

// 4. DETERMINISTIC RULE ENGINE
const findingCatalog = new Map();
for (const f of KB.findings.findings) findingCatalog.set(f.id, f);

function evaluateConditions(conditions, obs) {
  for (const [key, expected] of Object.entries(conditions)) {
    switch (key) {
      case "protocolEquals": if (obs.protocol !== expected) return false; break;
      case "isHttps": if (Boolean(obs.isHttps) !== expected) return false; break;
      case "hasPasswordInput": if (Boolean(obs.hasPasswordInput) !== expected) return false; break;
      case "hasInsecureOrCrossOriginPasswordForm": if (Boolean(obs.hasInsecureOrCrossOriginPasswordForm) !== expected) return false; break;
      case "hasMetaRefresh": if (Boolean(obs.hasMetaRefresh) !== expected) return false; break;
      case "hasHsts": if (Boolean(obs.hasHsts) !== expected) return false; break;
      case "hstsMaxAgeGte": if ((obs.hstsMaxAge || 0) < expected) return false; break;
      case "hstsMaxAgeLt": if ((obs.hstsMaxAge || 0) >= expected) return false; break;
      case "hasCsp": if (Boolean(obs.hasCsp) !== expected) return false; break;
      case "hasXctoNosniff": if (Boolean(obs.hasXctoNosniff) !== expected) return false; break;
      case "hasFramingProtection": if (Boolean(obs.hasFramingProtection) !== expected) return false; break;
      case "hasServerVersionDisclosure": if (Boolean(obs.hasServerVersionDisclosure) !== expected) return false; break;
      case "hasScriptObfuscation": if (Boolean(obs.hasScriptObfuscation) !== expected) return false; break;
      case "thirdPartyIframesGt": if ((obs.thirdPartyIframesCount ?? 0) <= expected) return false; break;
      case "hasScamKeywords": if (Boolean(obs.hasScamKeywords) !== expected) return false; break;
      default: if (obs[key] !== expected) return false; break;
    }
  }
  return true;
}

function evaluateObservationRules(obs) {
  const emittedFindings = [];
  for (const rule of KB.rules.rules) {
    if (!evaluateConditions(rule.conditions, obs)) continue;
    const findingDef = findingCatalog.get(rule.outputFindingId);
    if (!findingDef) continue;

    const variables = {
      finalUrl: obs.finalUrl || "",
      action: obs.passwordFormAction || "",
      destinationDetail: obs.passwordFormDestinationDetail || "",
      content: obs.metaRefreshContent || "",
      hstsValue: obs.hstsValue || "",
      maxAge: obs.hstsMaxAge || 0,
      policySnippet: obs.cspSnippet || "",
      headerValue: obs.xctoValue || "nosniff",
      mechanism: obs.framingMechanism || "framing protection",
      banner: obs.serverBanner || "",
      scriptCount: obs.scripts?.external || 0,
      patternDetail: obs.scriptObfuscationPattern || "eval/atob unpacker",
      frameCount: obs.thirdPartyIframesCount || 0,
      domains: obs.thirdPartyIframeDomains || "",
      host: obs.targetHost || "",
      phrases: obs.scamPhrasesMatched || ""
    };

    const title = renderTemplate(findingDef.titleTemplate, variables, findingDef.placeholders);
    const summary = renderTemplate(findingDef.summaryTemplate, variables, findingDef.placeholders);
    const evidence = renderTemplate(findingDef.evidenceTemplate, variables, findingDef.placeholders);
    const whyItMatters = renderTemplate(findingDef.whyItMattersTemplate, variables, findingDef.placeholders);
    const recommendation = renderTemplate(findingDef.recommendationTemplate, variables, findingDef.placeholders);

    let level = "good";
    if (findingDef.severity === "critical" || findingDef.severity === "high") level = "bad";
    else if (findingDef.severity === "medium" || findingDef.severity === "low") level = "warning";

    emittedFindings.push({
      id: findingDef.id,
      legacyId: findingDef.legacyId || findingDef.id,
      category: findingDef.category,
      subcategory: findingDef.subcategory,
      title,
      summary,
      evidence,
      whyItMatters,
      recommendation,
      severity: findingDef.severity,
      confidence: findingDef.confidence,
      source: findingDef.source,
      status: "detected",
      limitations: findingDef.limitations,
      level,
      simple: summary,
      nerd: evidence,
      matchedRuleId: rule.id
    });
  }
  return { findings: emittedFindings };
}

// 5. TRACKER DETECTION WITH STRICT DOMAIN BOUNDARIES
function matchDomainToService(hostname) {
  if (!hostname || typeof hostname !== "string") return null;
  const host = hostname.toLowerCase();
  for (const s of KB.domains.services) {
    const pat = s.pattern.toLowerCase();
    if (s.exactMatch) {
      if (host === pat) return s;
    } else {
      if (host === pat || host.endsWith("." + pat)) return s;
    }
  }
  return null;
}

function detectTrackers(html, siteHost) {
  const detected = [];
  const seenKeys = new Set();
  const urlRegex = /(?:src|href)=["']([^"']+)["']/gi;
  let match;
  while ((match = urlRegex.exec(html)) !== null) {
    const raw = match[1];
    let host;
    try {
      host = new URL(raw, "https://" + siteHost).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (host === siteHost || host.endsWith("." + siteHost)) continue;
    const matchedService = matchDomainToService(host);
    if (matchedService) {
      const key = matchedService.provider + ":" + host;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        detected.push({
          provider: matchedService.provider,
          category: matchedService.category,
          domain: host,
          isTracker: matchedService.isTracker
        });
      }
    }
  }
  return detected;
}

// 6. STATIC DOCUMENT & ELEMENT PARSER
function extractVisibleText(html) {
  return html
    .replace(/<script\\b[^<]*(?:(?!<\\/script>)<[^<]*)*<\\/script>/gi, " ")
    .replace(/<style\\b[^<]*(?:(?!<\\/style>)<[^<]*)*<\\/style>/gi, " ")
    .replace(/<!--[\\s\\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/\\s+/g, " ")
    .trim();
}

function analyzeStaticDocument(html, siteHost, pageUrl) {
  const normHost = (siteHost || "").toLowerCase();
  const forms = [];
  let hasPasswordInput = false;
  let hasInsecureOrCrossOriginPasswordForm = false;
  let passwordFormAction = "";
  let passwordFormDestinationDetail = "";

  const formRegex = /<form\\b([^>]*)>([\\s\\S]*?)<\\/form>/gi;
  let fMatch;
  while ((fMatch = formRegex.exec(html)) !== null) {
    const attrs = fMatch[1];
    const body = fMatch[2];
    const actionMatch = attrs.match(/action=["']([^"']*)["']/i);
    const rawAction = actionMatch ? actionMatch[1].trim() : "";
    const isPasswordForm = /type=["']password["']/i.test(body);
    if (isPasswordForm) hasPasswordInput = true;

    let targetHost = normHost;
    let isHttps = true;
    if (rawAction && !rawAction.startsWith("#") && !rawAction.startsWith("/")) {
      try {
        const parsed = new URL(rawAction, pageUrl || ("https://" + normHost));
        targetHost = parsed.hostname.toLowerCase();
        isHttps = parsed.protocol === "https:";
      } catch {}
    }

    const isCrossOrigin = targetHost !== normHost && !targetHost.endsWith("." + normHost);
    if (isPasswordForm && (!isHttps || isCrossOrigin)) {
      hasInsecureOrCrossOriginPasswordForm = true;
      passwordFormAction = rawAction || "(self)";
      passwordFormDestinationDetail = isCrossOrigin ? ("external domain '" + targetHost + "'") : "unencrypted HTTP endpoint";
    }
  }

  // Check meta-refresh
  const metaRefresh = /<meta[^>]+http-equiv=["']refresh["'][^>]*content=["']([0-9]+;\\s*url=[^"']+)["']/i.exec(html);

  // Check script obfuscation
  const hasScriptObfuscation = /eval\\s*\\(\\s*unescape\\s*\\(|eval\\s*\\(\\s*atob\\s*\\(|document\\.write\\s*\\(\\s*unescape/i.test(html);

  // Check scam keywords
  const plainText = extractVisibleText(html).toLowerCase();
  const matchedScamPhrases = [];
  for (const phrase of KB.phishing.scamKeywords) {
    if (plainText.includes(phrase.toLowerCase())) matchedScamPhrases.push(phrase);
  }

  // Check third party iframes
  const iframeRegex = /<iframe\\b[^>]*src=["']([^"']+)["']/gi;
  let ifMatch;
  const iframeHosts = new Set();
  while ((ifMatch = iframeRegex.exec(html)) !== null) {
    try {
      const h = new URL(ifMatch[1], pageUrl || ("https://" + normHost)).hostname.toLowerCase();
      if (h !== normHost && !h.endsWith("." + normHost)) iframeHosts.add(h);
    } catch {}
  }

  const trackers = detectTrackers(html, normHost);

  const observations = {
    targetHost: normHost,
    finalUrl: pageUrl,
    hasPasswordInput,
    hasInsecureOrCrossOriginPasswordForm,
    passwordFormAction,
    passwordFormDestinationDetail,
    hasMetaRefresh: Boolean(metaRefresh),
    metaRefreshContent: metaRefresh ? metaRefresh[1] : "",
    hasScriptObfuscation,
    scriptObfuscationPattern: hasScriptObfuscation ? "eval(unescape/atob) unpacker pattern" : "",
    hasScamKeywords: matchedScamPhrases.length > 0,
    scamPhrasesMatched: matchedScamPhrases.slice(0, 3).join(", "),
    thirdPartyIframesCount: iframeHosts.size,
    thirdPartyIframeDomains: Array.from(iframeHosts).slice(0, 3).join(", ")
  };

  const { findings } = evaluateObservationRules(observations);
  return {
    findings,
    trackers,
    observations
  };
}

// 7. SECURITY HEADERS ANALYZER
function analyzeSecurityHeaders(headers = {}, finalUrl = "") {
  const norm = {};
  for (const [k, v] of Object.entries(headers)) norm[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);

  const isHttps = finalUrl.startsWith("https:");
  const hsts = norm["strict-transport-security"];
  let hstsMaxAge = 0;
  if (hsts) {
    const m = hsts.match(/max-age=(\\d+)/i);
    hstsMaxAge = m ? Number.parseInt(m[1], 10) : 0;
  }

  const csp = norm["content-security-policy"];
  const xfo = norm["x-frame-options"];
  const hasCspFraming = csp && /frame-ancestors/i.test(csp);
  const serverBanner = norm["server"] || norm["x-powered-by"] || "";

  const obs = {
    finalUrl,
    protocol: isHttps ? "https:" : "http:",
    isHttps,
    hasHsts: Boolean(hsts),
    hstsValue: hsts || "",
    hstsMaxAge,
    hasCsp: Boolean(csp),
    cspSnippet: csp ? (csp.length > 100 ? csp.slice(0, 100) + "..." : csp) : "",
    hasXctoNosniff: Boolean(norm["x-content-type-options"] && norm["x-content-type-options"].toLowerCase().includes("nosniff")),
    xctoValue: norm["x-content-type-options"] || "",
    hasFramingProtection: Boolean(xfo || hasCspFraming),
    framingMechanism: xfo ? ("X-Frame-Options: " + xfo) : (hasCspFraming ? "CSP frame-ancestors" : ""),
    hasServerVersionDisclosure: Boolean(serverBanner && /\\d+\\.\\d+/.test(serverBanner)),
    serverBanner
  };

  const { findings } = evaluateObservationRules(obs);
  return findings.filter(f => f.category === "security" && (f.subcategory === "transport" || f.subcategory === "headers"));
}

// 8. NEGATION-AWARE POLICY ANALYZER
function analyzePolicyContent(policyText) {
  const lower = policyText.toLowerCase();
  const results = {};

  for (const [category, config] of Object.entries(KB.policyLexicon.disclosureCategories)) {
    let status = "not_found";
    let matchedPhrase = null;

    if (config.negativePatterns) {
      for (const pat of config.negativePatterns) {
        const m = lower.match(new RegExp(pat, "i"));
        if (m) { status = "explicit_denial"; matchedPhrase = m[0]; break; }
      }
    }
    if (status === "not_found" && config.affirmativePatterns) {
      for (const pat of config.affirmativePatterns) {
        const m = lower.match(new RegExp(pat, "i"));
        if (m) { status = "disclosed"; matchedPhrase = m[0]; break; }
      }
    }
    results[category] = {
      status,
      matchedPhrase,
      isAffirmative: status === "disclosed",
      isDenied: status === "explicit_denial"
    };
  }

  if (!results.deletion && results.deletionRights) results.deletion = results.deletionRights;
  if (!results.userRights && results.deletionRights) results.userRights = results.deletionRights;
  if (!results.contact && results.contactMethod) results.contact = results.contactMethod;
  return results;
}

function extractPolicyLinks(html, base) {
  const found = { terms: null, privacy: null };
  const linkRegex = /<a[^>]+href=["']([^"']+)["'][^>]*>([\\s\\S]*?)<\\/a>/gi;
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    const rawHref = match[1].trim();
    if (!rawHref || rawHref.startsWith("#") || rawHref.startsWith("javascript:")) continue;
    const text = match[2].replace(/<[^>]+>/g, " ").toLowerCase();
    const searchTarget = (rawHref + " " + text).toLowerCase();
    let abs;
    try { abs = new URL(rawHref, base).href; } catch { continue; }
    if (!found.terms && /(?:terms\\s+of\\s+service|terms\\s+and\\s+conditions|\\btos\\b|user\\s+agreement)/.test(searchTarget)) {
      found.terms = abs;
    }
    if (!found.privacy && /(?:privacy\\s+policy|privacy\\s+notice|data\\s+policy|\\bprivacy\\b)/.test(searchTarget)) {
      found.privacy = abs;
    }
  }
  return found;
}

function buildTermsFindings(policies, observedTrackers = []) {
  const list = [];
  if (policies.length === 0) {
    const def = findingCatalog.get("POL_POLICY_NONE_FOUND");
    if (def) {
      list.push({
        id: def.id,
        legacyId: "policy-none-found",
        category: def.category,
        title: def.titleTemplate,
        summary: def.summaryTemplate,
        evidence: def.evidenceTemplate,
        whyItMatters: def.whyItMattersTemplate,
        recommendation: def.recommendationTemplate,
        severity: def.severity,
        confidence: def.confidence,
        level: "warning",
        simple: def.summaryTemplate,
        nerd: def.evidenceTemplate
      });
    }
    return list;
  }

  for (const policy of policies) {
    if (policy.ok) {
      const disc = policy.disclosures || {};
      if (disc.dataSelling && disc.dataSelling.isDenied) {
        const denyDef = findingCatalog.get("POL_DATA_SELLING_DENIED");
        if (denyDef) {
          list.push({
            id: denyDef.id,
            legacyId: "policy-data-selling-denied",
            category: denyDef.category,
            title: denyDef.titleTemplate,
            summary: denyDef.summaryTemplate,
            evidence: "Policy statement confirms: " + (disc.dataSelling.matchedPhrase || "we do not sell personal data"),
            whyItMatters: denyDef.whyItMattersTemplate,
            recommendation: denyDef.recommendationTemplate,
            severity: denyDef.severity,
            confidence: denyDef.confidence,
            level: "good",
            simple: denyDef.summaryTemplate,
            nerd: "Verified explicit denial clause."
          });
        }
      }

      const cookiesDisclosed = Boolean(disc.cookies && (disc.cookies.isAffirmative || disc.cookies === true));
      const adsDisclosed = Boolean(disc.dataSelling && (disc.dataSelling.isAffirmative || disc.dataSelling === true));
      if (policy.kind === "Privacy Policy" && observedTrackers.length > 0 && !cookiesDisclosed && !adsDisclosed) {
        const gapDef = findingCatalog.get("POL_TRACKER_DISCLOSURE_GAP");
        if (gapDef) {
          list.push({
            id: gapDef.id,
            legacyId: "policy-tracker-disclosure-gap",
            category: gapDef.category,
            title: gapDef.titleTemplate,
            summary: gapDef.summaryTemplate,
            evidence: "Trackers identified on-page but unlisted in policy: " + observedTrackers.map(t => t.provider || t.domain).join(", "),
            whyItMatters: gapDef.whyItMattersTemplate,
            recommendation: gapDef.recommendationTemplate,
            severity: gapDef.severity,
            confidence: gapDef.confidence,
            level: "warning",
            simple: gapDef.summaryTemplate,
            nerd: "Transparency omission observed."
          });
        }
      }
    }
  }
  return list;
}

// 9. CALIBRATED RISK SCORER & MULTI-DIMENSIONAL VECTORS
function calculateRiskScore(findings = [], options = {}) {
  const counts = { good: 0, warning: 0, bad: 0 };
  let totalDeduction = 0;
  const findingWeights = KB.scoring.findingWeights || {};

  const vectorDeductions = { transport: 0, content: 0, telemetry: 0, governance: 0 };

  for (const finding of findings) {
    counts[finding.level] = (counts[finding.level] || 0) + 1;
    const specificWeight = (finding.id && findingWeights[finding.id]) ?? (finding.legacyId && findingWeights[finding.legacyId]);
    const baseWeight = specificWeight !== undefined ? specificWeight : (
      KB.scoring.severityWeights[finding.severity] ?? (finding.level === "bad" ? 25 : finding.level === "warning" ? 10 : 0)
    );
    const confidenceMultiplier = KB.scoring.confidenceMultipliers[finding.confidence] ?? 1.0;
    const deduction = Math.round(baseWeight * confidenceMultiplier);
    finding.impact = deduction;
    totalDeduction += deduction;

    const sub = finding.subcategory || "";
    const cat = finding.category || "";
    if (sub === "transport" || sub === "headers") vectorDeductions.transport += deduction;
    else if (sub === "forms" || sub === "scripts" || sub === "elements" || sub === "scam" || cat === "content") vectorDeductions.content += deduction;
    else if (cat === "privacy" || sub === "tracking_transparency" || sub === "telemetry") vectorDeductions.telemetry += deduction;
    else if (cat === "policy" || sub === "transparency") vectorDeductions.governance += deduction;
  }

  const trackers = options.trackers || [];
  if (trackers.length > 0) {
    const trackerPenalty = Math.min(14, trackers.length * 2);
    totalDeduction += trackerPenalty;
    vectorDeductions.telemetry += trackerPenalty;
  }

  const score = Math.max(KB.scoring.minScore, Math.min(KB.scoring.maxScore, Math.round(KB.scoring.baseScore - totalDeduction)));
  let verdictObj = KB.verdicts.verdicts.find(v => score >= v.minScore && score <= v.maxScore) || KB.verdicts.verdicts[KB.verdicts.verdicts.length - 1];

  const vectors = {
    transport: {
      score: Math.max(0, Math.min(100, 100 - vectorDeductions.transport)),
      label: vectorDeductions.transport === 0 ? "Hardened" : (vectorDeductions.transport < 15 ? "Guarded" : "Vulnerable")
    },
    content: {
      score: Math.max(0, Math.min(100, 100 - vectorDeductions.content)),
      label: vectorDeductions.content === 0 ? "Clean" : (vectorDeductions.content < 20 ? "Caution" : "Suspicious")
    },
    telemetry: {
      score: Math.max(0, Math.min(100, 100 - vectorDeductions.telemetry)),
      label: vectorDeductions.telemetry === 0 ? "Minimal" : (vectorDeductions.telemetry < 16 ? "Moderate" : "Heavy Tracking")
    },
    governance: {
      score: Math.max(0, Math.min(100, 100 - vectorDeductions.governance)),
      label: vectorDeductions.governance === 0 ? "Transparent" : (vectorDeductions.governance < 15 ? "Deficient" : "Unverified")
    }
  };

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
    vectors,
    totalDeduction: Math.round(totalDeduction)
  };
}

// 10. AI-STYLE HEURISTIC SYNTHESIZER
function generateAiSynthesis(context = {}) {
  const { site = "target domain", url = "", score = 100, verdict = "BUS", findings = [], trackers = [], policies = [], vectors = {} } = context;

  const fIds = new Set(findings.map(f => f.id));
  const lIds = new Set(findings.map(f => f.legacyId).filter(Boolean));
  const has = (id, leg) => fIds.has(id) || (leg && lIds.has(leg));

  const isHttps = url.startsWith("https:") || has("SEC_TRANSPORT_HTTPS", "transport-https");
  const hasStrongHsts = has("SEC_HEADER_HSTS_STRONG", "header-hsts-strong");
  const hasShortHsts = has("SEC_HEADER_HSTS_SHORT", "header-hsts-short");
  const hasCsp = has("SEC_HEADER_CSP_PRESENT", "header-csp-present");
  const hasCrossOriginPassword = has("SEC_FORM_PASSWORD_CROSS_ORIGIN", "form-password-insecure-destination");
  const hasPasswordDetected = has("SEC_FORM_PASSWORD_DETECTED", "form-password-detected");
  const hasObfuscation = has("SEC_SCRIPT_OBFUSCATION", "scripts-obfuscation-detected");
  const hasNoPolicy = has("POL_POLICY_NONE_FOUND", "policy-none-found");
  const hasTrackerGap = has("POL_TRACKER_DISCLOSURE_GAP", "policy-tracker-disclosure-gap");
  const hasSaleDenied = has("POL_DATA_SELLING_DENIED", "policy-data-selling-denied");

  let p1 = "";
  if (!isHttps) {
    p1 = "CRITICAL PROTOCOL HAZARD: Automated heuristic scanning of " + site + " identified that communications occur over unencrypted HTTP. In-transit packets are vulnerable to on-path interception.";
  } else if (hasStrongHsts && hasCsp) {
    p1 = "Heuristic inspection of " + site + " confirms an enterprise-grade cryptographic baseline. Transport is strictly secured via HTTPS backed by long-duration HSTS enforcement, complemented by active Content Security Policy (CSP) directives.";
  } else if (hasStrongHsts) {
    p1 = "Heuristic inspection of " + site + " confirms hardened TLS transport encryption backed by long-duration HSTS enforcement. However, Content Security Policy (CSP) headers are absent.";
  } else if (hasShortHsts) {
    p1 = "Heuristic inspection of " + site + " confirms TLS encryption; however, HSTS max-age is set to a short duration, leaving future sessions vulnerable to protocol downgrade intercepts.";
  } else {
    p1 = "Heuristic inspection of " + site + " indicates standard TLS encryption is active, but HTTP Strict Transport Security (HSTS) is omitted. Client connections remain exposed to downgrade threats.";
  }

  if (hasCrossOriginPassword) {
    p1 += " CRITICAL FORM VULNERABILITY: Document parsing detected password inputs configured to submit credentials cross-origin to an untrusted external destination.";
  } else if (hasPasswordDetected) {
    p1 += " Authentication elements were detected; form handlers target the verified origin without cross-origin exfiltration routes.";
  } else {
    p1 += " No authentication credential fields or password capture inputs were identified on the analyzed landing document.";
  }

  let p2 = "";
  if (trackers.length === 0) {
    p2 = "From a telemetry standpoint, the landing page exhibits a clean profile with zero detected third-party tracking beacons or ad exchanges.";
  } else {
    p2 = "From a telemetry standpoint, the page ingests " + trackers.length + " external tracking service(s) (" + trackers.map(t => t.provider || t.domain).slice(0, 3).join(", ") + "), establishing outbound network requests across distinct third-party domains.";
  }

  if (hasSaleDenied) {
    p2 += " Commendably, the published privacy documentation features explicit contractual disclosures confirming the operator does not monetize or sell user personal records.";
  } else if (hasTrackerGap) {
    p2 += " Crucially, the published privacy documentation fails to disclose these active third-party tracking entities, creating an observed discrepancy between page behavior and stated privacy commitments.";
  } else if (hasNoPolicy) {
    p2 += " Crucially, no accessible privacy policy or terms of service could be verified for this domain, leaving data retention periods and third-party data distribution completely undefined.";
  } else {
    p2 += " Basic legal disclosure documents were identified on the page.";
  }

  let p3 = "";
  let riskProfile = "MINIMAL RISK";
  if (score >= 70) {
    riskProfile = "MINIMAL RISK";
    p3 = "Analyst Assessment: " + site + " satisfies baseline security expectations with a calibrated trust score of " + score + "/100. The lack of malicious redirect chains, obfuscated script loaders, or deceptive inputs makes this link appropriate for regular interaction under standard user precautions.";
  } else if (score >= 40) {
    riskProfile = "ELEVATED EXPOSURE";
    p3 = "Analyst Assessment: " + site + " exhibits an elevated risk profile with a calibrated score of " + score + "/100 (MILDLY SUS). The convergence of defensive configuration gaps and third-party telemetry warrants visitor vigilance.";
  } else {
    riskProfile = "CRITICAL HAZARD";
    p3 = "Analyst Assessment: CRITICAL THREAT PROFILE (" + score + "/100 - SUS). The automated scanner discovered high-severity security anomalies consistent with deceptive landing infrastructure or credential theft. Visitors are advised not to interact with this link.";
  }

  const recs = [];
  if (!isHttps) recs.push({ action: "Migrate entire site transport to HTTPS with TLS 1.3", points: "+33 pts" });
  if (hasCrossOriginPassword) recs.push({ action: "Refactor login forms to submit exclusively to verified first-party origin", points: "+47 pts" });
  if (!hasStrongHsts && isHttps) recs.push({ action: "Enable Strict-Transport-Security (max-age >= 31536000; preload)", points: "+9 pts" });
  if (!hasCsp) recs.push({ action: "Deploy Content-Security-Policy with strict script-src and frame-ancestors", points: "+7 pts" });
  if (hasTrackerGap) recs.push({ action: "Update Privacy Policy to explicitly disclose third-party analytics partners", points: "+8 pts" });
  if (hasNoPolicy) recs.push({ action: "Publish formal Privacy Policy and Terms of Service documents", points: "+14 pts" });

  const summaryBullets = [
    {
      category: "Transport",
      text: isHttps ? (hasStrongHsts ? "TLS encryption strictly enforced with long-duration HSTS" : "TLS encryption active; HTTP Strict Transport Security (HSTS) lacks preload") : "Unencrypted cleartext HTTP detected (traffic exposed to interception)",
      level: isHttps ? (hasStrongHsts ? "good" : "warning") : "bad"
    },
    {
      category: "Forms & Input",
      text: hasCrossOriginPassword ? "Password input configured to submit cross-origin to an untrusted external destination" : (hasPasswordDetected ? "Standard login form present submitting to verified domain" : "No credential or password input fields detected on page"),
      level: hasCrossOriginPassword ? "bad" : "good"
    },
    {
      category: "Telemetry",
      text: trackers.length === 0 ? "Zero third-party trackers or advertising beacons detected" : (trackers.length + " third-party tracking/analytics service(s) detected (" + trackers.map(t => t.provider || t.domain).slice(0, 3).join(", ") + ")"),
      level: trackers.length === 0 ? "good" : (trackers.length > 3 ? "warning" : "good")
    },
    {
      category: "Governance",
      text: hasSaleDenied ? "Privacy policy explicitly guarantees personal data is not sold" : (hasNoPolicy ? "No privacy policy or terms of service documentation found" : (hasTrackerGap ? "Third-party trackers active on page but not acknowledged in privacy policy" : "Standard privacy documentation published")),
      level: hasSaleDenied ? "good" : (hasNoPolicy || hasTrackerGap ? "warning" : "good")
    },
    {
      category: "Guidance",
      text: score >= 70 ? "Baseline security standards met; appropriate for standard interaction" : (score >= 40 ? "Configuration gaps and telemetry exposure warrant visitor caution" : "High risk indicators detected; avoid credential submission or downloads"),
      level: score >= 70 ? "good" : (score >= 40 ? "warning" : "bad")
    }
  ];

  return {
    summaryTitle: "Key Security Observations",
    summaryBullets: summaryBullets,
    badge: "SECURITY ASSESSMENT",
    headline: "Calibrated Trust Index: " + score + "/100 (" + verdict + ") — " + riskProfile,
    executiveSummary: [p1, p2, p3].join("\\n\\n"),
    paragraphs: [p1, p2, p3],
    keyTakeaways: [
      "Transport: " + (isHttps ? (hasStrongHsts ? "Enforced TLS with long-term HSTS" : "Standard TLS (missing HSTS preload)") : "UNENCRYPTED (High Risk)"),
      "Telemetry: " + (trackers.length === 0 ? "Zero third-party trackers detected" : (trackers.length + " active tracker service(s) identified")),
      "Governance: " + (hasSaleDenied ? "Explicit data selling denial confirmed" : (hasNoPolicy ? "Missing privacy and terms disclosures" : (hasTrackerGap ? "Tracker disclosure transparency gap" : "Basic legal disclosures present")))
    ],
    riskProfile: riskProfile,
    confidenceScore: 96,
    skepticismCalibration: "Zero-Trust Deterministic Heuristics",
    actionableRecommendations: recs.slice(0, 4),
    vectors: vectors || {}
  };
}

// 11. MASTER SCANNER ORCHESTRATION PIPELINE
async function runFullScan(targetInput) {
  const normHost = cleanTarget(targetInput);
  if (!normHost) throw new Error("Invalid or unresolvable hostname format");

  let pageUrl = "https://" + normHost;
  let html = "";
  let headers = {};
  let status = 200;

  // Perform secure HTTP fetch (works in Deno, Node.js fetch, or fallback)
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const resp = await fetch(pageUrl, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SusOrBusScanner/2.6; +https://susorbus.com)"
      },
      redirect: "follow"
    });
    clearTimeout(timeout);
    status = resp.status;
    pageUrl = resp.url || pageUrl;
    html = await resp.text();
    for (const [k, v] of resp.headers.entries()) headers[k.toLowerCase()] = v;
  } catch (err) {
    if (pageUrl.startsWith("https:")) {
      try {
        pageUrl = "http://" + normHost;
        const resp2 = await fetch(pageUrl, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; SusOrBusScanner/2.6; +https://susorbus.com)" }
        });
        status = resp2.status;
        pageUrl = resp2.url || pageUrl;
        html = await resp2.text();
        for (const [k, v] of resp2.headers.entries()) headers[k.toLowerCase()] = v;
      } catch (err2) {
        throw new Error("Unable to establish HTTP/HTTPS connection to " + normHost + ": " + err2.message);
      }
    } else {
      throw new Error("Unable to establish connection to " + normHost + ": " + err.message);
    }
  }

  // 1. Static Document Analysis
  const staticResult = analyzeStaticDocument(html, normHost, pageUrl);

  // 2. Security Headers Analysis
  const headerFindings = analyzeSecurityHeaders(headers, pageUrl);

  // 3. Policy Discovery & Negation-Aware Inspection
  const policyLinks = extractPolicyLinks(html, pageUrl);
  const policies = [];
  if (policyLinks.privacy) {
    try {
      const pResp = await fetch(policyLinks.privacy);
      if (pResp.ok) {
        const pHtml = await pResp.text();
        const pText = extractVisibleText(pHtml);
        policies.push({
          kind: "Privacy Policy",
          url: policyLinks.privacy,
          status: pResp.status,
          ok: true,
          disclosures: analyzePolicyContent(pText)
        });
      }
    } catch {}
  }
  const termsFindings = buildTermsFindings(policies, staticResult.trackers);

  // 4. Consolidate and Deduplicate Findings
  const allFindings = [...staticResult.findings, ...headerFindings, ...termsFindings];
  const seenIds = new Set();
  const deduplicatedFindings = [];
  for (const f of allFindings) {
    const fId = f.id || f.title;
    if (seenIds.has(fId)) continue;
    seenIds.add(fId);
    deduplicatedFindings.push(f);
  }

  // 5. Calculate Precise Risk Score & Vectors
  const scoringResult = calculateRiskScore(deduplicatedFindings, { trackers: staticResult.trackers });

  // 6. Generate AI Heuristic Synthesis Briefing
  const aiSynthesis = generateAiSynthesis({
    site: normHost,
    url: pageUrl,
    score: scoringResult.score,
    verdict: scoringResult.verdict,
    findings: deduplicatedFindings,
    trackers: staticResult.trackers,
    policies,
    vectors: scoringResult.vectors
  });

  return {
    site: normHost,
    url: pageUrl,
    status,
    checkedAt: new Date().toISOString(),
    score: scoringResult.score,
    verdict: scoringResult.verdict,
    verdictDetails: scoringResult.verdictDetails,
    counts: scoringResult.counts,
    vectors: scoringResult.vectors,
    aiSynthesis,
    findings: deduplicatedFindings,
    policies,
    termsFindings,
    analysis: {
      trackers: staticResult.trackers
    }
  };
}

// 12. BASE44 CLOUD FUNCTION HTTP HANDLER (Deno & Node.js Compatible)
if (typeof Deno !== "undefined" && Deno.serve) {
  Deno.serve(async (req) => {
    // Enable CORS for frontend invocations
    if (req.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    try {
      let site = "";
      if (req.method === "POST") {
        const body = await req.json().catch(() => ({}));
        site = body.site || body.url || "";
      } else {
        const u = new URL(req.url);
        site = u.searchParams.get("site") || u.searchParams.get("url") || "";
      }

      if (!site) {
        return Response.json({ error: "Missing required 'site' parameter" }, { status: 400 });
      }

      const result = await runFullScan(site);
      return Response.json(result, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Content-Type": "application/json"
        }
      });
    } catch (err) {
      return Response.json({ error: err.message || "Scan execution error" }, {
        status: 500,
        headers: { "Access-Control-Allow-Origin": "*" }
      });
    }
  });
}

// Export for module systems
if (typeof module !== "undefined" && module.exports) {
  module.exports = { runFullScan, calculateRiskScore, generateAiSynthesis, KB };
}
`;

fs.writeFileSync(path.join(ROOT, "base44-scanner-function.js"), bundleContent, "utf8");
console.log("Successfully created base44-scanner-function.js!");

