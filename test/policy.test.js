"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { extractPolicyLinks, analyzePolicyContent, buildTermsFindings } = require("../sus-or-bus/lib/policy-analyzer");

describe("Layer E: Terms and Privacy Policy Analysis", () => {
  test("extracts Terms and Privacy Policy links from HTML", () => {
    const html = `
      <footer>
        <a href="/legal/terms">Terms of Service</a>
        <a href="/privacy-policy.html">Privacy Notice</a>
        <a href="/cookies">Cookie Policy</a>
      </footer>
    `;
    const links = extractPolicyLinks(html, "https://example.com/");
    assert.equal(links.terms, "https://example.com/legal/terms");
    assert.equal(links.privacy, "https://example.com/privacy-policy.html");
    assert.equal(links.cookie, "https://example.com/cookies");
  });

  test("analyzes policy text for essential disclosures", () => {
    const policyText = `
      We collect your personal information including name, email address, and IP address.
      We use cookies and tracking technologies to measure analytics.
      We share with third parties and service providers to run our platform.
      You have the right to request deletion of your account and data under GDPR and CCPA.
      Contact our data protection officer at privacy@example.com.
    `;
    const disclosures = analyzePolicyContent(policyText);
    assert.equal(disclosures.dataCollection.isAffirmative, true);
    assert.equal(disclosures.cookies.isAffirmative, true);
    assert.equal(disclosures.thirdPartySharing.isAffirmative, true);
    assert.equal(disclosures.deletion.isAffirmative, true);
    assert.equal(disclosures.userRights.isAffirmative, true);
    assert.equal(disclosures.contact.isAffirmative, true);
  });

  test("builds findings when policies are missing or unreachable", () => {
    const emptyPolicies = [];
    const missingFindings = buildTermsFindings(emptyPolicies);
    assert.equal(missingFindings.length, 1);
    assert.ok(missingFindings[0].id === "POL_POLICY_NONE_FOUND" || missingFindings[0].legacyId === "policy-none-found");
    assert.equal(missingFindings[0].level, "warning");

    const unreachable = [{
      kind: "Privacy Policy",
      url: "https://example.com/privacy",
      ok: false,
      error: "404 Not Found"
    }];
    const brokenFindings = buildTermsFindings(unreachable);
    assert.equal(brokenFindings[0].level, "warning");
    assert.ok(brokenFindings[0].legacyId === "policy-privacy-policy-unreachable" || brokenFindings[0].id.includes("POL_POLICY_UNREACHABLE"));
  });

  test("flags gap when trackers are present but not disclosed in privacy policy", () => {
    const policies = [{
      kind: "Privacy Policy",
      url: "https://example.com/privacy",
      ok: true,
      status: 200,
      size: 1500,
      disclosures: { dataCollection: true, cookies: false, advertising: false }
    }];
    const observedTrackers = [{ provider: "Meta Pixel", domain: "facebook.net" }];
    const findings = buildTermsFindings(policies, observedTrackers);
    const gapFinding = findings.find(f => f.id === "POL_TRACKER_DISCLOSURE_GAP" || f.legacyId === "policy-tracker-disclosure-gap");
    assert.ok(gapFinding, "Should flag tracker disclosure gap");
    assert.equal(gapFinding.level, "warning");
  });
});

