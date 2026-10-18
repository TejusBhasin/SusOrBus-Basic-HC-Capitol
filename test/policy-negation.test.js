"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { analyzePolicyContent, buildTermsFindings } = require("../sus-or-bus/lib/policy-analyzer");

describe("Negation-Aware Privacy Policy Engine", () => {
  test("never misinterprets explicit denial as affirmative admission", () => {
    const textDenyingSale = `
      Privacy Policy:
      We collect your contact email to fulfill orders.
      We do not sell your personal information or data to any third parties.
      We will never monetize user records.
    `;
    const disclosures = analyzePolicyContent(textDenyingSale);
    assert.equal(disclosures.dataSelling.status, "explicit_denial");
    assert.equal(disclosures.dataSelling.isDenied, true);
    assert.equal(disclosures.dataSelling.isAffirmative, false);
  });

  test("identifies affirmative disclosures when practice is stated", () => {
    const textAffirmingSharing = `
      We share your personal information with third parties and advertising partners.
    `;
    const disclosures = analyzePolicyContent(textAffirmingSharing);
    assert.equal(disclosures.thirdPartySharing.status, "disclosed");
    assert.equal(disclosures.thirdPartySharing.isAffirmative, true);
  });

  test("emits explicit denial finding when data sale is denied", () => {
    const policies = [{
      kind: "Privacy Policy",
      url: "https://example.com/privacy",
      ok: true,
      status: 200,
      size: 2000,
      disclosures: analyzePolicyContent("We do not sell your personal data or information to third parties.")
    }];
    const findings = buildTermsFindings(policies);
    const denialFinding = findings.find(f => f.id === "POL_DATA_SELLING_DENIED");
    assert.ok(denialFinding, "Should emit POL_DATA_SELLING_DENIED");
    assert.equal(denialFinding.level, "good");
    assert.ok(denialFinding.evidence.includes("do not sell"));
  });

  test("distinguishes silence / unmentioned practice from denial", () => {
    const silentText = "We are an online calculator widget. That is all.";
    const disclosures = analyzePolicyContent(silentText);
    assert.equal(disclosures.dataSelling.status, "not_found");
    assert.equal(disclosures.dataSelling.isDenied, false);
    assert.equal(disclosures.dataSelling.isAffirmative, false);
  });
});

