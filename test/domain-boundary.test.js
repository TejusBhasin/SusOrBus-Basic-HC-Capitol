"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { classifyThirdParty } = require("../sus-or-bus/lib/trackers");

describe("Domain Boundary & Service Classification", () => {
  test("matches legitimate provider subdomains", () => {
    const res = classifyThirdParty("https://adservice.google.com/ads", "mysite.com");
    // googleadservices or google services
    const ga = classifyThirdParty("https://region1.google-analytics.com/collect", "mysite.com");
    assert.equal(ga.provider, "Google Analytics");
    assert.equal(ga.isTracker, true);
  });

  test("rejects spoofed domains that merely contain provider substring", () => {
    // evil-google-analytics.com must NOT match google-analytics.com!
    const spoofed = classifyThirdParty("https://evil-google-analytics.com/steal", "mysite.com");
    assert.notEqual(spoofed.provider, "Google Analytics");
    assert.equal(spoofed.category, "unclassified-third-party");

    // notdoubleclick.net must NOT match doubleclick.net!
    const spoofed2 = classifyThirdParty("https://notdoubleclick.net/pixel", "mysite.com");
    assert.notEqual(spoofed2.provider, "Google DoubleClick");
    assert.equal(spoofed2.category, "unclassified-third-party");
  });

  test("enforces exact matching for specific provider hostnames", () => {
    const exactMatch = classifyThirdParty("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js", "mysite.com");
    assert.equal(exactMatch.provider, "Cloudflare CDNJS");
    assert.equal(exactMatch.category, "cdn");
    assert.equal(exactMatch.isTracker, false);

    // Some random cloudflare subdomain that isn't cdnjs should not be classified as CDNJS
    const otherSub = classifyThirdParty("https://random.cloudflare.com/page", "mysite.com");
    assert.notEqual(otherSub.provider, "Cloudflare CDNJS");
  });
});

