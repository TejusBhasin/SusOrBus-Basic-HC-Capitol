"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { classifyThirdParty, sanitizeUrlForLogging, isSameSite } = require("../sus-or-bus/lib/trackers");

describe("Layer D & H: Tracker and Third-Party Request Detection", () => {
  test("identifies known tracking and analytics services", () => {
    const ga = classifyThirdParty("https://www.google-analytics.com/analytics.js", "example.com");
    assert.equal(ga.isThirdParty, true);
    assert.equal(ga.category, "analytics");
    assert.equal(ga.isTracker, true);

    const meta = classifyThirdParty("https://connect.facebook.net/en_US/fbevents.js", "example.com");
    assert.equal(meta.isThirdParty, true);
    assert.equal(meta.category, "social");
    assert.equal(meta.isTracker, true);

    const ad = classifyThirdParty("https://securepubads.g.doubleclick.net/gampad/ads", "example.com");
    assert.equal(ad.category, "advertising");
    assert.equal(ad.isTracker, true);
  });

  test("differentiates benign CDN and font resources from trackers", () => {
    const cdn = classifyThirdParty("https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/react.min.js", "example.com");
    assert.equal(cdn.isThirdParty, true);
    assert.equal(cdn.category, "cdn");
    assert.equal(cdn.isTracker, false);

    const fonts = classifyThirdParty("https://fonts.googleapis.com/css2?family=Roboto", "example.com");
    assert.equal(fonts.category, "fonts");
    assert.equal(fonts.isTracker, false);
  });

  test("recognizes subdomains as first-party", () => {
    assert.equal(isSameSite("cdn.example.com", "example.com"), true);
    assert.equal(isSameSite("api.example.com", "example.com"), true);
    assert.equal(isSameSite("example.com", "othersite.com"), false);
  });

  test("sanitizes URLs to strip query parameters containing sensitive tokens", () => {
    const raw = "https://tracker.com/collect?token=secret123&user=john@example.com&id=42";
    const sanitized = sanitizeUrlForLogging(raw);
    assert.equal(sanitized, "https://tracker.com/collect");
  });
});

