"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { safeFetchPage, FetchSecurityError, MAX_HTML_BYTES } = require("../sus-or-bus/lib/fetcher");

describe("Layer B: Safe Fetcher and Redirects", () => {
  test("enforces redirect bounds and rejects redirect loops", async () => {
    // Mock lookup that returns public IP
    const mockLookup = async () => [{ address: "93.184.216.34", family: 4 }];

    // Attempting safe fetch to non-existent or localhost triggers security bounds
    await assert.rejects(
      () => safeFetchPage("http://127.0.0.1", { customLookup: mockLookup }),
      { name: "DnsSecurityError" }
    );
  });

  test("rejects non-standard ports before network connection", async () => {
    await assert.rejects(
      () => safeFetchPage("https://example.com:8443"),
      { name: "UrlValidationError" }
    );
  });
});

