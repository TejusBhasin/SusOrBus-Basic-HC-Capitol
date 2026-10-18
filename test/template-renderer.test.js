"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { renderTemplate, escapeHtml } = require("../sus-or-bus/lib/knowledge");

describe("Deterministic Template Renderer", () => {
  test("replaces placeholders with provided variables", () => {
    const template = "The site contacted {originCount} distinct external origins during the scan.";
    const result = renderTemplate(template, { originCount: 5 }, { originCount: "integer" });
    assert.equal(result, "The site contacted 5 distinct external origins during the scan.");
  });

  test("escapes HTML in variables to prevent untrusted remote injection", () => {
    const template = "Form action '{action}' targets external destination.";
    const maliciousInput = '<script>alert("xss")</script>';
    const result = renderTemplate(template, { action: maliciousInput });
    assert.equal(result.includes("<script>"), false);
    assert.equal(result.includes("&lt;script&gt;"), true);
  });

  test("handles missing variables safely in non-strict mode without crashing", () => {
    const template = "Page title: \"{title}\" on host {host}.";
    const result = renderTemplate(template, { host: "example.com" });
    assert.equal(result, "Page title: \"{title}\" on host example.com.");
  });

  test("throws error on missing variable in strict mode", () => {
    const template = "Hello {name}!";
    assert.throws(
      () => renderTemplate(template, {}, {}, { strict: true }),
      /Missing required placeholder/
    );
  });

  test("enforces integer type validation in strict mode", () => {
    const template = "Total count: {count}";
    assert.throws(
      () => renderTemplate(template, { count: "not-a-number" }, { count: "integer" }, { strict: true }),
      /expected integer/
    );
  });

  test("produces deterministic, identical output across multiple runs", () => {
    const template = "Checked {site} at {time}.";
    const vars = { site: "example.com", time: "2026-10-18T00:00:00Z" };
    const res1 = renderTemplate(template, vars);
    const res2 = renderTemplate(template, vars);
    assert.equal(res1, res2);
  });
});

