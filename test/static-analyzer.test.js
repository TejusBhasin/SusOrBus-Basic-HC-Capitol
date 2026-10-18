"use strict";

const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { analyzeStaticDocument, parseHtmlElements, extractVisibleText } = require("../sus-or-bus/lib/static-analyzer");

describe("Layer C: Static Document Analysis", () => {
  test("extracts visible plain text while stripping scripts, styles, and tags", () => {
    const html = `
      <html>
        <head><title>Test Page</title><style>body { color: red; }</style></head>
        <body>
          <script>console.log("secret");</script>
          <!-- comment -->
          <h1>Hello World &amp; Welcome</h1>
          <p>This is a safe <b>text</b> snippet.</p>
        </body>
      </html>
    `;
    const text = extractVisibleText(html);
    assert.equal(text.includes("secret"), false);
    assert.equal(text.includes("color: red"), false);
    assert.equal(text.includes("comment"), false);
    assert.equal(text.includes("Hello World & Welcome"), true);
    assert.equal(text.includes("This is a safe text snippet."), true);
  });

  test("detects password input submitted cross-origin as critical finding", () => {
    const html = `
      <html>
        <body>
          <form action="https://phishing-catcher.com/collect" method="POST">
            <input type="text" name="username">
            <input type="password" name="pwd">
            <button type="submit">Log in</button>
          </form>
        </body>
      </html>
    `;
    const result = analyzeStaticDocument(html, "legitbank.com", "https://legitbank.com/login");
    const finding = result.findings.find(f => f.id === "SEC_FORM_PASSWORD_CROSS_ORIGIN" || f.legacyId === "form-password-insecure-destination");
    assert.ok(finding, "Should flag cross-origin password submission");
    assert.equal(finding.severity, "critical");
    assert.equal(finding.level, "bad");
  });

  test("identifies standard login form on same domain with appropriate warning", () => {
    const html = `
      <html>
        <body>
          <form action="/auth/login" method="POST">
            <input type="password" name="password">
          </form>
        </body>
      </html>
    `;
    const result = analyzeStaticDocument(html, "example.com", "https://example.com/login");
    const finding = result.findings.find(f => f.id === "SEC_FORM_PASSWORD_DETECTED" || f.legacyId === "form-password-detected");
    assert.ok(finding, "Should identify password input");
    assert.equal(finding.level, "warning");
    assert.equal(finding.confidence, "high");
  });

  test("confirms no credential fields on informational page", () => {
    const html = `<html><body><article>Just an article without forms</article></body></html>`;
    const result = analyzeStaticDocument(html, "example.com", "https://example.com/");
    const finding = result.findings.find(f => f.id === "SEC_FORM_NO_PASSWORD" || f.legacyId === "form-no-password");
    assert.ok(finding);
    assert.equal(finding.level, "good");
  });

  test("detects meta-refresh automatic redirect", () => {
    const html = `
      <html>
        <head>
          <meta http-equiv="refresh" content="0; url=https://evil.com/phish">
        </head>
      </html>
    `;
    const result = analyzeStaticDocument(html, "example.com", "https://example.com");
    const finding = result.findings.find(f => f.id === "SEC_REDIRECT_META_REFRESH" || f.legacyId === "meta-refresh-redirect");
    assert.ok(finding);
    assert.equal(finding.level, "warning");
  });

  test("detects script dynamic evaluation and unpacker obfuscation", () => {
    const html = `
      <html>
        <head>
          <script>
            eval(unescape("%77%69%6E%64%6F%77%2E%6C%6F%63%61%74%69%6F%6E"));
          </script>
        </head>
      </html>
    `;
    const result = analyzeStaticDocument(html, "example.com", "https://example.com");
    const finding = result.findings.find(f => f.id === "SEC_SCRIPT_OBFUSCATION" || f.legacyId === "scripts-obfuscation-detected");
    assert.ok(finding);
    assert.equal(finding.level, "bad");
  });

  test("detects high-pressure scam language", () => {
    const html = `
      <html>
        <body>
          <h1>CONGRATULATIONS WINNER!</h1>
          <p>You have won a free prize. Click here to claim your bitcoin doubling reward!</p>
        </body>
      </html>
    `;
    const result = analyzeStaticDocument(html, "example.com", "https://example.com");
    const finding = result.findings.find(f => f.id === "SEC_CONTENT_SCAM_KEYWORDS" || f.legacyId === "content-scam-urgency-language");
    assert.ok(finding);
    assert.equal(finding.level, "bad");
  });

  test("identifies third-party iframes", () => {
    const html = `
      <html>
        <body>
          <iframe src="https://external-ad-network.com/widget"></iframe>
        </body>
      </html>
    `;
    const result = analyzeStaticDocument(html, "mysite.com", "https://mysite.com");
    const finding = result.findings.find(f => f.id === "SEC_IFRAME_THIRD_PARTY" || f.legacyId === "iframes-third-party");
    assert.ok(finding);
    assert.equal(finding.level, "warning");
  });
});

