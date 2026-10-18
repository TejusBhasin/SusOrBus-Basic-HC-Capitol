"use strict";

const { validateKnowledgeBase, metadata, messages, verdicts, scoring, domains, phishing, policyLexicon, findings, rules } = require("./validator");
const { renderTemplate, escapeHtml } = require("./renderer");

module.exports = {
  metadata,
  messages,
  verdicts,
  scoring,
  domains,
  phishing,
  policyLexicon,
  findings,
  rules,
  renderTemplate,
  escapeHtml,
  validateKnowledgeBase
};

