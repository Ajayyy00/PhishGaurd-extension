/* Risk-level boundaries match backend/services/risk.py. Online blocking is
 * authoritative in the API's should_block; shouldBlock below is offline-only. */
"use strict";
globalThis.PhishGuardRisk = Object.freeze({
  version: "evidence-v2",
  validScore: (score) => typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 100,
  level(score, degraded = false) {
    if (!this.validScore(score) || (degraded && score <= 30)) return "unknown";
    return score <= 30 ? "safe" : score <= 70 ? "suspicious" : "dangerous";
  },
  shouldBlock(urlScore, score) { return urlScore >= 50 || score > 70; },
  httpUrl(value) {
    if (typeof value !== "string" || value.length > 2048 || /[\s\x00-\x1f\x7f\\]/.test(value)) return null;
    try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.href : null; } catch { return null; }
  },
  escapeHtml(value) { return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); },
});
