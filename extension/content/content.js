/**
 * PhishGuard Content Script
 * Blocks page and shows warning overlay for risky URLs
 */

"use strict";

// ============================================================================
// Configuration
// ============================================================================

const BLOCK_THRESHOLD = 50; // Block URLs with risk >= 50

// ============================================================================
// Wait for document to be ready
// ============================================================================

function onDocumentReady(callback) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", callback);
  } else {
    callback();
  }
}

// ============================================================================
// Main Entry Point
// ============================================================================

onDocumentReady(async () => {
  // Skip internal pages
  if (
    window.location.protocol === "chrome:" ||
    window.location.protocol === "chrome-extension:" ||
    window.location.protocol === "about:"
  ) {
    return;
  }

  console.log("[PhishGuard] Content script loaded:", window.location.href);

  // Check if this URL was already bypassed
  try {
    const bypassResult = await chrome.runtime.sendMessage({
      type: "CHECK_BYPASS",
      url: window.location.href,
    });

    if (bypassResult && bypassResult.bypassed) {
      console.log("[PhishGuard] URL was bypassed, allowing");
      return;
    }
  } catch (e) {
    console.log("[PhishGuard] Could not check bypass status");
  }

  // Show blocking overlay immediately
  showBlockingOverlay();

  // Request URL analysis
  try {
    const analysis = await chrome.runtime.sendMessage({
      type: "ANALYZE_URL",
      url: window.location.href,
    });

    console.log("[PhishGuard] Analysis result:", analysis);

    if (analysis && analysis.riskScore >= BLOCK_THRESHOLD) {
      // High risk - show warning
      showWarningOverlay(analysis);
    } else {
      // Safe - remove overlay and show safe badge
      removeOverlay();
      showSafeBadge();

      // Continue with full page analysis after page loads
      if (document.readyState === "complete") {
        performFullAnalysis();
      } else {
        window.addEventListener("load", performFullAnalysis, { once: true });
      }
    }
  } catch (error) {
    console.error("[PhishGuard] Analysis error:", error);
    removeOverlay(); // On error, allow access
  }
});

// ============================================================================
// Blocking Overlay (shown while checking)
// ============================================================================

function showBlockingOverlay() {
  if (document.getElementById("phishguard-overlay")) return;

  const overlay = document.createElement("div");
  overlay.id = "phishguard-overlay";

  // Apply styles directly
  Object.assign(overlay.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    height: "100%",
    background: "rgba(15, 15, 26, 0.98)",
    zIndex: "2147483647",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  });

  overlay.innerHTML = `
    <div style="text-align: center; color: #fff;">
      <div style="width: 50px; height: 50px; border: 4px solid rgba(0, 217, 255, 0.2); border-top-color: #00d9ff; border-radius: 50%; animation: phishguard-spin 1s linear infinite; margin: 0 auto 20px;"></div>
      <h2 style="font-size: 24px; margin-bottom: 10px;">🛡️ PhishGuard</h2>
      <p style="color: #8892b0; font-size: 14px;">Checking site safety...</p>
    </div>
    <style>
      @keyframes phishguard-spin {
        to { transform: rotate(360deg); }
      }
    </style>
  `;

  // Append to body or documentElement
  const target = document.body || document.documentElement;
  target.appendChild(overlay);
}

// ============================================================================
// Warning Overlay (shown for risky sites)
// ============================================================================

function showWarningOverlay(analysis) {
  let overlay = document.getElementById("phishguard-overlay");

  // Create overlay if it doesn't exist
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "phishguard-overlay";
    const target = document.body || document.documentElement;
    target.appendChild(overlay);
  }

  const riskLevel = analysis.riskLevel || "high";
  const riskScore = analysis.riskScore || 0;
  const explanations = analysis.explanations || [];

  // Build reasons list
  let reasonsHtml = "";
  if (explanations.length > 0) {
    explanations.forEach((exp) => {
      if (exp.type === "danger" || exp.type === "warning") {
        reasonsHtml += `<div style="padding: 10px; background: rgba(255, 255, 255, 0.05); border-radius: 8px; margin-bottom: 8px; font-size: 13px; color: #ffab00;">⚠️ ${exp.message}</div>`;
      }
    });
  }
  if (!reasonsHtml) {
    reasonsHtml =
      '<div style="padding: 10px; background: rgba(255, 255, 255, 0.05); border-radius: 8px; margin-bottom: 8px; font-size: 13px; color: #ffab00;">⚠️ High-risk URL detected by ML analysis</div>';
  }

  // Apply container styles
  Object.assign(overlay.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    height: "100%",
    background:
      "linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f0f23 100%)",
    zIndex: "2147483647",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  });

  overlay.innerHTML = `
    <div style="max-width: 500px; width: 90%; text-align: center; color: #fff; padding: 40px; background: rgba(255, 255, 255, 0.05); border-radius: 20px; border: 1px solid rgba(255, 107, 107, 0.3);">
      <div style="font-size: 60px; margin-bottom: 20px;">🛡️</div>
      <h1 style="font-size: 24px; color: #ff6b6b; margin-bottom: 10px;">Potential Phishing Site Detected</h1>
      <p style="color: #a0a0a0; margin-bottom: 20px; font-size: 14px;">PhishGuard has identified security concerns with this website</p>
      
      <div style="background: rgba(255, 107, 107, 0.1); border: 1px solid rgba(255, 107, 107, 0.3); border-radius: 12px; padding: 20px; margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between;">
        <div>
          <div style="font-size: 42px; font-weight: bold; color: #ff6b6b;">${riskScore}</div>
          <div style="font-size: 12px; color: #a0a0a0;">Risk Score</div>
        </div>
        <span style="padding: 8px 16px; border-radius: 20px; font-weight: bold; text-transform: uppercase; font-size: 12px; background: #ff1744; color: #fff;">${riskLevel.toUpperCase()}</span>
      </div>
      
      <div style="background: rgba(0, 0, 0, 0.3); border-radius: 8px; padding: 12px; font-family: monospace; font-size: 12px; word-break: break-all; color: #ff9800; margin-bottom: 20px;">${window.location.href}</div>
      
      <div style="text-align: left; margin-bottom: 25px;">
        <h3 style="font-size: 12px; color: #a0a0a0; margin-bottom: 10px; text-transform: uppercase;">⚠️ Detected Issues</h3>
        ${reasonsHtml}
      </div>
      
      <div style="display: flex; gap: 15px; justify-content: center;">
        <button id="phishguard-back-btn" style="padding: 14px 28px; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; background: linear-gradient(135deg, #00c853, #00e676); color: #000;">← Go Back to Safety</button>
        <button id="phishguard-proceed-btn" style="padding: 14px 28px; border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; background: rgba(255, 255, 255, 0.1); color: #a0a0a0;">Proceed Anyway</button>
      </div>
      
      <p style="margin-top: 20px; font-size: 11px; color: #666;">Protected by PhishGuard</p>
    </div>
  `;

  // Attach event listeners using setTimeout to ensure DOM is ready
  setTimeout(() => {
    const backBtn = document.getElementById("phishguard-back-btn");
    const proceedBtn = document.getElementById("phishguard-proceed-btn");

    if (backBtn) {
      backBtn.onclick = function () {
        console.log("[PhishGuard] Back button clicked");
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.location.href = "https://www.google.com";
        }
      };
    }

    if (proceedBtn) {
      proceedBtn.onclick = async function () {
        console.log("[PhishGuard] Proceed button clicked");
        try {
          await chrome.runtime.sendMessage({
            type: "BYPASS_WARNING",
            url: window.location.href,
          });
        } catch (e) {
          console.log("[PhishGuard] Could not send bypass message");
        }
        removeOverlay();
      };
    }
  }, 50);
}

// ============================================================================
// Remove Overlay
// ============================================================================

function removeOverlay() {
  const overlay = document.getElementById("phishguard-overlay");
  if (overlay) {
    overlay.style.transition = "opacity 0.3s ease";
    overlay.style.opacity = "0";
    setTimeout(() => overlay.remove(), 300);
  }
}

// ============================================================================
// Full Page Analysis (after page loads)
// ============================================================================

async function performFullAnalysis() {
  // Extract page data
  const pageData = extractPageData();

  // Send for NLP analysis
  try {
    const result = await chrome.runtime.sendMessage({
      type: "ANALYZE_PAGE_DATA",
      data: pageData,
    });

    console.log("[PhishGuard] Full analysis result:", result);

    // If NLP analysis reveals high risk, show indicator
    if (result && result.nlpRisk > 30) {
      showRiskIndicator(result);
    }
  } catch (error) {
    console.error("[PhishGuard] Full analysis error:", error);
  }
}

function extractPageData() {
  return {
    url: window.location.href,
    visibleText: document.body?.innerText?.substring(0, 10000) || "",
    domFingerprint: {
      stats: {
        forms: document.querySelectorAll("form").length,
        inputs: document.querySelectorAll("input").length,
        links: document.querySelectorAll("a").length,
        scripts: document.querySelectorAll("script").length,
        iframes: document.querySelectorAll("iframe").length,
      },
    },
  };
}

function showRiskIndicator(analysis) {
  if (document.getElementById("phishguard-indicator")) return;

  const indicator = document.createElement("div");
  indicator.id = "phishguard-indicator";

  Object.assign(indicator.style, {
    position: "fixed",
    top: "10px",
    right: "10px",
    padding: "10px 15px",
    background: "rgba(255, 171, 0, 0.9)",
    color: "#000",
    borderRadius: "8px",
    fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
    fontSize: "12px",
    fontWeight: "600",
    zIndex: "2147483646",
    boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
    cursor: "pointer",
  });

  indicator.textContent = "⚠️ PhishGuard: Suspicious content detected";

  indicator.onclick = () => indicator.remove();

  document.body.appendChild(indicator);

  // Auto-hide after 10 seconds
  setTimeout(() => {
    if (indicator.parentNode) indicator.remove();
  }, 10000);
}

// ============================================================================
// Safe Badge (shown for safe sites)
// ============================================================================

function showSafeBadge() {
  if (document.getElementById("phishguard-safe-badge")) return;

  const badge = document.createElement("div");
  badge.id = "phishguard-safe-badge";

  Object.assign(badge.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    padding: "10px 16px",
    background: "linear-gradient(135deg, #00c853 0%, #00e676 100%)",
    color: "#000",
    borderRadius: "10px",
    fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
    fontSize: "13px",
    fontWeight: "600",
    zIndex: "2147483646",
    boxShadow: "0 4px 15px rgba(0, 200, 83, 0.4)",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    gap: "8px",
    transition: "transform 0.2s, opacity 0.3s",
  });

  badge.innerHTML = `
    <span style="font-size: 16px;">🛡️</span>
    <span>PhishGuard: <strong>Safe</strong></span>
  `;

  badge.onmouseenter = () => {
    badge.style.transform = "translateY(-2px)";
  };

  badge.onmouseleave = () => {
    badge.style.transform = "translateY(0)";
  };

  badge.onclick = () => {
    badge.style.opacity = "0";
    setTimeout(() => badge.remove(), 300);
  };

  document.body.appendChild(badge);

  // Auto-hide after 5 seconds
  setTimeout(() => {
    if (badge.parentNode) {
      badge.style.opacity = "0";
      setTimeout(() => badge.remove(), 300);
    }
  }, 5000);
}

// ============================================================================
// Listen for messages from background
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYSIS_RESULT") {
    console.log("[PhishGuard] Received analysis result:", message.data);

    // Highlight suspicious phrases if found
    if (message.data && message.data.suspicious_phrases) {
      highlightSuspiciousPhrases(message.data.suspicious_phrases);
    }
  }
  return true;
});

// ============================================================================
// Real-Time Text Highlighting
// ============================================================================

// Suspicious phrases to detect (local detection for speed)
const SUSPICIOUS_PHRASES = [
  // Urgency
  "act now",
  "urgent",
  "immediately",
  "expire",
  "limited time",
  "within 24 hours",
  "within 48 hours",
  "last chance",
  "final warning",
  "action required",
  "respond immediately",
  // Verification/Security
  "verify your account",
  "confirm your identity",
  "update your information",
  "security alert",
  "unusual activity",
  "suspicious activity",
  "unauthorized access",
  "account suspended",
  "account locked",
  // Credentials
  "enter your password",
  "confirm your password",
  "verify your email",
  "one time password",
  "verification code",
  "security code",
  // Click actions
  "click here",
  "click now",
  "click below",
  "click the link",
  "log in now",
  "sign in now",
  // Prizes/Money
  "you have won",
  "congratulations",
  "claim your prize",
  "lottery",
  "free gift",
  "cash prize",
  // Threats
  "legal action",
  "your account will be",
  "failure to",
];

// Form-related keywords
const FORM_KEYWORDS = [
  "password",
  "ssn",
  "social security",
  "credit card",
  "card number",
  "cvv",
  "pin",
  "bank account",
  "routing number",
  "otp",
];

let highlightingEnabled = true;
let highlightedElements = [];

/**
 * Scan and highlight suspicious text on the page
 */
function scanAndHighlightPage() {
  if (!highlightingEnabled) return;

  console.log("[PhishGuard] Scanning page for suspicious text...");

  // Inject highlight styles
  injectHighlightStyles();

  // Get all text nodes
  const textNodes = getTextNodes(document.body);
  let highlightCount = 0;

  textNodes.forEach((node) => {
    const text = node.textContent.toLowerCase();

    // Check for suspicious phrases
    SUSPICIOUS_PHRASES.forEach((phrase) => {
      if (text.includes(phrase)) {
        highlightTextInNode(
          node,
          phrase,
          "warning",
          `⚠️ Suspicious phrase: "${phrase}"`,
        );
        highlightCount++;
      }
    });

    // Check for form keywords (more severe)
    FORM_KEYWORDS.forEach((keyword) => {
      if (text.includes(keyword)) {
        highlightTextInNode(
          node,
          keyword,
          "danger",
          `🔒 Sensitive info request: "${keyword}"`,
        );
        highlightCount++;
      }
    });
  });

  if (highlightCount > 0) {
    console.log(
      `[PhishGuard] Highlighted ${highlightCount} suspicious text areas`,
    );
    showHighlightSummary(highlightCount);
  }
}

/**
 * Get all text nodes in an element
 */
function getTextNodes(element) {
  const nodes = [];
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, {
    acceptNode: function (node) {
      // Skip script, style, and already processed nodes
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;

      const tagName = parent.tagName.toLowerCase();
      if (["script", "style", "noscript", "iframe"].includes(tagName)) {
        return NodeFilter.FILTER_REJECT;
      }

      // Skip already highlighted
      if (parent.classList.contains("phishguard-highlight")) {
        return NodeFilter.FILTER_REJECT;
      }

      // Only accept non-empty text
      if (node.textContent.trim().length > 3) {
        return NodeFilter.FILTER_ACCEPT;
      }

      return NodeFilter.FILTER_REJECT;
    },
  });

  let node;
  while ((node = walker.nextNode())) {
    nodes.push(node);
  }

  return nodes;
}

/**
 * Highlight specific text within a text node
 */
function highlightTextInNode(textNode, phrase, severity, tooltip) {
  const text = textNode.textContent;
  const lowerText = text.toLowerCase();
  const index = lowerText.indexOf(phrase.toLowerCase());

  if (index === -1) return;

  // Don't highlight if already in a highlight span
  if (textNode.parentElement?.classList.contains("phishguard-highlight"))
    return;

  try {
    const before = text.substring(0, index);
    const match = text.substring(index, index + phrase.length);
    const after = text.substring(index + phrase.length);

    const span = document.createElement("span");
    span.className = `phishguard-highlight phishguard-${severity}`;
    span.textContent = match;
    span.setAttribute("data-phishguard-tooltip", tooltip);

    const fragment = document.createDocumentFragment();
    if (before) fragment.appendChild(document.createTextNode(before));
    fragment.appendChild(span);
    if (after) fragment.appendChild(document.createTextNode(after));

    textNode.parentNode.replaceChild(fragment, textNode);
    highlightedElements.push(span);
  } catch (e) {
    // Ignore DOM manipulation errors
  }
}

/**
 * Highlight phrases from API response
 */
function highlightSuspiciousPhrases(phrases) {
  if (!phrases || phrases.length === 0) return;

  console.log("[PhishGuard] Highlighting phrases from API:", phrases);
  injectHighlightStyles();

  const textNodes = getTextNodes(document.body);

  textNodes.forEach((node) => {
    const text = node.textContent.toLowerCase();

    phrases.forEach((phrase) => {
      if (text.includes(phrase.toLowerCase())) {
        highlightTextInNode(
          node,
          phrase,
          "warning",
          `⚠️ Detected: "${phrase}"`,
        );
      }
    });
  });
}

/**
 * Inject CSS for highlights
 */
function injectHighlightStyles() {
  if (document.getElementById("phishguard-highlight-styles")) return;

  const style = document.createElement("style");
  style.id = "phishguard-highlight-styles";
  style.textContent = `
    .phishguard-highlight {
      position: relative;
      cursor: help;
    }

    .phishguard-warning {
      background: linear-gradient(to bottom, rgba(255, 193, 7, 0.3) 0%, rgba(255, 193, 7, 0.3) 100%);
      border-bottom: 2px wavy #ffc107;
      padding: 1px 2px;
      border-radius: 2px;
    }

    .phishguard-danger {
      background: linear-gradient(to bottom, rgba(244, 67, 54, 0.3) 0%, rgba(244, 67, 54, 0.3) 100%);
      border-bottom: 2px wavy #f44336;
      padding: 1px 2px;
      border-radius: 2px;
    }

    .phishguard-highlight::after {
      content: attr(data-phishguard-tooltip);
      position: absolute;
      bottom: 100%;
      left: 50%;
      transform: translateX(-50%);
      background: #1a1a2e;
      color: #fff;
      padding: 6px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      white-space: nowrap;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.2s, visibility 0.2s;
      z-index: 2147483647;
      pointer-events: none;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }

    .phishguard-highlight:hover::after {
      opacity: 1;
      visibility: visible;
    }

    #phishguard-highlight-summary {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: #fff;
      padding: 12px 16px;
      border-radius: 10px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 13px;
      z-index: 2147483646;
      box-shadow: 0 8px 24px rgba(0,0,0,0.4);
      border: 1px solid rgba(255, 193, 7, 0.3);
      display: flex;
      align-items: center;
      gap: 10px;
      cursor: pointer;
      transition: transform 0.2s;
    }

    #phishguard-highlight-summary:hover {
      transform: translateY(-2px);
    }

    .phishguard-summary-icon {
      font-size: 20px;
    }

    .phishguard-summary-text strong {
      color: #ffc107;
    }
  `;

  document.head.appendChild(style);
}

/**
 * Show floating summary of highlighted items
 */
function showHighlightSummary(count) {
  if (document.getElementById("phishguard-highlight-summary")) return;

  const summary = document.createElement("div");
  summary.id = "phishguard-highlight-summary";
  summary.innerHTML = `
    <span class="phishguard-summary-icon">🛡️</span>
    <span class="phishguard-summary-text">
      <strong>${count}</strong> suspicious text areas highlighted
    </span>
  `;

  summary.onclick = () => {
    // Toggle highlighting
    toggleHighlights();
  };

  document.body.appendChild(summary);

  // Auto-hide after 15 seconds
  setTimeout(() => {
    if (summary.parentNode) {
      summary.style.transition = "opacity 0.3s";
      summary.style.opacity = "0";
      setTimeout(() => summary.remove(), 300);
    }
  }, 15000);
}

/**
 * Toggle highlight visibility
 */
function toggleHighlights() {
  highlightingEnabled = !highlightingEnabled;

  highlightedElements.forEach((el) => {
    if (highlightingEnabled) {
      el.classList.add("phishguard-highlight");
    } else {
      el.classList.remove("phishguard-highlight");
    }
  });

  const summary = document.getElementById("phishguard-highlight-summary");
  if (summary) {
    summary.querySelector(".phishguard-summary-text").innerHTML =
      highlightingEnabled
        ? `<strong>${highlightedElements.length}</strong> suspicious text areas highlighted`
        : "Highlights hidden - click to show";
  }
}

// ============================================================================
// Run highlighting after page loads
// ============================================================================

// Check NLP setting from storage and run highlighting
async function initializeHighlighting() {
  try {
    const settings = await chrome.storage.local.get(["nlpHighlightingEnabled"]);
    highlightingEnabled = settings.nlpHighlightingEnabled !== false; // Default to true
  } catch (e) {
    highlightingEnabled = true;
  }

  if (highlightingEnabled && document.body) {
    console.log("[PhishGuard] Starting page scan for suspicious text...");
    scanAndHighlightPage();
    setupMutationObserver();
  }
}

function setupMutationObserver() {
  if (!document.body) return;

  // Watch for dynamic content
  const observer = new MutationObserver((mutations) => {
    if (!highlightingEnabled) return;

    // Debounce - only scan if significant changes
    let hasNewContent = mutations.some(
      (m) =>
        m.addedNodes.length > 0 &&
        Array.from(m.addedNodes).some(
          (n) => n.nodeType === 1 && n.textContent?.length > 50,
        ),
    );

    if (hasNewContent) {
      clearTimeout(window.phishguardScanTimeout);
      window.phishguardScanTimeout = setTimeout(scanAndHighlightPage, 2000);
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

// Wait for page to fully load, then scan
if (document.readyState === "complete") {
  setTimeout(initializeHighlighting, 500);
} else {
  window.addEventListener("load", () => {
    setTimeout(initializeHighlighting, 500);
  });
}

// Listen for toggle messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "TOGGLE_NLP_HIGHLIGHTING") {
    highlightingEnabled = message.enabled;

    if (highlightingEnabled) {
      // Re-scan page
      scanAndHighlightPage();
    } else {
      // Remove all highlights
      highlightedElements.forEach((el) => {
        el.classList.remove(
          "phishguard-highlight",
          "phishguard-warning",
          "phishguard-danger",
        );
      });
      const summary = document.getElementById("phishguard-highlight-summary");
      if (summary) summary.remove();
    }

    sendResponse({ success: true, enabled: highlightingEnabled });
  }
  return true;
});
