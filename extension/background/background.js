/**
 * PhishGuard Background Service Worker
 * Handles URL interception, API communication, and blocking
 */

"use strict";

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
  API_ENDPOINT: "http://127.0.0.1:5000/api/analyze",
  API_TIMEOUT: 2000, // 2 seconds for fast URL check, fall back quickly if offline
  CACHE_TTL: 300000, // 5 minutes
  MAX_RETRIES: 1,
  BLOCK_THRESHOLD: 50, // Block URLs with risk >= 50
  WARN_THRESHOLD: 30, // Warn for URLs with risk >= 30
};

// ============================================================================
// State Management
// ============================================================================

const state = {
  analysisCache: new Map(),
  pendingRequests: new Map(),
  bypassedUrls: new Set(), // URLs user chose to proceed to
  settings: {
    enabled: true,
    apiEndpoint: CONFIG.API_ENDPOINT,
  },
};

// ============================================================================
// Initialization
// ============================================================================

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("[PhishGuard] Extension installed:", details.reason);
  if (details.reason === "install") {
    await initializeSettings();
  }
});

async function initializeSettings() {
  await chrome.storage.local.set({
    enabled: true,
    apiEndpoint: CONFIG.API_ENDPOINT,
    totalScans: 0,
    threatsBlocked: 0,
  });
  console.log("[PhishGuard] Settings initialized");
}

// ============================================================================
// Navigation Interception - BEFORE page loads
// ============================================================================

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept main frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;
  console.log("[PhishGuard] Intercepting navigation:", url);

  // Skip internal pages
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://")
  ) {
    return;
  }

  // Check if user bypassed this URL
  if (state.bypassedUrls.has(url)) {
    console.log("[PhishGuard] URL was bypassed by user, allowing");
    return;
  }

  // Check cache first
  const cached = getCachedAnalysis(url);
  if (cached && cached.riskScore < CONFIG.BLOCK_THRESHOLD) {
    console.log("[PhishGuard] Cached safe URL, allowing");
    return;
  }

  // Analyze URL before allowing
  try {
    const result = await analyzeUrlQuick(url);

    // Cache the result
    cacheAnalysis(url, result);
    state.analysisCache.set(details.tabId, result);

    // Update stats
    await updateScanStats(result.riskScore >= CONFIG.BLOCK_THRESHOLD);

    // Block if high risk
    if (result.riskScore >= CONFIG.BLOCK_THRESHOLD) {
      console.log("[PhishGuard] HIGH RISK URL DETECTED:", result.riskScore);

      // Redirect to warning page
      const warningUrl = buildWarningUrl(url, result);

      chrome.tabs.update(details.tabId, { url: warningUrl });
    }
  } catch (error) {
    console.error("[PhishGuard] Analysis error:", error.message);
    // On error, allow navigation but log it
  }
});

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  state.analysisCache.delete(tabId);
  state.pendingRequests.delete(tabId);
});

// ============================================================================
// Quick URL Analysis (Fast, URL-only)
// ============================================================================

async function analyzeUrlQuick(url) {
  // Check cache first
  const cached = getCachedAnalysis(url);
  if (cached) {
    console.log("[PhishGuard] Returning cached analysis for:", url);
    return cached;
  }

  console.log("[PhishGuard] Quick URL analysis:", url);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.API_TIMEOUT);

    const response = await fetch(CONFIG.API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        url: url,
        text: "",
        dom: {},
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    const result = await response.json();
    console.log("[PhishGuard] API result:", result);

    return {
      url,
      timestamp: Date.now(),
      riskScore: result.url_risk ?? result.final_score ?? 0,
      riskLevel: result.risk_level ?? getRiskLevel(result.url_risk ?? 0),
      isPhishing: result.is_phishing ?? false,
      confidence: result.confidence ?? 0.75,
      features: result.features ?? {},
      explanations: result.explanations ?? [],
      explanation: result.explanations?.[0]?.message ?? "Analysis complete",
      urlRisk: result.url_risk ?? 0,
      nlpRisk: result.nlp_risk ?? 0,
      domRisk: result.dom_risk ?? 0,
      finalScore: result.final_score ?? 0,
      apiResponse: true,
    };
  } catch (error) {
    console.error("[PhishGuard] API failed, using fallback:", error.message);
    return fallbackUrlAnalysis(url);
  }
}

function fallbackUrlAnalysis(url) {
  const riskScore = calculateUrlRisk(url);
  return {
    url,
    timestamp: Date.now(),
    riskScore,
    riskLevel: getRiskLevel(riskScore),
    isPhishing: riskScore > 70,
    confidence: 0.5,
    features: extractUrlFeatures(url),
    explanations: [],
    explanation: "Heuristic analysis (API unavailable)",
    urlRisk: riskScore,
    nlpRisk: 0,
    domRisk: 0,
    finalScore: riskScore,
    apiResponse: false,
  };
}

function calculateUrlRisk(url) {
  let score = 0;

  try {
    const urlObj = new URL(url);

    // Suspicious TLDs
    const suspiciousTlds = [
      ".tk",
      ".ml",
      ".ga",
      ".cf",
      ".gq",
      ".xyz",
      ".top",
      ".work",
      ".click",
    ];
    if (suspiciousTlds.some((tld) => urlObj.hostname.endsWith(tld)))
      score += 50;

    if (urlObj.protocol !== "https:") score += 20;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(urlObj.hostname))
      score += 40;
    if (urlObj.hostname.includes("-")) score += 5;
    if (urlObj.hostname.split(".").length > 4) score += 15;
    if (urlObj.hostname.length > 30) score += 10;
    if (/login|signin|account|verify|secure/i.test(urlObj.pathname))
      score += 10;
    if (url.includes("@")) score += 40;
  } catch {
    score = 40;
  }

  return Math.min(score, 100);
}

function extractUrlFeatures(url) {
  try {
    const urlObj = new URL(url);
    return {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      hasSubdomain: urlObj.hostname.split(".").length > 2,
      hostnameLength: urlObj.hostname.length,
      pathDepth: urlObj.pathname.split("/").filter(Boolean).length,
      hasQueryParams: urlObj.search.length > 0,
      riskFactors: [],
      safeFactors: urlObj.protocol === "https:" ? ["secure_connection"] : [],
    };
  } catch {
    return { error: "Invalid URL" };
  }
}

// ============================================================================
// Warning Page URL Builder
// ============================================================================

function buildWarningUrl(targetUrl, analysis) {
  const warningPage = chrome.runtime.getURL("warning/warning.html");

  // Build reasons string
  const reasons = [];
  if (analysis.explanations && analysis.explanations.length > 0) {
    analysis.explanations.forEach((exp) => {
      if (exp.type === "danger" || exp.type === "warning") {
        reasons.push(exp.message);
      }
    });
  }
  if (analysis.features?.riskFactors?.length > 0) {
    analysis.features.riskFactors.forEach((factor) => {
      reasons.push(
        factor.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase()),
      );
    });
  }

  const params = new URLSearchParams({
    url: targetUrl,
    score: analysis.riskScore.toString(),
    level: analysis.riskLevel,
    reasons: reasons.slice(0, 5).join("|"),
  });

  return `${warningPage}?${params.toString()}`;
}

// ============================================================================
// Message Handling
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("[PhishGuard] Message received:", message.type);

  handleMessage(message, sender)
    .then(sendResponse)
    .catch((error) => {
      console.error("[PhishGuard] Message error:", error);
      sendResponse({ error: error.message });
    });

  return true; // Keep channel open for async
});

async function handleMessage(message, sender) {
  switch (message.type) {
    case "BYPASS_WARNING":
      return handleBypassWarning(message.url);

    case "CHECK_BYPASS":
      return { bypassed: state.bypassedUrls.has(message.url) };

    case "ANALYZE_PAGE_DATA":
      return await handleAnalyzePageData(message.data, sender.tab?.id);

    case "GET_CURRENT_ANALYSIS":
      return handleGetCurrentAnalysis(sender.tab?.id);

    case "ANALYZE_URL":
      return await analyzeUrlQuick(message.url);

    case "GET_STATS":
      return await getStats();

    case "GET_SETTINGS":
      return await getSettings();

    case "UPDATE_SETTINGS":
      return await updateSettings(message.settings);

    default:
      return { error: "Unknown message type" };
  }
}

function handleBypassWarning(url) {
  console.log("[PhishGuard] User bypassing warning for:", url);
  state.bypassedUrls.add(url);

  // Clear bypass after 30 minutes
  setTimeout(
    () => {
      state.bypassedUrls.delete(url);
    },
    30 * 60 * 1000,
  );

  return { success: true };
}

// ============================================================================
// Full Page Analysis (After page loads, includes NLP)
// ============================================================================

async function handleAnalyzePageData(pageData, tabId) {
  if (!pageData || !pageData.url) {
    return { error: "Invalid page data" };
  }

  const urlString =
    typeof pageData.url === "object" ? pageData.url.full : pageData.url;

  // Skip internal pages
  if (
    urlString.startsWith("chrome://") ||
    urlString.startsWith("chrome-extension://")
  ) {
    return createSafeResult(urlString, "System page");
  }

  try {
    console.log("[PhishGuard] Full page analysis with NLP:", urlString);

    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      CONFIG.API_TIMEOUT * 2,
    );

    const response = await fetch(CONFIG.API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        url: urlString,
        text: pageData.visibleText || "",
        dom: pageData.domFingerprint || {},
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    const result = await response.json();

    const analysis = {
      url: urlString,
      timestamp: Date.now(),
      riskScore: result.url_risk ?? result.final_score ?? 0,
      riskLevel: result.risk_level ?? "unknown",
      isPhishing: result.is_phishing ?? false,
      confidence: result.confidence ?? 0.75,
      features: result.features ?? {},
      explanations: result.explanations ?? [],
      explanation: result.explanations?.[0]?.message ?? "Analysis complete",
      urlRisk: result.url_risk ?? 0,
      nlpRisk: result.nlp_risk ?? 0,
      domRisk: result.dom_risk ?? 0,
      finalScore: result.final_score ?? 0,
      apiResponse: true,
    };

    // Cache and store
    cacheAnalysis(urlString, analysis);
    if (tabId) {
      state.analysisCache.set(tabId, analysis);
    }

    // Notify content script
    if (tabId) {
      try {
        await chrome.tabs.sendMessage(tabId, {
          type: "ANALYSIS_RESULT",
          data: analysis,
        });
      } catch (e) {
        console.log("[PhishGuard] Could not notify content script");
      }
    }

    return analysis;
  } catch (error) {
    console.error("[PhishGuard] Full analysis failed:", error.message);
    return fallbackUrlAnalysis(urlString);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function createSafeResult(url, reason) {
  return {
    url,
    timestamp: Date.now(),
    riskScore: 0,
    riskLevel: "safe",
    isPhishing: false,
    confidence: 1.0,
    features: {},
    explanations: [],
    explanation: reason,
    urlRisk: 0,
    nlpRisk: 0,
    domRisk: 0,
    finalScore: 0,
  };
}

function getRiskLevel(score) {
  if (score < 20) return "safe";
  if (score < 40) return "low";
  if (score < 60) return "medium";
  if (score < 80) return "high";
  return "critical";
}

function handleGetCurrentAnalysis(tabId) {
  if (!tabId) return { error: "No tab ID" };
  return state.analysisCache.get(tabId) || { error: "No analysis available" };
}

// ============================================================================
// Caching
// ============================================================================

const urlCache = new Map();

function getCachedAnalysis(url) {
  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_TTL) {
    return cached.data;
  }
  urlCache.delete(url);
  return null;
}

function cacheAnalysis(url, data) {
  urlCache.set(url, { data, timestamp: Date.now() });

  // Clean old entries
  if (urlCache.size > 100) {
    const oldest = [...urlCache.entries()]
      .sort((a, b) => a[1].timestamp - b[1].timestamp)
      .slice(0, 20);
    oldest.forEach(([k]) => urlCache.delete(k));
  }
}

// ============================================================================
// Statistics
// ============================================================================

async function updateScanStats(isBlocked) {
  const data = await chrome.storage.local.get(["totalScans", "threatsBlocked"]);
  await chrome.storage.local.set({
    totalScans: (data.totalScans || 0) + 1,
    threatsBlocked: (data.threatsBlocked || 0) + (isBlocked ? 1 : 0),
  });
}

async function getStats() {
  const data = await chrome.storage.local.get(["totalScans", "threatsBlocked"]);
  return {
    totalScans: data.totalScans || 0,
    threatsBlocked: data.threatsBlocked || 0,
    cacheSize: state.analysisCache.size,
    bypassedCount: state.bypassedUrls.size,
  };
}

async function getSettings() {
  const data = await chrome.storage.local.get(["enabled", "apiEndpoint"]);
  return {
    enabled: data.enabled ?? true,
    apiEndpoint: data.apiEndpoint ?? CONFIG.API_ENDPOINT,
  };
}

async function updateSettings(newSettings) {
  await chrome.storage.local.set(newSettings);
  if (newSettings.apiEndpoint) {
    CONFIG.API_ENDPOINT = newSettings.apiEndpoint;
  }
  return { success: true };
}
