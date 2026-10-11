/**
 * PhishGuard Background Service Worker
 * Handles URL interception, API communication, and blocking
 */

"use strict";
importScripts("../shared/risk.js");

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
  API_ENDPOINT: "http://127.0.0.1:5000/api/analyze",
  API_TIMEOUT: 8000,
  CONTENT_TIMEOUT: 25000,
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
  bypassExpiries: {},
  navigation: new Map(),
  settings: {
    enabled: true,
    apiEndpoint: CONFIG.API_ENDPOINT,
  },
};

// IndexedDB belongs to the extension origin. Content scripts use the visited
// page's IndexedDB origin and cannot read this token (including older Chrome).
function tokenStore(operation, value) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('phishguard-pairing', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('credentials');
    request.onerror = () => reject(new Error('Cannot open private pairing store'));
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('credentials', operation === 'put' ? 'readwrite' : 'readonly');
      const store = tx.objectStore('credentials');
      const item = operation === 'put' ? store.put(value, 'apiToken') : store.get('apiToken');
      tx.oncomplete = () => { const result = item.result; db.close(); resolve(result); };
      tx.onerror = tx.onabort = () => { db.close(); reject(new Error('Private pairing store unavailable')); };
    };
  });
}

const ready = (async () => {
  if (chrome.storage.local.setAccessLevel) await chrome.storage.local.setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"});
  const saved = await chrome.storage.local.get(["enabled", "apiEndpoint"]);
  saved.apiToken = await tokenStore('get');
  state.settings = {...state.settings, ...saved};
  if (saved.apiEndpoint && validEndpoint(saved.apiEndpoint)) CONFIG.API_ENDPOINT = saved.apiEndpoint;
  const session = await chrome.storage.session.get(["bypassExpiries"]);
  state.bypassExpiries = session.bypassExpiries || {};
  for (const [url, expiry] of Object.entries(state.bypassExpiries)) {
    if (expiry > Date.now()) state.bypassedUrls.add(url);
  }
})();

function validEndpoint(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) &&
      url.pathname === "/api/analyze" && !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}

function trustedPage(sender) {
  return sender.id === chrome.runtime.id && ["popup/popup.html", "options/options.html", "warning/warning.html"]
    .some(path => sender.url?.split("?")[0] === chrome.runtime.getURL(path));
}

async function requestApi(payload, timeoutMs = CONFIG.API_TIMEOUT, endpoint = CONFIG.API_ENDPOINT) {
  await ready;
  if (!state.settings.apiToken) throw new Error("Pairing required. Open Connection settings.");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: payload ? "POST" : "GET", cache: "no-store", redirect: "error", credentials: "omit",
      headers: {"Content-Type": "application/json", "Authorization": `Bearer ${state.settings.apiToken}`},
      body: payload ? JSON.stringify(payload) : undefined, signal: controller.signal,
    });
    if (!response.ok) throw new Error(`API returned ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timeout); }
}

function normalizeResult(url, result) {
  if (!result || result.url !== url || !PhishGuardRisk.validScore(result.final_score) ||
      !PhishGuardRisk.validScore(result.url_risk) ||
      ![result.nlp_risk, result.dom_risk].every(score => score === null || PhishGuardRisk.validScore(score)) ||
      !result.detectors || typeof result.analysis_stage !== "string" || !Array.isArray(result.explanations)) {
    throw new Error("Malformed analysis response");
  }
  return {url, timestamp: Date.now(), riskScore: result.final_score, finalScore: result.final_score,
    riskLevel: PhishGuardRisk.level(result.final_score, result.degraded),
    isPhishing: result.final_score > 70, shouldBlock: PhishGuardRisk.shouldBlock(result.url_risk, result.final_score),
    confidence: result.confidence, features: result.features || {}, explanations: result.explanations,
    explanation: result.explanation || "Analysis complete", urlRisk: result.url_risk,
    nlpRisk: result.nlp_risk, domRisk: result.dom_risk, analysisStage: result.analysis_stage,
    detectors: result.detectors, degraded: Boolean(result.degraded), errors: result.errors || [],
    suspicious_phrases: result.suspicious_phrases || [], apiResponse: true};
}

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
// Navigation notification and asynchronous warning redirect
// ============================================================================

chrome.webNavigation.onBeforeNavigate.addListener(async details => {
  if (details.frameId !== 0 || !PhishGuardRisk.httpUrl(details.url)) return;
  const url = details.url;
  const navigation = {url, id: crypto.randomUUID()};
  state.navigation.set(details.tabId, navigation);
  state.analysisCache.delete(details.tabId);
  state.pendingRequests.delete(details.tabId);
  try {
    await ready;
    if (!state.settings.enabled || isBypassed(url)) return;
    const result = await analyzeUrlQuick(url);
    if (state.navigation.get(details.tabId) !== navigation || !await tabMatches(details.tabId, url)) return;
    // Do not replace a newer content result with this slower URL-only result.
    if (!state.analysisCache.has(details.tabId)) state.analysisCache.set(details.tabId, result);
    await updateScanStats(result.shouldBlock);
    if (result.shouldBlock && !isBypassed(url) && state.navigation.get(details.tabId) === navigation && await tabMatches(details.tabId, url)) {
      await chrome.tabs.update(details.tabId, {url: buildWarningUrl(url, result)});
    }
  } catch (error) { console.warn("[PhishGuard] Navigation analysis unavailable:", error.message); }
});

async function tabMatches(tabId, url) {
  try {
    const tab = await chrome.tabs.get(tabId);
    return (tab.pendingUrl || tab.url) === url;
  } catch { return false; }
}

chrome.webNavigation.onHistoryStateUpdated.addListener(async details => {
  if (details.frameId !== 0 || !PhishGuardRisk.httpUrl(details.url)) return;
  state.navigation.set(details.tabId, {url: details.url, id: crypto.randomUUID()});
  state.analysisCache.delete(details.tabId);
  state.pendingRequests.delete(details.tabId);
  try { await chrome.tabs.sendMessage(details.tabId, {type: "RESCAN_PAGE", forceRefresh: true}); } catch {}
});

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  state.analysisCache.delete(tabId);
  state.pendingRequests.delete(tabId);
  state.navigation.delete(tabId);
});

// ============================================================================
// Quick URL Analysis (Fast, URL-only)
// ============================================================================

async function analyzeUrlQuick(url, forceRefresh = false) {
  await ready;
  if (!PhishGuardRisk.httpUrl(url)) throw new Error("Unsupported URL");
  const cached = forceRefresh ? null : getCachedAnalysis(url);
  if (cached) return cached;
  try {
    const result = normalizeResult(url, await requestApi({url, text: "", dom: {}, force_refresh: forceRefresh}));
    if (!result.degraded) cacheAnalysis(url, result);
    return result;
  } catch (error) {
    console.warn("[PhishGuard] URL check degraded:", error.message);
    return fallbackUrlAnalysis(url, error.message);
  }
}

function fallbackUrlAnalysis(url, reason = "API unavailable") {
  const riskScore = calculateUrlRisk(url);
  return {
    url,
    timestamp: Date.now(),
    riskScore,
    riskLevel: PhishGuardRisk.level(riskScore, true),
    isPhishing: riskScore > 70,
    confidence: null,
    shouldBlock: PhishGuardRisk.shouldBlock(riskScore, riskScore),
    degraded: true,
    analysisStage: "url_only",
    detectors: {url: {status: "failed", source: "heuristic_fallback"}, nlp: {status: "not_run"}, dom: {status: "not_run"}},
    features: extractUrlFeatures(url),
    explanations: [],
    explanation: `Reduced protection: URL heuristics only. ${reason}`,
    urlRisk: riskScore,
    nlpRisk: null,
    domRisk: null,
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
  if (analysis.degraded) reasons.push(analysis.explanation || 'Reduced protection: URL heuristics only');
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
    score: String(analysis.finalScore > 70 ? analysis.finalScore : analysis.urlRisk),
    basis: analysis.analysisStage !== "url_only" && analysis.finalScore > 70 ? "combined" : "url",
    level: analysis.riskLevel,
    reasons: reasons.slice(0, 5).join("|"),
  });

  return `${warningPage}?${params.toString()}`;
}

// ============================================================================
// Message Handling
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {


  handleMessage(message, sender)
    .then(sendResponse)
    .catch((error) => {
      console.error("[PhishGuard] Message error:", error);
      sendResponse({ error: error.message });
    });

  return true; // Keep channel open for async
});

async function handleMessage(message, sender) {
  await ready;
  if (sender.id !== chrome.runtime.id) return {error: "Untrusted sender"};
  const privileged = trustedPage(sender);
  const fromPage = sender.tab && PhishGuardRisk.httpUrl(sender.url);
  if (!privileged && !fromPage) return {error: "Untrusted context"};
  switch (message.type) {
    case "BYPASS_WARNING": {
      const url = PhishGuardRisk.httpUrl(message.url);
      const warningTarget = privileged && sender.url?.startsWith(chrome.runtime.getURL("warning/warning.html"))
        ? new URL(sender.url).searchParams.get("url") : null;
      if (!url || (!privileged && sender.url !== url) || (warningTarget && warningTarget !== url)) return {error: "Invalid bypass target"};
      return handleBypassWarning(url);
    }
    case "CHECK_BYPASS":
      return {bypassed: isBypassed(privileged ? message.url : sender.url), enabled: state.settings.enabled};
    case "ANALYZE_PAGE_DATA":
      if (!fromPage || message.data?.url !== sender.url) return {error: "Page URL mismatch"};
      return handleAnalyzePageData(message.data, sender.tab.id, message.forceRefresh === true);
    case "GET_CURRENT_ANALYSIS":
      return handleGetCurrentAnalysis(privileged ? message.tabId : sender.tab.id);
    case "ANALYZE_URL": {
      const url = privileged ? message.url : sender.url;
      if (!PhishGuardRisk.httpUrl(url)) return {error: "Unsupported URL"};
      return analyzeUrlQuick(url, message.forceRefresh === true);
    }
    case "GET_STATS":
      return privileged ? getStats() : {error: "Not authorized"};
    case "GET_SETTINGS":
      return getSettings(); // Never returns the API token, including to content scripts.
    case "UPDATE_SETTINGS":
      return privileged ? updateSettings(message.settings) : {error: "Not authorized"};
    case "TEST_CONNECTION":
      if (!privileged) return {error: "Not authorized"};
      return requestApi(null, CONFIG.API_TIMEOUT, new URL("status", CONFIG.API_ENDPOINT).href);
    default:
      return {error: "Unknown message type"};
  }
}

function isBypassed(url) {
  if ((state.bypassExpiries[url] || 0) > Date.now()) return true;
  delete state.bypassExpiries[url];
  state.bypassedUrls.delete(url);
  return false;
}

async function handleBypassWarning(url) {
  if (!PhishGuardRisk.httpUrl(url)) return {error: "Unsupported URL"};
  for (const target of Object.keys(state.bypassExpiries)) isBypassed(target);
  state.bypassExpiries[url] = Date.now() + 30 * 60 * 1000;
  state.bypassedUrls.add(url);
  const entries = Object.entries(state.bypassExpiries).sort((a,b) => b[1]-a[1]).slice(0,100);
  state.bypassExpiries = Object.fromEntries(entries);
  state.bypassedUrls = new Set(entries.map(([target]) => target));
  await chrome.storage.session.set({bypassExpiries: state.bypassExpiries});
  return {success: true};
}

// ============================================================================
// Full Page Analysis (After page loads, includes NLP)
// ============================================================================

async function handleAnalyzePageData(pageData, tabId, forceRefresh = false) {
  await ready;
  if (!pageData || !PhishGuardRisk.httpUrl(pageData.url)) return {error: "Invalid page data"};
  const url = pageData.url;
  const requestId = crypto.randomUUID();
  state.pendingRequests.set(tabId, requestId);
  let analysis;
  try {
    analysis = normalizeResult(url, await requestApi({url, text: pageData.visibleText || "",
      dom: pageData.domFingerprint || {}, force_refresh: forceRefresh}, CONFIG.CONTENT_TIMEOUT));
  } catch (error) {
    console.warn("[PhishGuard] Page check degraded:", error.message);
    analysis = fallbackUrlAnalysis(url, error.message);
  }
  if (state.pendingRequests.get(tabId) !== requestId || !await tabMatches(tabId, url)) return {error: "Stale page analysis discarded"};
  state.pendingRequests.delete(tabId);
  state.analysisCache.set(tabId, analysis);
  // Full-page results never enter the separate URL-only cache.
  try { await chrome.tabs.sendMessage(tabId, {type: "ANALYSIS_RESULT", data: analysis}); } catch {}
  if (analysis.shouldBlock && !isBypassed(url) && await tabMatches(tabId, url)) {
    await chrome.tabs.update(tabId, {url: buildWarningUrl(url, analysis)});
  }
  return analysis;
}

// ============================================================================
// Helper Functions
// ============================================================================

async function handleGetCurrentAnalysis(tabId) {
  if (!Number.isInteger(tabId)) return {error: "No tab ID"};
  const result = state.analysisCache.get(tabId);
  // Short-lived fallback remains visible, then the popup retries full detection.
  if (!result || Date.now()-result.timestamp >= (result.degraded ? 5000 : CONFIG.CACHE_TTL) || !await tabMatches(tabId, result.url)) {
    state.analysisCache.delete(tabId);
    return {error: "No current analysis available"};
  }
  return result;
}

// ============================================================================
// Caching
// ============================================================================

const urlCache = new Map();

function getCachedAnalysis(url) {
  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_TTL) {
    urlCache.delete(url);
    urlCache.set(url, cached);
    return cached.data;
  }
  urlCache.delete(url);
  return null;
}

function cacheAnalysis(url, data) {
  urlCache.set(url, { data, timestamp: Date.now() });

  while (urlCache.size > 100) urlCache.delete(urlCache.keys().next().value);
}

// ============================================================================
// Statistics
// ============================================================================

let statsQueue = Promise.resolve();
function updateScanStats(isBlocked) {
  statsQueue = statsQueue.catch(() => {}).then(() => writeScanStats(isBlocked));
  return statsQueue;
}
async function writeScanStats(isBlocked) {
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
  const data = await chrome.storage.local.get(["enabled", "apiEndpoint", "nlpHighlightingEnabled"]);
  return {enabled: data.enabled ?? true, apiEndpoint: data.apiEndpoint ?? CONFIG.API_ENDPOINT,
    nlpHighlightingEnabled: data.nlpHighlightingEnabled !== false, paired: Boolean(state.settings.apiToken)};
}

async function updateSettings(settings) {
  if (!settings || typeof settings !== "object") throw new Error("Invalid settings");
  const allowed = ["enabled", "apiEndpoint", "apiToken", "nlpHighlightingEnabled"];
  if (Object.keys(settings).some(key => !allowed.includes(key))) throw new Error("Unknown setting");
  if (settings.apiEndpoint !== undefined && !validEndpoint(settings.apiEndpoint)) throw new Error("Only a loopback HTTP /api/analyze endpoint is allowed");
  if (settings.apiToken !== undefined && (typeof settings.apiToken !== "string" || !/^[A-Za-z0-9_-]{32,256}$/.test(settings.apiToken))) throw new Error("Token must be 32-256 letters, digits, underscores or hyphens");
  for (const key of ["enabled", "nlpHighlightingEnabled"]) {
    if (settings[key] !== undefined && typeof settings[key] !== "boolean") throw new Error("Invalid boolean setting");
  }
  if (settings.apiToken !== undefined) await tokenStore('put', settings.apiToken);
  const {apiToken, ...publicSettings} = settings;
  await chrome.storage.local.set(publicSettings);
  state.settings = {...state.settings, ...settings};
  if (settings.apiEndpoint) CONFIG.API_ENDPOINT = settings.apiEndpoint;
  urlCache.clear();
  state.analysisCache.clear();
  return {success: true};
}
