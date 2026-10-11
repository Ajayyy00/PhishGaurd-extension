/**
 * PhishGuard Modern Popup Script
 */

const elements = {
  domain: document.getElementById("domain"),
  favicon: document.getElementById("favicon"),
  riskScore: document.getElementById("risk-score"),
  gaugeArc: document.getElementById("gauge-arc"),
  riskBadge: document.getElementById("risk-badge"),

  // Breakdown
  barUrl: document.getElementById("bar-url"),
  scoreUrl: document.getElementById("score-url"),
  barNlp: document.getElementById("bar-nlp"),
  scoreNlp: document.getElementById("score-nlp"),
  barDom: document.getElementById("bar-dom"),
  scoreDom: document.getElementById("score-dom"),

  // Details
  toggleDetails: document.getElementById("toggle-details"),
  explanationsList: document.getElementById("explanations-list"),

  // Actions
  rescanBtn: document.getElementById("rescan-btn"),
  nlpToggle: document.getElementById("nlp-toggle"),
  connectionStatus: document.getElementById("connection-status"),
};

// Constants
let refreshInProgress = false;
let rescanPending = false;
const GAUGE_CIRCUMFERENCE = 251.2; // pi * 80

document.addEventListener("DOMContentLoaded", async () => {
  init();
});

async function init() {
  elements.favicon.addEventListener("error", () => { elements.favicon.style.display = "none"; });
  document.getElementById("connection-settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
  setupEventListeners();
  await loadAnalysis();
  loadSettings();
  setInterval(() => loadAnalysis(), 2000);
}

function setupEventListeners() {
  elements.toggleDetails.addEventListener("click", () => {
    elements.explanationsList.classList.toggle("hidden");
    const chevron = elements.toggleDetails.querySelector(".chevron");
    chevron.style.transform = elements.explanationsList.classList.contains(
      "hidden",
    )
      ? "rotate(0deg)"
      : "rotate(180deg)";
  });

  elements.rescanBtn.addEventListener("click", async () => {
    setLoadingState(true);
    await loadAnalysis(true);
    setLoadingState(false);
  });

  elements.nlpToggle.addEventListener("change", async (e) => {
    const enabled = e.target.checked;
    await chrome.storage.local.set({ nlpHighlightingEnabled: enabled });

    // Notify content script
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (tab?.id) {
      chrome.tabs
        .sendMessage(tab.id, {
          type: "TOGGLE_NLP_HIGHLIGHTING",
          enabled,
        })
        .catch(() => {}); // Ignore error if content script not ready
    }
  });
}

async function loadAnalysis(forceRefresh = false) {
  if (refreshInProgress) { if (forceRefresh) rescanPending = true; return; }
  refreshInProgress = true;
  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    if (!tab?.url || !PhishGuardRisk.httpUrl(tab.url)) {
      renderSystemPage();
      return;
    }

    const url = new URL(tab.url);
    elements.domain.textContent = tab.url;
    elements.domain.title = tab.url;
    elements.favicon.src = "../assets/icons/icon48.png";
    elements.favicon.style.display = "block";

    // Check cache first if not forced
    if (!forceRefresh) {
      const cached = await chrome.runtime.sendMessage({
        type: "GET_CURRENT_ANALYSIS",
        tabId: tab.id,
      });
      if (cached && cached.url === tab.url) {
        await renderForTab(tab, cached);
        return;
      }
    }

    // Rescan uses current visible text and DOM; restricted pages fall back to URL-only.
    try {
      const pageResult = await chrome.tabs.sendMessage(tab.id, {type: "RESCAN_PAGE", forceRefresh});
      if (pageResult && !pageResult.error && pageResult.url === tab.url) {
        await renderForTab(tab, pageResult);
        return;
      }
    } catch {}
    // Request Analysis
    const analysis = await chrome.runtime.sendMessage({
      type: "ANALYZE_URL",
      url: tab.url,
      forceRefresh,
    });

    if (analysis.error) throw new Error(analysis.error);
    await renderForTab(tab, analysis);
  } catch (error) {
    console.error("Analysis failed:", error);
    renderError(error.message);
  } finally {
    refreshInProgress = false;
    if (rescanPending) { rescanPending = false; loadAnalysis(true); }
  }
}

async function renderForTab(tab, data) {
  const [current] = await chrome.tabs.query({active: true, currentWindow: true});
  if (current?.id === tab.id && current?.url === data.url) renderAnalysis(data);
}

function renderAnalysis(data) {
  elements.domain.textContent = data.url || "Unknown URL";
  elements.connectionStatus.textContent = data.degraded ? "Reduced protection" : "Connected";
  document.getElementById("analysis-status").textContent = `${data.analysisStage || "Pending"}${data.degraded ? " · URL fallback or incomplete detection" : ""}`;
  // 1. Risk Gauge
  const score = data.finalScore ?? data.riskScore;
  if (!PhishGuardRisk.validScore(score)) { renderError("Analysis unavailable"); return; }
  const offset = GAUGE_CIRCUMFERENCE - (score / 100) * GAUGE_CIRCUMFERENCE;

  elements.riskScore.textContent = score;
  elements.gaugeArc.style.strokeDashoffset = offset;

  // Color based on score
  let color = "#22c55e"; // Green
  if (score > 70)
    color = "#ef4444"; // Red
  else if (score > 30) color = "#f59e0b"; // Orange

  elements.gaugeArc.style.stroke = color;

  // 2. Risk Badge
  const level = PhishGuardRisk.level(score, data.degraded);
  elements.riskBadge.className = `risk-badge ${level}`;
  elements.riskBadge.textContent = level.toUpperCase();

  // 3. Breakdown
  updateBar(elements.barUrl, elements.scoreUrl, data.urlRisk);
  updateBar(elements.barNlp, elements.scoreNlp, data.nlpRisk);
  updateBar(elements.barDom, elements.scoreDom, data.domRisk);

  // 4. Explanations
  renderExplanations(data.degraded ? [{type: "warning", category: "system", message: data.explanation || "Detection is incomplete"}, ...(data.explanations || [])] : data.explanations || []);
}

function updateBar(barEl, scoreEl, score) {
  if (!PhishGuardRisk.validScore(score)) { barEl.style.width = "0%"; scoreEl.textContent = "Unavailable"; return; }
  barEl.style.width = `${score}%`;
  scoreEl.textContent = `${score}%`;

  let color = "#22c55e";
  if (score > 70) color = "#ef4444";
  else if (score > 30) color = "#f59e0b";

  barEl.style.backgroundColor = color;
}

function renderExplanations(list) {
  elements.explanationsList.innerHTML = "";

  if (!list || list.length === 0) {
    elements.explanationsList.innerHTML =
      '<div class="empty-state">No specific threats detected.</div>';
    return;
  }

  list.forEach((item) => {
    const el = document.createElement("div");
    el.className = "explanation-item";

    let icon = "ℹ️";
    if (item.type === "danger") icon = "🚫";
    if (item.type === "warning") icon = "⚠️";
    if (item.type === "safe") icon = "✅";

    // Badge logic (optional, based on category)
    let badgeClass = "";
    if (item.category === "ml") badgeClass = "badge-ml";
    else if (item.category === "url") badgeClass = "badge-url";
    else if (item.category === "content") badgeClass = "badge-content";

    const iconEl = document.createElement("span");
    iconEl.className = "exp-icon";
    iconEl.textContent = icon;
    const textEl = document.createElement("span");
    textEl.className = "exp-text";
    textEl.textContent = String(item.message || "");
    el.append(iconEl, textEl);
    if (badgeClass) {
      const badge = document.createElement("span");
      badge.className = `exp-badge ${badgeClass}`;
      badge.textContent = item.category;
      el.appendChild(badge);
    }
    elements.explanationsList.appendChild(el);
  });
}

function renderSystemPage() {
  elements.domain.textContent = "System Page";
  elements.riskScore.textContent = "--";
  elements.gaugeArc.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  elements.riskBadge.className = "risk-badge safe";
  elements.riskBadge.textContent = "NOT ANALYZED";
  document.getElementById("analysis-status").textContent = "Browser page; analysis unavailable";
  [elements.scoreUrl, elements.scoreNlp, elements.scoreDom].forEach(el => { el.textContent = "--"; });
  renderExplanations([]);
}

function renderError(msg) {
  elements.riskScore.textContent = "--";
  [[elements.barUrl,elements.scoreUrl],[elements.barNlp,elements.scoreNlp],[elements.barDom,elements.scoreDom]].forEach(([bar,label]) => updateBar(bar,label,null));
  elements.domain.textContent = "Error";
  elements.riskBadge.className = "risk-badge warning";
  elements.riskBadge.textContent = "ERROR";
  renderExplanations([{ type: "warning", message: msg, category: "system" }]);
}

function setLoadingState(isLoading) {
  const btn = elements.rescanBtn;
  if (isLoading) {
    btn.disabled = true;
    btn.innerHTML = "<span>⏳</span> Scanning...";
  } else {
    btn.disabled = false;
    btn.innerHTML = "<span>🔄</span> Rescan";
  }
}

function loadSettings() {
  chrome.storage.local.get(["nlpHighlightingEnabled"], (result) => {
    elements.nlpToggle.checked = result.nlpHighlightingEnabled !== false;
  });
}
