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
const GAUGE_CIRCUMFERENCE = 251.2; // pi * 80

document.addEventListener("DOMContentLoaded", async () => {
  init();
});

async function init() {
  setupEventListeners();
  await loadAnalysis();
  loadSettings();
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
  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    if (!tab?.url || tab.url.startsWith("chrome://")) {
      renderSystemPage();
      return;
    }

    const url = new URL(tab.url);
    elements.domain.textContent = url.hostname;
    elements.favicon.src = `https://www.google.com/s2/favicons?domain=${url.hostname}&sz=64`;
    elements.favicon.style.display = "block";

    // Check cache first if not forced
    if (!forceRefresh) {
      const cached = await chrome.runtime.sendMessage({
        type: "GET_CURRENT_ANALYSIS",
      });
      if (cached && cached.url === tab.url) {
        renderAnalysis(cached);
        return;
      }
    }

    // Request Analysis
    const analysis = await chrome.runtime.sendMessage({
      type: "ANALYZE_URL",
      url: tab.url,
    });

    if (analysis.error) throw new Error(analysis.error);
    renderAnalysis(analysis);
  } catch (error) {
    console.error("Analysis failed:", error);
    renderError(error.message);
  }
}

function renderAnalysis(data) {
  // Update Connection Status
  if (data.apiResponse === false) {
    elements.connectionStatus.innerHTML =
      '<span class="dot" style="background-color: var(--warning); box-shadow: 0 0 8px var(--warning)"></span> Offline Mode';
  } else {
    elements.connectionStatus.innerHTML = '<span class="dot"></span> Connected';
  }

  // 1. Risk Gauge
  const score = data.finalScore ?? data.riskScore ?? 0;
  const offset = GAUGE_CIRCUMFERENCE - (score / 100) * GAUGE_CIRCUMFERENCE;

  elements.riskScore.textContent = score;
  elements.gaugeArc.style.strokeDashoffset = offset;

  // Color based on score
  let color = "#22c55e"; // Green
  if (score >= 70)
    color = "#ef4444"; // Red
  else if (score >= 30) color = "#f59e0b"; // Orange

  elements.gaugeArc.style.stroke = color;

  // 2. Risk Badge
  const level =
    data.riskLevel ||
    (score >= 70 ? "dangerous" : score >= 30 ? "suspicious" : "safe");
  elements.riskBadge.className = `risk-badge ${level}`;
  elements.riskBadge.textContent = level.toUpperCase();

  // 3. Breakdown
  updateBar(elements.barUrl, elements.scoreUrl, data.urlRisk ?? 0);
  updateBar(elements.barNlp, elements.scoreNlp, data.nlpRisk ?? 0);
  updateBar(elements.barDom, elements.scoreDom, data.domRisk ?? 0);

  // 4. Explanations
  renderExplanations(data.explanations || []);
}

function updateBar(barEl, scoreEl, score) {
  barEl.style.width = `${score}%`;
  scoreEl.textContent = `${score}%`;

  let color = "#22c55e";
  if (score >= 70) color = "#ef4444";
  else if (score >= 30) color = "#f59e0b";

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

    el.innerHTML = `
            <span class="exp-icon">${icon}</span>
            <span class="exp-text">${item.message}</span>
            ${badgeClass ? `<span class="exp-badge ${badgeClass}">${item.category}</span>` : ""}
        `;
    elements.explanationsList.appendChild(el);
  });
}

function renderSystemPage() {
  elements.domain.textContent = "System Page";
  elements.riskScore.textContent = "0";
  elements.gaugeArc.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  elements.riskBadge.className = "risk-badge safe";
  elements.riskBadge.textContent = "SAFE";
  renderExplanations([]);
}

function renderError(msg) {
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
