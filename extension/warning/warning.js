/**
 * PhishGuard Warning Page Script
 */

document.addEventListener("DOMContentLoaded", () => {
  // Parse URL parameters
  const params = new URLSearchParams(window.location.search);
  const targetUrl = PhishGuardRisk.httpUrl(params.get("url"));
  const rawScore = Number(params.get("score"));
  const riskScore = params.has("score") && PhishGuardRisk.validScore(rawScore) ? rawScore : null;
  const riskLevel = PhishGuardRisk.level(riskScore);
  const reasons = params.get("reasons") || "";

  // Populate UI
  document.getElementById("urlDisplay").textContent = targetUrl || "Invalid or unsupported target URL";
  document.querySelector(".risk-label").textContent = params.get("basis") === "url" ? "URL protection score" : "Combined risk score";
  document.getElementById("proceedBtn").disabled = !targetUrl;
  document.getElementById("riskScore").textContent = riskScore ?? "--";

  const riskLevelEl = document.getElementById("riskLevel");
  riskLevelEl.textContent = riskLevel.toUpperCase();
  riskLevelEl.className = `risk-level ${riskLevel}`;

  // Populate reasons
  const reasonsList = document.getElementById("reasonsList");
  if (reasons) {
    const reasonsArr = reasons.split("|").filter((r) => r);
    reasonsArr.forEach((reason) => {
      const item = document.createElement("div");
      item.className = "reason-item";
      const icon = document.createElement("span");
      icon.className = "reason-icon";
      icon.textContent = "⚠️";
      const text = document.createElement("span");
      text.textContent = reason;
      item.append(icon, text);
      reasonsList.appendChild(item);
    });
  } else {
    reasonsList.innerHTML =
      '<div class="reason-item"><span class="reason-icon">⚠️</span><span>Protection threshold exceeded</span></div>';
  }

  // Back button - leave this navigation without a redirect loop
  document.getElementById("backBtn").addEventListener("click", () => {
    // A local blank page also works while offline.
    window.location.replace("about:blank");
  });

  // Proceed button - allow the URL
  document.getElementById("proceedBtn").addEventListener("click", () => {
    if (!targetUrl) return;
    // Send message to background to whitelist this URL temporarily
    chrome.runtime.sendMessage(
      {
        type: "BYPASS_WARNING",
        url: targetUrl,
      },
      (response) => {
        if (response?.success) window.location.replace(targetUrl);
        else document.getElementById("reasonsList").textContent = "Bypass failed. Please retry.";
      },
    );
  });
});
