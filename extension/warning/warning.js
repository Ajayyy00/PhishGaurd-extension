/**
 * PhishGuard Warning Page Script
 */

document.addEventListener("DOMContentLoaded", () => {
  // Parse URL parameters
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "";
  const riskScore = parseInt(params.get("score")) || 0;
  const riskLevel = params.get("level") || "unknown";
  const reasons = params.get("reasons") || "";

  // Populate UI
  document.getElementById("urlDisplay").textContent = targetUrl;
  document.getElementById("riskScore").textContent = riskScore;

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
      item.innerHTML = `<span class="reason-icon">⚠️</span><span>${reason}</span>`;
      reasonsList.appendChild(item);
    });
  } else {
    reasonsList.innerHTML =
      '<div class="reason-item"><span class="reason-icon">⚠️</span><span>High-risk URL detected by ML analysis</span></div>';
  }

  // Back button - go to a safe page (Google)
  document.getElementById("backBtn").addEventListener("click", () => {
    // Always go to Google to avoid redirect loops
    window.location.href = "https://www.google.com";
  });

  // Proceed button - allow the URL
  document.getElementById("proceedBtn").addEventListener("click", () => {
    // Send message to background to whitelist this URL temporarily
    chrome.runtime.sendMessage(
      {
        type: "BYPASS_WARNING",
        url: targetUrl,
      },
      (response) => {
        window.location.href = targetUrl;
      },
    );
  });
});
