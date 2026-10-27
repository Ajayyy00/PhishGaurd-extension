"use strict";
const status = document.getElementById("status");
document.getElementById("origin").textContent = `chrome-extension://${chrome.runtime.id}`;
chrome.runtime.sendMessage({type: "GET_SETTINGS"}).then(settings => {
  document.getElementById("endpoint").value = settings.apiEndpoint;
  status.textContent = settings.paired ? "Token saved. Use Test connection to verify." : "Pairing required; offline heuristics remain available.";
});
document.getElementById("connection-form").addEventListener("submit", async event => {
  event.preventDefault();
  const settings = {apiEndpoint: document.getElementById("endpoint").value};
  const token = document.getElementById("token").value.trim();
  if (token) settings.apiToken = token;
  try {
    const result = await chrome.runtime.sendMessage({type: "UPDATE_SETTINGS", settings});
    if (result.error) throw new Error(result.error);
    document.getElementById("token").value = "";
    status.textContent = "Connection saved. Use Test connection to verify.";
  } catch (error) { status.textContent = error.message; }
});
document.getElementById("test-connection").addEventListener("click", async () => {
  const result = await chrome.runtime.sendMessage({type: "TEST_CONNECTION"});
  status.textContent = result.error || "Connected and authenticated. All three detectors are enabled.";
});
