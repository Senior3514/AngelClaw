/* AngelClaw AGI Guardian — Popup Logic */
/* eslint-env browser */
/* global chrome */

const DEFAULT_API = "http://localhost:8500";

// DOM elements
const statusDot = document.getElementById("statusDot");
const statusLabel = document.getElementById("statusLabel");
const statusVersion = document.getElementById("statusVersion");
const chatInput = document.getElementById("chatInput");
const chatResponse = document.getElementById("chatResponse");
const apiUrlInput = document.getElementById("apiUrl");
const authTokenInput = document.getElementById("authToken");

// ── Settings persistence ──────────────────────────────────────────────
function loadSettings() {
  chrome.storage.local.get(["apiUrl", "authToken"], (data) => {
    apiUrlInput.value = data.apiUrl || DEFAULT_API;
    authTokenInput.value = data.authToken || "";
    checkConnection();
  });
}

function saveSettings() {
  const apiUrl = apiUrlInput.value.replace(/\/+$/, "") || DEFAULT_API;
  const authToken = authTokenInput.value.trim();
  chrome.storage.local.set({ apiUrl, authToken }, () => {
    apiUrlInput.value = apiUrl;
    statusLabel.textContent = "Settings saved";
    checkConnection();
  });
}

// ── Connection check ──────────────────────────────────────────────────
async function checkConnection() {
  const apiUrl = apiUrlInput.value.replace(/\/+$/, "") || DEFAULT_API;
  statusDot.className = "status-dot checking";
  statusLabel.textContent = "Checking connection...";
  statusVersion.textContent = "";

  try {
    const resp = await fetch(`${apiUrl}/health`, { method: "GET", signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      const data = await resp.json();
      statusDot.className = "status-dot connected";
      statusLabel.textContent = "Connected";
      statusVersion.textContent = `v${data.version || "?"}`;
    } else {
      throw new Error(`HTTP ${resp.status}`);
    }
  } catch (err) {
    statusDot.className = "status-dot error";
    statusLabel.textContent = "Disconnected";
    statusVersion.textContent = "";
  }
}

// ── Chat ──────────────────────────────────────────────────────────────
async function sendChat(prompt) {
  const apiUrl = apiUrlInput.value.replace(/\/+$/, "") || DEFAULT_API;
  const token = authTokenInput.value.trim();

  chatResponse.textContent = "Thinking...";
  chatResponse.style.color = "var(--text-muted)";

  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const resp = await fetch(`${apiUrl}/api/v1/angelclaw/chat`, {
      method: "POST",
      headers,
      body: JSON.stringify({ tenantId: "default", prompt }),
      signal: AbortSignal.timeout(30000),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }

    const data = await resp.json();
    chatResponse.style.color = "var(--text)";
    chatResponse.textContent = data.answer || "No response";
  } catch (err) {
    chatResponse.style.color = "var(--danger)";
    chatResponse.textContent = `Error: ${err.message}`;
  }
}

// ── Event listeners ───────────────────────────────────────────────────
document.getElementById("btnSave").addEventListener("click", saveSettings);
document.getElementById("btnScan").addEventListener("click", () => sendChat("Scan the system"));
document.getElementById("btnShield").addEventListener("click", () => sendChat("Run shield assessment"));
document.getElementById("btnDashboard").addEventListener("click", () => {
  const apiUrl = apiUrlInput.value.replace(/\/+$/, "") || DEFAULT_API;
  chrome.tabs.create({ url: `${apiUrl}/ui` });
});
document.getElementById("btnChat").addEventListener("click", () => {
  const prompt = chatInput.value.trim();
  if (prompt) { sendChat(prompt); chatInput.value = ""; }
});
chatInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const prompt = chatInput.value.trim();
    if (prompt) { sendChat(prompt); chatInput.value = ""; }
  }
});

// ── Init ──────────────────────────────────────────────────────────────
loadSettings();
