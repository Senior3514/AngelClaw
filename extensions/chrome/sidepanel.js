/* AngelClaw AGI Guardian — Side Panel Chat Logic */
/* eslint-env browser */
/* global chrome */

const DEFAULT_API = "http://localhost:8500";

const statusDot = document.getElementById("statusDot");
const statusLabel = document.getElementById("statusLabel");
const pageUrlEl = document.getElementById("pageUrl");
const chatMessages = document.getElementById("chatMessages");
const chatInput = document.getElementById("chatInput");

let apiUrl = DEFAULT_API;
let authToken = "";
let currentPageUrl = "";

// ── Settings ──────────────────────────────────────────────────────────
function loadSettings() {
  chrome.storage.local.get(["apiUrl", "authToken"], (data) => {
    apiUrl = (data.apiUrl || DEFAULT_API).replace(/\/+$/, "");
    authToken = data.authToken || "";
    checkConnection();
  });
}

// ── Connection ────────────────────────────────────────────────────────
async function checkConnection() {
  statusDot.className = "status-dot checking";
  statusLabel.textContent = "Connecting...";
  try {
    const resp = await fetch(`${apiUrl}/health`, { signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      statusDot.className = "status-dot connected";
      statusLabel.textContent = "Connected";
    } else {
      throw new Error();
    }
  } catch {
    statusDot.className = "status-dot error";
    statusLabel.textContent = "Disconnected — check popup settings";
  }
}

// ── Page context ──────────────────────────────────────────────────────
function updatePageContext() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      currentPageUrl = tabs[0].url || "";
      pageUrlEl.textContent = currentPageUrl || "—";
    }
  });
}

// ── Chat ──────────────────────────────────────────────────────────────
function addMessage(text, role) {
  const div = document.createElement("div");
  div.className = `chat-message ${role}`;
  div.textContent = text;
  chatMessages.appendChild(div);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

async function sendChat(prompt) {
  addMessage(prompt, "user");

  const fullPrompt = currentPageUrl
    ? `[Page context: ${currentPageUrl}] ${prompt}`
    : prompt;

  const headers = { "Content-Type": "application/json" };
  if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

  try {
    const resp = await fetch(`${apiUrl}/api/v1/angelclaw/chat`, {
      method: "POST",
      headers,
      body: JSON.stringify({ tenantId: "default", prompt: fullPrompt }),
      signal: AbortSignal.timeout(30000),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }

    const data = await resp.json();
    addMessage(data.answer || "No response", "assistant");
  } catch (err) {
    addMessage(`Error: ${err.message}`, "assistant");
  }
}

// ── Events ────────────────────────────────────────────────────────────
document.getElementById("btnSend").addEventListener("click", () => {
  const prompt = chatInput.value.trim();
  if (prompt) { sendChat(prompt); chatInput.value = ""; }
});

chatInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const prompt = chatInput.value.trim();
    if (prompt) { sendChat(prompt); chatInput.value = ""; }
  }
});

// Listen for tab changes to update page context
chrome.tabs.onActivated.addListener(updatePageContext);
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) updatePageContext();
});

// ── Init ──────────────────────────────────────────────────────────────
loadSettings();
updatePageContext();
chatInput.focus();
