console.log("[LeakLens] Content script loaded.");

const LEAKLENS_SCAN_URL = "http://127.0.0.1:8000/scan";
const LEAKLENS_POLICY = "redact";

function createBadge(text, backgroundColor) {
  const existingBadge = document.getElementById("leaklens-status-badge");

  if (existingBadge) {
    existingBadge.remove();
  }

  const badge = document.createElement("div");
  badge.id = "leaklens-status-badge";
  badge.textContent = text;

  badge.style.position = "fixed";
  badge.style.top = "16px";
  badge.style.right = "16px";
  badge.style.zIndex = "999999";
  badge.style.padding = "10px 14px";
  badge.style.borderRadius = "10px";
  badge.style.background = backgroundColor;
  badge.style.color = "#ffffff";
  badge.style.fontFamily = "Arial, sans-serif";
  badge.style.fontSize = "14px";
  badge.style.boxShadow = "0 8px 20px rgba(0, 0, 0, 0.2)";

  document.body.appendChild(badge);
}

function showOverlay(scanResult) {
  const existingOverlay = document.getElementById("leaklens-overlay");

  if (existingOverlay) {
    existingOverlay.remove();
  }

  const detections = Array.isArray(scanResult.detections)
    ? scanResult.detections
    : [];

  const detectedTypes = detections.length
    ? detections.map((item) => item.pii_type).join(", ")
    : "None";

  const severities = detections.length
    ? detections.map((item) => item.severity).join(", ")
    : "None";

  const overlay = document.createElement("div");
  overlay.id = "leaklens-overlay";

  overlay.innerHTML = `
    <div style="font-weight: 700; margin-bottom: 8px;">LeakLens scan result</div>
    <div><strong>Detected:</strong> ${escapeHtml(detectedTypes)}</div>
    <div><strong>Severity:</strong> ${escapeHtml(severities)}</div>
    <div><strong>Risk score:</strong> ${escapeHtml(String(scanResult.risk_score))}</div>
    <div><strong>Action:</strong> ${escapeHtml(scanResult.action_taken || "unknown")}</div>
    <div style="margin-top: 8px;"><strong>Preview:</strong></div>
    <div style="margin-top: 4px; padding: 8px; background: #1f2937; border-radius: 8px;">
      ${escapeHtml(scanResult.output_text || "")}
    </div>
  `;

  overlay.style.position = "fixed";
  overlay.style.bottom = "24px";
  overlay.style.right = "24px";
  overlay.style.zIndex = "999999";
  overlay.style.width = "360px";
  overlay.style.padding = "16px";
  overlay.style.borderRadius = "14px";
  overlay.style.background = "#111827";
  overlay.style.color = "#ffffff";
  overlay.style.fontFamily = "Arial, sans-serif";
  overlay.style.fontSize = "14px";
  overlay.style.lineHeight = "1.5";
  overlay.style.boxShadow = "0 12px 28px rgba(0, 0, 0, 0.28)";

  document.body.appendChild(overlay);
}

function showErrorOverlay(message) {
  const existingOverlay = document.getElementById("leaklens-overlay");

  if (existingOverlay) {
    existingOverlay.remove();
  }

  const overlay = document.createElement("div");
  overlay.id = "leaklens-overlay";

  overlay.innerHTML = `
    <div style="font-weight: 700; margin-bottom: 8px;">LeakLens error</div>
    <div>${escapeHtml(message)}</div>
  `;

  overlay.style.position = "fixed";
  overlay.style.bottom = "24px";
  overlay.style.right = "24px";
  overlay.style.zIndex = "999999";
  overlay.style.width = "360px";
  overlay.style.padding = "16px";
  overlay.style.borderRadius = "14px";
  overlay.style.background = "#991b1b";
  overlay.style.color = "#ffffff";
  overlay.style.fontFamily = "Arial, sans-serif";
  overlay.style.fontSize = "14px";
  overlay.style.lineHeight = "1.5";
  overlay.style.boxShadow = "0 12px 28px rgba(0, 0, 0, 0.28)";

  document.body.appendChild(overlay);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function addMessageToDemoChat(text) {
  const chatHistory = document.querySelector("#chatHistory");

  if (!chatHistory) {
    console.error("[LeakLens] Could not find chat history.");
    return;
  }

  const messageElement = document.createElement("div");
  messageElement.classList.add("message", "user-message");
  messageElement.textContent = text;

  chatHistory.appendChild(messageElement);
  chatHistory.scrollTop = chatHistory.scrollHeight;
}

async function scanText(text) {
  const response = await fetch(LEAKLENS_SCAN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      text: text,
      policy: LEAKLENS_POLICY
    })
  });

  if (!response.ok) {
    throw new Error(`Scanner returned HTTP ${response.status}`);
  }

  return await response.json();
}

function handlePolicyResult(scanResult, originalText, textarea) {
  const actionTaken = scanResult.action_taken || "unknown";

  showOverlay(scanResult);

  if (LEAKLENS_POLICY === "block") {
    console.warn("[LeakLens] Message blocked:", scanResult);
    textarea.value = originalText;
    textarea.focus();
    return;
  }

  if (LEAKLENS_POLICY === "warn") {
    console.warn("[LeakLens] Warning shown. Sending original text.");
    addMessageToDemoChat(originalText);
    textarea.value = "";
    textarea.focus();
    return;
  }

  if (LEAKLENS_POLICY === "redact") {
    const finalText = scanResult.output_text || originalText;

    console.log("[LeakLens] Sending redacted text:", finalText);

    textarea.value = finalText;
    addMessageToDemoChat(finalText);
    textarea.value = "";
    textarea.focus();
    return;
  }

  console.warn("[LeakLens] Unknown policy. Blocking by default:", LEAKLENS_POLICY);
  textarea.value = originalText;
  textarea.focus();
}

function setupInterception() {
  const textarea = document.querySelector("#messageInput");
  const sendButton = document.querySelector("#sendButton");
  const chatForm = document.querySelector("#chatForm");

  console.log("[LeakLens] textarea:", textarea);
  console.log("[LeakLens] sendButton:", sendButton);
  console.log("[LeakLens] chatForm:", chatForm);

  if (!textarea || !sendButton || !chatForm) {
    createBadge("LeakLens: demo elements not found", "#b91c1c");
    return;
  }

  if (chatForm.dataset.leaklensAttached === "true") {
    console.log("[LeakLens] Interception already attached. Skipping.");
    createBadge("LeakLens: already attached", "#92400e");
    return;
  }

  chatForm.dataset.leaklensAttached = "true";

  createBadge("LeakLens: scanner ready", "#15803d");

  chatForm.addEventListener(
    "submit",
    async function (event) {
      event.preventDefault();
      event.stopImmediatePropagation();

      const messageText = textarea.value.trim();

      if (!messageText) {
        return;
      }

      console.log("[LeakLens] Intercepted message:", messageText);

      sendButton.disabled = true;
      sendButton.textContent = "Scanning...";

      try {
        const scanResult = await scanText(messageText);

        console.log("[LeakLens] Scan result:", scanResult);

        handlePolicyResult(scanResult, messageText, textarea);
      } catch (error) {
        console.error("[LeakLens] Scan failed:", error);

        showErrorOverlay(
          "Could not reach local scanner. Make sure FastAPI is running on http://127.0.0.1:8000"
        );
      } finally {
        sendButton.disabled = false;
        sendButton.textContent = "Send";
      }
    },
    true
  );
}

setupInterception();