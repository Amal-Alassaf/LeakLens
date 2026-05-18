// demo-web/app.js
// ================= LeakLens Demo JS =================

const textarea = document.getElementById("messageInput");
const sendButton = document.getElementById("sendButton");
const chatForm = document.getElementById("chatForm");
const chatHistory = document.getElementById("chatHistory");

const fileInput = document.getElementById("fileInput");
const scanFileButton = document.getElementById("scanFileButton");

// ---------------- Helper: map backend action to CSS class ----------------
function mapActionToClass(action) {
  if (action === "redacted") return "redact";
  if (action === "blocked") return "block";
  if (action === "allowed_with_warning") return "warn";
  return "system";
}

// ---------------- Helper: add message to chat ----------------
function addMessage(text, type = "system") {
  const msg = document.createElement("div");
  msg.classList.add("message", type);
  msg.textContent = text;
  chatHistory.appendChild(msg);
  chatHistory.scrollTop = chatHistory.scrollHeight;
}

// ---------------- Overlay helpers ----------------
function showOverlay(scanResult, policy) {
  const existing = document.getElementById("leaklens-overlay");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "leaklens-overlay";

  let title = "LeakLens Scan Result";
  let background = "#111827";
  if (policy === "warn") { title = "Warning"; background = "#facc15"; }
  else if (policy === "block") { title = "Blocked"; background = "#ef4444"; }
  else if (policy === "redact") { title = "Redacted"; background = "#f97316"; }

  overlay.innerHTML = `
    <div style="font-weight:700; margin-bottom:8px;">${title}</div>
    <div><strong>Detected:</strong> ${scanResult.detections.map(d => d.pii_type).join(", ")}</div>
    <div><strong>Action:</strong> ${scanResult.action_taken}</div>
    <div style="margin-top:4px; background:rgba(31,41,55,0.85); padding:8px; border-radius:8px; max-height:120px; overflow-y:auto;">
      ${scanResult.output_text || ""}
    </div>
  `;
  overlay.style.position = "fixed";
  overlay.style.bottom = "24px";
  overlay.style.right = "24px";
  overlay.style.zIndex = "999999";
  overlay.style.width = "360px";
  overlay.style.padding = "16px";
  overlay.style.borderRadius = "14px";
  overlay.style.background = background;
  overlay.style.color = "#fff";
  overlay.style.fontFamily = "Arial,sans-serif";
  overlay.style.fontSize = "14px";
  overlay.style.lineHeight = "1.5";
  overlay.style.boxShadow = "0 12px 28px rgba(0,0,0,0.28)";

  document.body.appendChild(overlay);
  setTimeout(() => overlay.remove(), 8000);
}
function showFileScanOverlay(result, policy) {
    // Remove any existing overlay
    const existing = document.getElementById("leaklens-file-overlay");
    if (existing) existing.remove();

    // Create overlay container
    const overlay = document.createElement("div");
    overlay.id = "leaklens-file-overlay";
    overlay.style.position = "fixed";
    overlay.style.top = "24px";
    overlay.style.right = "24px";
    overlay.style.width = "360px";
    overlay.style.maxHeight = "70vh";
    overlay.style.overflowY = "auto";
    overlay.style.padding = "16px";
    overlay.style.borderRadius = "14px";
    overlay.style.boxShadow = "0 8px 24px rgba(0,0,0,0.3)";
    overlay.style.fontFamily = "Arial, sans-serif";
    overlay.style.fontSize = "14px";
    overlay.style.lineHeight = "1.5";
    overlay.style.color = "#fff";
    overlay.style.zIndex = "999999";

    // Background color based on policy / severity
    if (policy === "block") {
        overlay.style.background = "#b91c1c"; // red
    } else if (policy === "warn") {
        overlay.style.background = "#f59e0b"; // yellow/orange
        overlay.style.color = "#000";
    } else {
        overlay.style.background = "#111827"; // dark neutral
    }

    // Title
    const title = document.createElement("div");
    title.style.fontWeight = "bold";
    title.style.marginBottom = "8px";
    title.innerText = `LeakLens Scan Result (${policy.toUpperCase()})`;
    overlay.appendChild(title);

    // Risk Score
    const risk = document.createElement("div");
    risk.style.marginBottom = "8px";
    risk.innerHTML = `<strong>Risk score:</strong> ${result.risk_score}`;
    overlay.appendChild(risk);

    // Detected PII
    if (result.detections && result.detections.length) {
        const list = document.createElement("ul");
        list.style.paddingLeft = "16px";
        list.style.margin = "0 0 8px 0";
        result.detections.forEach(d => {
            const li = document.createElement("li");
            li.style.marginBottom = "4px";
            li.innerHTML = `<strong>${d.pii_type}</strong>: ${d.redacted} (${d.severity})`;
            list.appendChild(li);
        });
        overlay.appendChild(list);
    }

    // Action taken
    const action = document.createElement("div");
    action.style.fontWeight = "bold";
    action.style.marginTop = "8px";
    action.innerText = `Action taken: ${result.action_taken}`;
    overlay.appendChild(action);

    document.body.appendChild(overlay);

    // Auto-remove after 10 seconds
    setTimeout(() => overlay.remove(), 10000);
}

function showErrorOverlay(message) {
  const overlay = document.createElement("div");
  overlay.id = "leaklens-error-overlay";
  overlay.innerText = message;
  overlay.style.position = "fixed";
  overlay.style.bottom = "24px";
  overlay.style.right = "24px";
  overlay.style.background = "#991b1b";
  overlay.style.color = "#fff";
  overlay.style.padding = "12px";
  overlay.style.borderRadius = "10px";
  overlay.style.zIndex = "999999";
  document.body.appendChild(overlay);
  setTimeout(() => overlay.remove(), 5000);
}

// ---------------- Get policy from popup ----------------
async function getCurrentPolicy() {
  return new Promise(resolve => {
    chrome.storage.local.get(["leaklensPolicy"], result => {
      resolve(result.leaklensPolicy || "redact");
    });
  });
}

// ---------------- Chat input ----------------
chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = textarea.value.trim();
    if (!text) return;

    const policy = await getCurrentPolicy();
    try {
        const result = await scanText(text, policy);
        showOverlay(result, policy);

        if (policy === "redact") {
            textarea.value = result.output_text;
            chatForm.submit(); // send after redaction
        } else if (policy === "block") {
            showErrorOverlay("Message blocked by LeakLens policy."); 
            return; // do not submit
        } else if (policy === "warn") {
            showWarningOverlay("Message contains PII. Review before sending.");
            chatForm.submit(); // optional: allow send after warning
        } else {
            chatForm.submit(); // send if policy is default/allowed
        }

    } catch (err) {
        console.error("[LeakLens] Scan failed:", err);
        showErrorOverlay("Scan failed. Is the backend running?");
    }
});

// ---------------- File input ----------------
scanFileButton.addEventListener("click", async () => {
  const file = fileInput.files[0];
  if (!file) { showErrorOverlay("Attach a file first"); return; }

  const allowed = [".txt", ".pdf", ".docx"];
  if (!allowed.some(ext => file.name.toLowerCase().endsWith(ext))) {
    showErrorOverlay("Unsupported file type");
    return;
  }

  scanFileButton.disabled = true;
  scanFileButton.textContent = "Scanning file...";

  try {
    const policy = await getCurrentPolicy();
    let data;

    if (file.name.toLowerCase().endsWith(".txt")) {
      const content = await file.text();
      const res = await fetch("http://127.0.0.1:8000/scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ text: content, policy })
      });
      data = await res.json();
    } else {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("policy", policy);

      const res = await fetch("http://127.0.0.1:8000/scan-file", {
        method: "POST",
        body: formData
      });
      data = await res.json();
    }

    const cssClass = mapActionToClass(data.action_taken);
    addMessage(data.output_text || "[blocked]", cssClass);

    // --- Use improved overlay ---
    showFileScanOverlay(data, policy);

  } catch (err) {
    console.error("[LeakLens] File scan failed:", err);
    showErrorOverlay("File scan failed. Is the backend running?");
  } finally {
    scanFileButton.disabled = false;
    scanFileButton.textContent = "Scan file";
  }
});



document.addEventListener("LeakLensMessage", (e) => {
    const { text, policy } = e.detail;
    if (policy === "blocked") return; // do not send
    addMessage(text, "user");
});

console.log("[LeakLens] Chat and file scanning ready");