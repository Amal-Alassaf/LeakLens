// ============ LeakLens Content Script ============
console.log("[LeakLens] Content script loaded.");

// --- Overlay helpers ---
function showOverlay(scanResult, policy) {
    let overlay = document.getElementById("leaklens-overlay");
    if (!overlay) {
        overlay = document.createElement("div");
        overlay.id = "leaklens-overlay";
        overlay.style.position = "fixed";
        overlay.style.bottom = "24px";
        overlay.style.right = "24px";
        overlay.style.background = "rgb(17,24,39)";
        overlay.style.color = "#fff";
        overlay.style.padding = "16px";
        overlay.style.borderRadius = "14px";
        overlay.style.fontFamily = "Arial, sans-serif";
        overlay.style.fontSize = "14px";
        overlay.style.lineHeight = "1.5";
        overlay.style.boxShadow = "0 0 12px rgba(0,0,0,0.28)";
        overlay.style.zIndex = "999999";
        overlay.style.maxWidth = "360px";
        overlay.style.whiteSpace = "pre-wrap";
        document.body.appendChild(overlay);
    }
    overlay.innerText = `LeakLens scan result\nDetected: ${scanResult.detections.map(d => d.pii_type).join(", ")}\nSeverity: ${scanResult.detections.map(d => d.severity).join(", ")}\nRisk score: ${scanResult.risk_score}\nAction: ${scanResult.action_taken}\nPreview:\n${scanResult.output_text || "[Blocked]"}`;
    setTimeout(() => overlay.remove(), 8000);
}

function showErrorOverlay(message) {
    let overlay = document.createElement("div");
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

function showWarningOverlay(message) {
    let overlay = document.createElement("div");
    overlay.id = "leaklens-warning-overlay";
    overlay.innerText = message;
    overlay.style.position = "fixed";
    overlay.style.bottom = "24px";
    overlay.style.right = "24px";
    overlay.style.background = "#f59e0b";
    overlay.style.color = "#000";
    overlay.style.padding = "12px";
    overlay.style.borderRadius = "10px";
    overlay.style.zIndex = "999999";
    document.body.appendChild(overlay);
    setTimeout(() => overlay.remove(), 5000);
}

// --- Backend helpers ---
async function scanText(text, policy) {
    const response = await fetch("http://127.0.0.1:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, policy })
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function scanFile(file, policy) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("policy", policy);
    const response = await fetch("http://127.0.0.1:8000/scan-file", { method: "POST", body: formData });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

// --- Get policy from popup ---
async function getCurrentPolicy() {
    return new Promise((resolve) => {
        chrome.storage.local.get(["leaklensPolicy"], function (result) {
            resolve(result.leaklensPolicy || "redact");
        });
    });
}

// --- Dispatch messages to page via CustomEvent ---
function dispatchMessageToPage(text, policy) {
    const event = new CustomEvent("LeakLensMessage", {
        detail: { text, policy }
    });
    document.dispatchEvent(event);
}

// --- Chat interception ---
function setupChatInterception() {
    const chatForm = document.getElementById("chatForm");
    const messageInput = document.getElementById("messageInput");
    if (!chatForm || !messageInput) return;
    if (chatForm.dataset.leaklensAttached === "true") return;

    chatForm.dataset.leaklensAttached = "true";

    chatForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const text = messageInput.value.trim();
        if (!text) return;

        const policy = await getCurrentPolicy();

        try {
            const result = await scanText(text, policy);
            showOverlay(result, policy);

            // --- Decide what to send to page ---
            if (result.action_taken === "blocked") {
                showErrorOverlay("Message blocked due to sensitive content");
            } else if (result.action_taken === "redacted") {
                dispatchMessageToPage(result.output_text, "redact");
            } else if (result.action_taken === "allowed_with_warning") {
                showWarningOverlay("Message contains sensitive data");
                dispatchMessageToPage(text, "warn");
            } else {
                dispatchMessageToPage(text, "none");
            }

            messageInput.value = "";
            messageInput.focus();

        } catch (err) {
            console.error("[LeakLens] Scan failed:", err);
            showErrorOverlay("Scan failed. Sending message anyway.");
            dispatchMessageToPage(text, "error");
            messageInput.value = "";
            messageInput.focus();
        }
    });
}

// --- File scanning ---
function setupFileScanning() {
    const fileInput = document.getElementById("fileInput");
    const scanFileButton = document.getElementById("scanFileButton");
    if (!fileInput || !scanFileButton) return;
    if (scanFileButton.dataset.leaklensFileAttached === "true") return;

    scanFileButton.dataset.leaklensFileAttached = "true";

    scanFileButton.addEventListener("click", async () => {
        const file = fileInput.files[0];
        if (!file) return showErrorOverlay("Please attach a file first.");

        const allowedExt = [".txt", ".pdf", ".docx"];
        if (!allowedExt.some(ext => file.name.toLowerCase().endsWith(ext))) {
            return showErrorOverlay("Only .txt, .pdf, .docx files are supported.");
        }

        scanFileButton.disabled = true;
        scanFileButton.textContent = "Scanning file...";
        try {
            const policy = await getCurrentPolicy();
            let result;
            if (file.name.toLowerCase().endsWith(".txt")) {
                const text = await file.text();
                result = await scanText(text, policy);
            } else {
                result = await scanFile(file, policy);
            }
            showOverlay(result, policy);
        } catch (err) {
            console.error("[LeakLens] File scan failed:", err);
            showErrorOverlay("File scan failed. Is the backend running?");
        } finally {
            scanFileButton.disabled = false;
            scanFileButton.textContent = "Scan file";
        }
    });
}

// --- Initialize ---
setupChatInterception();
setupFileScanning();
console.log("[LeakLens] Chat + file scanning ready.");