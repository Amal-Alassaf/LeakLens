// ============ LeakLens Content Script ============
console.log("[LeakLens] Content script loaded.");

// =========================
// Toast notification helpers
// =========================

function showToast(message, type = "info") {
    const oldToast = document.getElementById("leaklens-toast");
    if (oldToast) oldToast.remove();

    const toast = document.createElement("div");
    toast.id = "leaklens-toast";

    const themes = {
        block: {
            background: "#8b1a1a",
            border: "#ef4444",
            color: "#ffffff",
            icon: "⛔"
        },
        warning: {
            background: "#a16207",
            border: "#facc15",
            color: "#ffffff",
            icon: "⚠️"
        },
        redact: {
            background: "#1d4ed8",
            border: "#60a5fa",
            color: "#ffffff",
            icon: "✂️"
        },
        error: {
            background: "#7f1d1d",
            border: "#ef4444",
            color: "#ffffff",
            icon: "❌"
        },
        info: {
            background: "#1f2937",
            border: "#6b7280",
            color: "#ffffff",
            icon: "ℹ️"
        }
    };

    const theme = themes[type] || themes.info;

    toast.innerText = `${theme.icon} ${message}`;

    toast.style.position = "fixed";
    toast.style.top = "24px";
    toast.style.right = "24px";
    toast.style.zIndex = "999999";
    toast.style.background = theme.background;
    toast.style.border = `1px solid ${theme.border}`;
    toast.style.color = theme.color;
    toast.style.padding = "12px 18px";
    toast.style.borderRadius = "10px";
    toast.style.fontFamily = "Arial, sans-serif";
    toast.style.fontSize = "14px";
    toast.style.fontWeight = "700";
    toast.style.lineHeight = "1.4";
    toast.style.boxShadow = "0 10px 25px rgba(0,0,0,0.28)";
    toast.style.maxWidth = "360px";
    toast.style.whiteSpace = "normal";

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 5000);
}

function showOverlay(scanResult, policy) {
    if (!scanResult) return;

    if (scanResult.action_taken === "blocked") {
        showToast("Message blocked due to sensitive content", "block");
    } else if (scanResult.action_taken === "redacted") {
        showToast("Message was redacted before sending", "redact");
    } else if (scanResult.action_taken === "allowed_with_warning") {
        showToast("Message contains sensitive data", "warning");
    } else {
        showToast("Message passed LeakLens scan", "info");
    }
}

function showErrorOverlay(message) {
    showToast(message, "error");
}

function showWarningOverlay(message) {
    showToast(message, "warning");
}

function showBlockOverlay(message) {
    showToast(message, "block");
}

function showRedactOverlay(message) {
    showToast(message, "redact");
}

// =========================
// Local fallback scanner
// Used when backend is offline
// =========================

const LOCAL_REGEX_RULES = [
    {
        type: "email",
        regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        severity: "medium"
    },
    {
        type: "phone",
        regex: /(?:\+9665\d{8}|05\d{8}|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b)/g,
        severity: "medium"
    },
    {
        type: "credit_card",
        regex: /\b(?:\d{4}[- ]?){3}\d{4}\b/g,
        severity: "high"
    },
    {
        type: "ip_address",
        regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
        severity: "medium"
    },
    {
        type: "password",
        regex: /\b(password|pass|pwd)\s*[:=]\s*\S+/gi,
        severity: "high"
    },
    {
        type: "national_id",
        regex: /\b[12]\d{9}\b/g,
        severity: "high"
    },
    {
        type: "passport",
        regex: /\b[A-Z]\d{7}\b/g,
        severity: "high"
    }
];

async function scanTextLocalFallback(text, policy) {
    const detections = [];
    let redactedText = text;
    let isSafe = true;

    for (const rule of LOCAL_REGEX_RULES) {
        let match;
        rule.regex.lastIndex = 0;

        while ((match = rule.regex.exec(text)) !== null) {
            isSafe = false;

            const value = match[0];
            const redacted = `[${rule.type.toUpperCase()} REDACTED]`;

            detections.push({
                pii_type: rule.type,
                value,
                redacted,
                severity: rule.severity,
                confidence: 0.75,
                explanation: "Detected by local fallback regex scanner",
                source: "local_regex"
            });

            redactedText = redactedText.replace(value, redacted);
        }
    }

    let actionTaken = "allowed";
    let outputText = text;

    if (!isSafe) {
        if (policy === "block") {
            actionTaken = "blocked";
            outputText = "";
        } else if (policy === "redact") {
            actionTaken = "redacted";
            outputText = redactedText;
        } else {
            actionTaken = "allowed_with_warning";
            outputText = text;
        }
    }

    return {
        is_safe: isSafe,
        action_taken: actionTaken,
        risk_score: isSafe ? 0 : 1,
        detections,
        original_text: text,
        output_text: outputText,
        summary: isSafe
            ? "No sensitive info found locally."
            : "Local regex matched sensitive data."
    };
}

// =========================
// Backend helpers
// =========================

async function scanText(text, policy) {
    try {
        const response = await fetch("http://127.0.0.1:8000/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text, policy })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        return await response.json();
    } catch (err) {
        console.warn("[LeakLens] Backend unreachable. Falling back to local regex scanner.", err);
        return await scanTextLocalFallback(text, policy);
    }
}

async function scanFile(file, policy) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("policy", policy);

    const response = await fetch("http://127.0.0.1:8000/scan-file", {
        method: "POST",
        body: formData
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    return await response.json();
}

// =========================
// Policy
// =========================

async function getCurrentPolicy() {
    return new Promise((resolve) => {
        if (!chrome?.storage?.local) {
            resolve("redact");
            return;
        }

        chrome.storage.local.get(["leaklensPolicy"], function (result) {
            resolve(result.leaklensPolicy || "redact");
        });
    });
}

// =========================
// Demo page helpers
// =========================

function dispatchMessageToPage(text, policy) {
    const event = new CustomEvent("LeakLensMessage", {
        detail: { text, policy }
    });

    document.dispatchEvent(event);
}

function setupDemoChatInterception() {
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

            if (result.action_taken === "blocked") {
                showBlockOverlay("Message blocked due to sensitive content");
            } else if (result.action_taken === "redacted") {
                showRedactOverlay("Message was redacted before sending");
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
            console.error("[LeakLens] Demo chat scan failed:", err);

            showErrorOverlay("Scan failed. Sending message anyway.");
            dispatchMessageToPage(text, "error");

            messageInput.value = "";
            messageInput.focus();
        }
    });

    console.log("[LeakLens] Demo chat interception attached.");
}

function setupDemoFileScanning() {
    const fileInput = document.getElementById("fileInput");
    const scanFileButton = document.getElementById("scanFileButton");

    if (!fileInput || !scanFileButton) return;
    if (scanFileButton.dataset.leaklensFileAttached === "true") return;

    scanFileButton.dataset.leaklensFileAttached = "true";

    scanFileButton.addEventListener("click", async () => {
        const file = fileInput.files[0];

        if (!file) {
            showErrorOverlay("Please attach a file first.");
            return;
        }

        const allowedExt = [".txt", ".pdf", ".docx"];
        const fileName = file.name.toLowerCase();

        if (!allowedExt.some(ext => fileName.endsWith(ext))) {
            showErrorOverlay("Only .txt, .pdf, .docx files are supported.");
            return;
        }

        scanFileButton.disabled = true;
        scanFileButton.textContent = "Scanning file...";

        try {
            const policy = await getCurrentPolicy();

            let result;

            if (fileName.endsWith(".txt")) {
                const text = await file.text();
                result = await scanText(text, policy);
            } else {
                result = await scanFile(file, policy);
            }

            if (result.action_taken === "blocked") {
                showBlockOverlay("File blocked due to sensitive content");
            } else if (result.action_taken === "redacted") {
                showRedactOverlay("File content was redacted");
            } else if (result.action_taken === "allowed_with_warning") {
                showWarningOverlay("File contains sensitive data");
            } else {
                showToast("File scan completed", "info");
            }
        } catch (err) {
            console.error("[LeakLens] File scan failed:", err);
            showErrorOverlay("File scan failed. Is the backend running?");
        } finally {
            scanFileButton.disabled = false;
            scanFileButton.textContent = "Scan file";
        }
    });

    console.log("[LeakLens] Demo file scanning attached.");
}

// =========================
// LLM / ChatGPT-style helpers
// =========================

let leaklensAllowSend = false;

function redactInPlace(element, detections) {
    console.log("[LeakLens] redactInPlace called with", detections.length, "detections");

    const selection = window.getSelection();

    for (const detection of detections) {
        if (!detection.value || !detection.redacted) continue;

        let found = true;

        while (found) {
            found = false;

            const walker = document.createTreeWalker(
                element,
                NodeFilter.SHOW_TEXT,
                null,
                false
            );

            let node;

            while ((node = walker.nextNode())) {
                const index = node.nodeValue.indexOf(detection.value);

                if (index !== -1) {
                    const range = document.createRange();
                    range.setStart(node, index);
                    range.setEnd(node, index + detection.value.length);

                    selection.removeAllRanges();
                    selection.addRange(range);

                    document.execCommand("insertText", false, detection.redacted);

                    found = true;
                    break;
                }
            }
        }
    }

    console.log("[LeakLens] Redaction complete.");
}

function setPromptText(promptElement, text) {
    if (!promptElement) return;

    if (promptElement.isContentEditable) {
        promptElement.focus();
        promptElement.innerText = text;
        promptElement.dispatchEvent(new InputEvent("input", {
            bubbles: true,
            inputType: "insertText",
            data: text
        }));
    } else {
        promptElement.value = text;
        promptElement.dispatchEvent(new Event("input", { bubbles: true }));
    }
}

function getPromptText(promptElement) {
    if (!promptElement) return "";

    if (promptElement.isContentEditable) {
        return promptElement.innerText || promptElement.textContent || "";
    }

    return promptElement.value || "";
}

function getLLMPromptElement() {
    return (
        document.getElementById("prompt-textarea") ||
        document.querySelector('[contenteditable="true"]') ||
        document.querySelector("textarea")
    );
}

function getLLMSendButton() {
    return (
        document.querySelector('button[data-testid="send-button"]') ||
        document.querySelector('button[aria-label="Send prompt"]') ||
        document.querySelector('button[aria-label="Send message"]') ||
        document.querySelector('button[type="submit"]')
    );
}

async function interceptAndScanLLM(e) {
    console.log("[LeakLens] LLM intercept fired:", e.type);

    if (leaklensAllowSend) {
        console.log("[LeakLens] Allowing programmatic send.");
        return;
    }

    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    const promptElement = getLLMPromptElement();

    if (!promptElement) {
        console.error("[LeakLens] Could not find LLM prompt element.");
        showErrorOverlay("LeakLens could not find the chat input.");
        return;
    }

    const text = getPromptText(promptElement);

    if (!text.trim()) {
        return;
    }

    const policy = await getCurrentPolicy();

    try {
        const result = await scanText(text, policy);

        if (result.is_safe || result.action_taken === "allowed") {
            triggerLLMSend();
            return;
        }

        if (result.action_taken === "blocked") {
            showBlockOverlay("Message blocked by LeakLens");
            return;
        }

        if (result.action_taken === "redacted") {
            showRedactOverlay("Message was redacted before sending");

            if (result.output_text) {
                setPromptText(promptElement, result.output_text);
            } else if (promptElement.isContentEditable) {
                redactInPlace(promptElement, result.detections || []);
            }

            await new Promise(resolve => setTimeout(resolve, 150));
            triggerLLMSend();
            return;
        }

        if (result.action_taken === "allowed_with_warning") {
            showWarningOverlay("Message contains sensitive data");
            triggerLLMSend();
            return;
        }

        triggerLLMSend();
    } catch (err) {
        console.error("[LeakLens] LLM scan failed:", err);
        showErrorOverlay("LeakLens scan failed. Message sent as-is.");
        triggerLLMSend();
    }
}

function triggerLLMSend() {
    leaklensAllowSend = true;

    const sendButton = getLLMSendButton();

    if (sendButton) {
        sendButton.click();
    } else {
        console.error("[LeakLens] Send button not found.");
        showErrorOverlay("LeakLens could not find the send button.");
    }

    setTimeout(() => {
        leaklensAllowSend = false;
    }, 300);
}

function setupLLMChatInterception() {
    console.log("[LeakLens] Setting up LLM chat interception.");

    setInterval(() => {
        const promptElement = getLLMPromptElement();

        if (promptElement && promptElement.dataset.leaklensAttached !== "true") {
            promptElement.dataset.leaklensAttached = "true";

            promptElement.addEventListener(
                "keydown",
                (e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                        interceptAndScanLLM(e);
                    }
                },
                true
            );

            console.log("[LeakLens] Attached keydown listener to LLM prompt.");
        }

        const sendButton = getLLMSendButton();

        if (sendButton && sendButton.dataset.leaklensAttached !== "true") {
            sendButton.dataset.leaklensAttached = "true";

            sendButton.addEventListener(
                "click",
                (e) => {
                    if (!leaklensAllowSend) {
                        interceptAndScanLLM(e);
                    }
                },
                true
            );

            console.log("[LeakLens] Attached click listener to LLM send button.");
        }
    }, 1000);
}

// =========================
// Initialize
// =========================

setupDemoChatInterception();
setupDemoFileScanning();
setupLLMChatInterception();

console.log("[LeakLens] ===== Content script loaded and initialized =====");