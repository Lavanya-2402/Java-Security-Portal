// JS Controller for SecureCode AI

document.addEventListener("DOMContentLoaded", () => {
    const inputCode = document.getElementById("input-code");
    const remediatedCode = document.getElementById("remediated-code");
    const scanBtn = document.getElementById("scan-btn");
    const copyBtn = document.getElementById("copy-btn");
    const downloadBtn = document.getElementById("download-btn");
    const loadingOverlay = document.getElementById("loading-overlay");
    const loadingText = document.getElementById("loading-text");
    const resultsSection = document.getElementById("results-section");
    const statusBadges = document.getElementById("status-badges");
    const cweCard = document.getElementById("cwe-card");

    // Copy output code to clipboard
    copyBtn.addEventListener("click", () => {
        if (remediatedCode.value.trim() !== "") {
            remediatedCode.select();
            document.execCommand("copy");
            const originalText = copyBtn.innerText;
            copyBtn.innerText = "✅ Monospace Code Copied!";
            setTimeout(() => {
                copyBtn.innerText = originalText;
            }, 2000);
        }
    });

    // Download remediated Java code as file
    downloadBtn.addEventListener("click", () => {
        const code = remediatedCode.value;
        if (!code.trim()) return;
        
        // Match class name dynamically
        const classMatch = code.match(/class\s+(\w+)/);
        const className = classMatch ? classMatch[1] : "Remediated";
        const filename = `${className}.java`;
        
        const blob = new Blob([code], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    // Run Code Scan & Remediation via Background Task Polling
    scanBtn.addEventListener("click", async () => {
        const code = inputCode.value.trim();
        if (!code) {
            alert("Please paste some Java code before scanning!");
            return;
        }

        // Show loading state
        loadingOverlay.classList.remove("hidden");
        loadingText.innerText = "Initializing scan on AMD GPU...";
        
        try {
            // 1. Submit relative POST request to start background task
            const res = await fetch("api/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ code: code })
            });

            if (!res.ok) {
                throw new Error(`Server returned error: ${res.statusText}`);
            }

            const data = await res.json();
            const taskId = data.task_id;
            
            // 2. Start polling the task status every 2 seconds
            pollTaskStatus(taskId);

        } catch (err) {
            console.error(err);
            alert(`Scan failed to start: ${err.message}`);
            loadingOverlay.classList.add("hidden");
        }
    });

    // Poll status endpoint recursively
    async function pollTaskStatus(taskId) {
        try {
            const res = await fetch(`api/tasks/${taskId}`);
            if (!res.ok) {
                throw new Error(`Failed to check task: ${res.statusText}`);
            }

            const task = await res.json();
            
            if (task.status === "processing") {
                loadingText.innerText = "Analyzing code and running GPU inference (this may take 10-25s)...";
                // Poll again in 2 seconds
                setTimeout(() => pollTaskStatus(taskId), 2000);
            } 
            else if (task.status === "completed") {
                // Task finished successfully!
                loadingOverlay.classList.add("hidden");
                renderResults(task.result);
            } 
            else if (task.status === "failed") {
                // Task execution failed on the GPU backend
                throw new Error(task.error || "Unknown backend error");
            }
        } catch (err) {
            console.error(err);
            alert(`GPU Model connection failed: ${err.message}`);
            loadingOverlay.classList.add("hidden");
        }
    }

    // Helper to escape HTML characters
    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Render results in the UI
    function renderResults(result) {
        remediatedCode.value = result.fixed_code;
        
        const isFallbackExp = result.explanation.includes("Vulnerability detected");
        const safeExplanation = escapeHtml(result.explanation);
        const safeRawOutput = escapeHtml(result.raw_output || "");
        
        let explanationHtml = "";
        if (!isFallbackExp && result.explanation.trim()) {
            explanationHtml = `
                <div style="margin-top: 15px; border-top: 1px solid var(--border-color); padding-top: 15px;">
                    <h5 style="margin: 0 0 8px 0; color: #c084fc; font-size: 0.95rem; font-weight: 700;">📝 Detailed Vulnerability & Fix Analysis</h5>
                    <p style="margin: 0; font-size: 0.92rem; line-height: 1.5; color: #e2e8f0; white-space: pre-wrap; text-align: left;">${safeExplanation}</p>
                </div>
            `;
        }

        const rawOutputHtml = result.raw_output ? `
            <details style="margin-top: 15px; border-top: 1px solid var(--border-color); padding-top: 12px;">
                <summary style="cursor: pointer; color: var(--text-secondary); font-size: 0.8rem; font-weight: 600; outline: none; user-select: none;">🤖 View Raw GPU Model Output</summary>
                <pre style="margin-top: 10px; white-space: pre-wrap; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.82rem; color: #a5b4fc; background: #030712; padding: 12px; border-radius: 6px; border: 1px solid var(--border-color); max-height: 250px; overflow-y: auto; text-align: left;">${safeRawOutput}</pre>
            </details>
        ` : '';

        // Render CWE metadata, explanation, and raw output in a single unified card
        cweCard.innerHTML = `
            <h4>CWE Reference Guidelines</h4>
            <p><strong>Description:</strong> ${result.description}</p>
            <p style="margin-bottom: 0; color: #34d399;"><strong>Mitigation Guide:</strong> ${result.remediation}</p>
            ${explanationHtml}
            ${rawOutputHtml}
        `;

        // Render Status Badges
        const severityClass = result.severity === "SECURE" ? "badge-secure" : "badge-vulnerable";
        const syntaxClass = result.is_valid ? "badge-syntax-valid" : "badge-syntax-error";
        
        statusBadges.innerHTML = `
            <span class="badge ${severityClass}">Severity: ${result.severity}</span>
            <span class="badge badge-vulnerable">CWE: ${result.cwe}</span>
            <span class="badge ${syntaxClass}">${result.validation_status}</span>
        `;

        // Reveal results section
        resultsSection.classList.remove("hidden");
        resultsSection.scrollIntoView({ behavior: "smooth" });
    }
});
