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

    // Sidebar Toggles
    const sidebar = document.getElementById("sidebar");
    const sidebarToggleBtn = document.getElementById("sidebar-toggle-btn");
    const sidebarCloseBtn = document.getElementById("sidebar-close-btn");
    const historyList = document.getElementById("history-list");

    // View Modes Toggles
    const btnEditorView = document.getElementById("btn-editor-view");
    const btnDiffView = document.getElementById("btn-diff-view");
    const editorsLayout = document.getElementById("editors-layout");
    const diffLayout = document.getElementById("diff-layout");
    const diffContent = document.getElementById("diff-content");

    // SVG Gauge and Metrics
    const gaugeFill = document.getElementById("gauge-fill");
    const gaugeText = document.getElementById("gauge-text");
    const metricTime = document.getElementById("metric-time");
    const metricSpeed = document.getElementById("metric-speed");
    const metricResource = document.getElementById("metric-resource");

    // Scan History Store
    let scanHistory = [];

    // Sidebar event listeners
    sidebarToggleBtn.addEventListener("click", () => {
        sidebar.classList.toggle("collapsed");
    });
    sidebarCloseBtn.addEventListener("click", () => {
        sidebar.classList.add("collapsed");
    });

    // View toggles event listeners
    btnEditorView.addEventListener("click", () => {
        btnEditorView.classList.add("active");
        btnDiffView.classList.remove("active");
        editorsLayout.classList.remove("hidden");
        diffLayout.classList.add("hidden");
    });

    btnDiffView.addEventListener("click", () => {
        btnDiffView.classList.add("active");
        btnEditorView.classList.remove("active");
        editorsLayout.classList.add("hidden");
        diffLayout.classList.remove("hidden");
        renderDiff();
    });

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
        loadingText.innerText = "Initializing scan on GPU...";
        
        try {
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
            pollTaskStatus(taskId, code);

        } catch (err) {
            console.error(err);
            alert(`Scan failed to start: ${err.message}`);
            loadingOverlay.classList.add("hidden");
        }
    });

    // Poll status endpoint recursively
    async function pollTaskStatus(taskId, originalCode) {
        try {
            const res = await fetch(`api/tasks/${taskId}`);
            if (!res.ok) {
                throw new Error(`Failed to check task: ${res.statusText}`);
            }

            const task = await res.json();
            
            if (task.status === "processing") {
                loadingText.innerText = "Analyzing code and running GPU inference (this may take 10-25s)...";
                setTimeout(() => pollTaskStatus(taskId, originalCode), 2000);
            } 
            else if (task.status === "completed") {
                loadingOverlay.classList.add("hidden");
                renderResults(task.result);
                
                // Add successful scan to history list
                addToHistory(originalCode, task.result.fixed_code, task.result);
            } 
            else if (task.status === "failed") {
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

    // DP LCS Line-by-Line Diff Algorithm
    function computeLineDiff(oldText, newText) {
        const oldLines = oldText.split('\n');
        const newLines = newText.split('\n');
        const dp = Array(oldLines.length + 1).fill(null).map(() => Array(newLines.length + 1).fill(0));
        
        for (let i = 1; i <= oldLines.length; i++) {
            for (let j = 1; j <= newLines.length; j++) {
                if (oldLines[i-1].trim() === newLines[j-1].trim()) {
                    dp[i][j] = dp[i-1][j-1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i-1][j], dp[i][j-1]);
                }
            }
        }
        
        let i = oldLines.length;
        let j = newLines.length;
        const diff = [];
        
        while (i > 0 || j > 0) {
            if (i > 0 && j > 0 && oldLines[i-1].trim() === newLines[j-1].trim()) {
                diff.push({ type: 'normal', line: oldLines[i-1] });
                i--;
                j--;
            } else if (j > 0 && (i === 0 || dp[i][j-1] >= dp[i-1][j])) {
                diff.push({ type: 'add', line: newLines[j-1] });
                j--;
            } else {
                diff.push({ type: 'delete', line: oldLines[i-1] });
                i--;
            }
        }
        
        return diff.reverse();
    }

    function renderDiff() {
        const oldText = inputCode.value;
        const newText = remediatedCode.value;
        const diffs = computeLineDiff(oldText, newText);
        
        let html = "";
        diffs.forEach(item => {
            const safeLine = escapeHtml(item.line);
            if (item.type === 'add') {
                html += `<span class="diff-line addition">+ ${safeLine}</span>`;
            } else if (item.type === 'delete') {
                html += `<span class="diff-line deletion">- ${safeLine}</span>`;
            } else {
                html += `<span class="diff-line normal">  ${safeLine}</span>`;
            }
        });
        
        diffContent.innerHTML = html || "<span class='empty-diff'>No changes detected</span>";
    }

    // Add search result to scan history
    function addToHistory(inputVal, fixedVal, result) {
        const item = {
            id: Date.now(),
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            input: inputVal,
            fixed: fixedVal,
            result: result
        };
        
        scanHistory.unshift(item);
        renderHistoryList();
    }

    function renderHistoryList() {
        if (scanHistory.length === 0) {
            historyList.innerHTML = `<span class="empty-history">No scans recorded yet</span>`;
            return;
        }
        
        historyList.innerHTML = scanHistory.map(item => {
            const isSecure = item.result.severity === "SECURE";
            const badgeClass = isSecure ? "secure" : "vulnerable";
            const statusLabel = isSecure ? "Secure Code" : item.result.vulnerability_type;
            
            return `
                <div class="history-item" onclick="loadHistoryItem(${item.id})">
                    <div class="history-item-header">
                        <span class="history-item-type">${statusLabel}</span>
                        <span class="history-item-badge ${badgeClass}">${item.result.severity}</span>
                    </div>
                    <span class="history-item-time">🕒 ${item.time}</span>
                </div>
            `;
        }).join('');
    }

    window.loadHistoryItem = function(id) {
        const item = scanHistory.find(h => h.id === id);
        if (!item) return;
        
        inputCode.value = item.input;
        remediatedCode.value = item.fixed;
        renderResults(item.result);
        
        // Hide diff view and reset back to Editor View
        btnEditorView.click();
        sidebar.classList.add("collapsed");
    };

    // Render results in the UI
    function renderResults(result) {
        remediatedCode.value = result.fixed_code;
        
        const isFallbackExp = result.explanation.includes("Vulnerability detected");
        const safeExplanation = escapeHtml(result.explanation);
        
        let explanationHtml = "";
        if (!isFallbackExp && result.explanation.trim()) {
            explanationHtml = `
                <div style="margin-top: 15px; border-top: 1px solid var(--border-color); padding-top: 15px;">
                    <h5 style="margin: 0 0 8px 0; color: #c084fc; font-size: 0.95rem; font-weight: 700; text-align: left;">📝 Detailed Vulnerability & Fix Analysis</h5>
                    <p style="margin: 0; font-size: 0.92rem; line-height: 1.5; color: #e2e8f0; white-space: pre-wrap; text-align: left;">${safeExplanation}</p>
                </div>
            `;
        }

        // Render CWE metadata block and explanation
        cweCard.innerHTML = `
            <h4>CWE Reference Guidelines</h4>
            <p><strong>Description:</strong> ${result.description}</p>
            <p style="margin-bottom: 0; color: #34d399;"><strong>Mitigation Guide:</strong> ${result.remediation}</p>
            ${explanationHtml}
        `;

        // Render Status Badges (with interactive CWE links)
        const severityClass = result.severity === "SECURE" ? "badge-secure" : "badge-vulnerable";
        const syntaxClass = result.is_valid ? "badge-syntax-valid" : "badge-syntax-error";
        
        const cweMatch = result.cwe.match(/CWE-(\d+)/i);
        const cweId = cweMatch ? cweMatch[1] : "";
        const cweUrl = cweId ? `https://cwe.mitre.org/data/definitions/${cweId}.html` : "#";
        
        statusBadges.innerHTML = `
            <span class="badge ${severityClass}">Severity: ${result.severity}</span>
            <a href="${cweUrl}" target="_blank" class="badge badge-vulnerable hover-badge">CWE: ${result.cwe} 🔗</a>
            <span class="badge ${syntaxClass}">${result.validation_status}</span>
        `;

        // Animate circular risk SVG gauge
        const isSecure = result.severity === "SECURE";
        const riskPct = isSecure ? 0 : 95; // 0% risk for secure, 95% risk for vulnerable
        const dashOffset = 251.2 - (251.2 * riskPct / 100);
        gaugeFill.style.strokeDashoffset = dashOffset;
        gaugeFill.style.stroke = isSecure ? "var(--accent-emerald)" : "var(--accent-red)";
        gaugeText.textContent = `${riskPct}%`;

        // Populate execution metrics
        const m = result.metrics || { inference_time: "0.0", tokens_per_sec: "0", resource_status: "GPU Standalone" };
        metricTime.textContent = `${m.inference_time}s`;
        metricSpeed.textContent = `${m.tokens_per_sec} t/s`;
        metricResource.textContent = m.resource_status;

        // Reveal results section
        resultsSection.classList.remove("hidden");
        resultsSection.scrollIntoView({ behavior: "smooth" });
    }
});
