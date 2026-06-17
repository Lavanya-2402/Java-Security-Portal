// JS Controller for AMD Instinct Security Portal

const EXAMPLES = {
    sqli: `// SQL Injection Example
public void getUser(String userId) throws SQLException {
    String query = "SELECT * FROM users WHERE id = '" + userId + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
}`,
    path: `// Path Traversal Example
public File getProfilePicture(String filename) {
    File baseDir = new File("/var/www/uploads");
    return new File(baseDir, filename);
}`,
    cmd: `// Command Injection Example
public void pingHost(String host) throws IOException {
    String command = "ping -c 3 " + host;
    Runtime.getRuntime().exec(command);
}`,
    xss: `// Cross-Site Scripting (XSS) Example
public void renderUser(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String name = request.getParameter("name");
    response.getWriter().write("<html><body><h1>Hello " + name + "</h1></body></html>");
}`,
    deserial: `// Insecure Deserialization Example
public Object deserializeData(byte[] data) throws Exception {
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bais);
    return ois.readObject();
}`,
    buffer: `// Buffer Overflow Example
public void copyData(byte[] source) {
    ByteBuffer buffer = ByteBuffer.allocate(10);
    System.arraycopy(source, 0, buffer.array(), 0, source.length);
}`,
    secure: `// Secure Code Example
public void getUserSecure(String userId) throws SQLException {
    String query = "SELECT * FROM users WHERE id = ?";
    PreparedStatement pstmt = connection.prepareStatement(query);
    pstmt.setString(1, userId);
    ResultSet rs = pstmt.executeQuery();
}`
};

document.addEventListener("DOMContentLoaded", () => {
    const inputCode = document.getElementById("input-code");
    const remediatedCode = document.getElementById("remediated-code");
    const scanBtn = document.getElementById("scan-btn");
    const copyBtn = document.getElementById("copy-btn");
    const loadingOverlay = document.getElementById("loading-overlay");
    const loadingText = document.getElementById("loading-text");
    const resultsSection = document.getElementById("results-section");
    const statusBadges = document.getElementById("status-badges");
    const cweCard = document.getElementById("cwe-card");
    const explanationBox = document.getElementById("explanation-box");

    // Load example on button click
    document.querySelectorAll(".example-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const type = btn.getAttribute("data-type");
            if (EXAMPLES[type]) {
                inputCode.value = EXAMPLES[type];
                // Smooth scroll to input
                inputCode.scrollIntoView({ behavior: "smooth" });
            }
        });
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

    // Render results in the UI
    function renderResults(result) {
        remediatedCode.value = result.fixed_code;
        explanationBox.innerText = result.explanation;

        // Render Status Badges
        const severityClass = result.severity === "SECURE" ? "badge-secure" : "badge-vulnerable";
        const syntaxClass = result.is_valid ? "badge-syntax-valid" : "badge-syntax-error";
        
        statusBadges.innerHTML = `
            <span class="badge ${severityClass}">Severity: ${result.severity}</span>
            <span class="badge badge-vulnerable">CWE: ${result.cwe}</span>
            <span class="badge ${syntaxClass}">${result.validation_status}</span>
        `;

        // Render CWE metadata block
        cweCard.innerHTML = `
            <h4>CWE Reference Guidelines</h4>
            <p><strong>Description:</strong> ${result.description}</p>
            <p style="margin-bottom: 0; color: #34d399;"><strong>Mitigation Guide:</strong> ${result.remediation}</p>
        `;

        // Reveal results section
        resultsSection.classList.remove("hidden");
        resultsSection.scrollIntoView({ behavior: "smooth" });
    }
});
