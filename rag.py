import re
import tree_sitter_java
from tree_sitter import Parser, Language

# ==========================================
# 1. LOCAL RAG CWE DATABASE
# ==========================================
VULNERABILITY_DB = {
    "Cross-Site Scripting (XSS)": {
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page served to other users.",
        "remediation": "Use context-aware HTML entity encoding (e.g., OWASP Java Encoder), framework-provided safe rendering (e.g., Thymeleaf HTML escaping), or sanitize input using libraries like Jsoup."
    },
    "SQL Injection": {
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The software constructs all or part of an SQL command using externally-influenced input, but it does not neutralize or incorrectly neutralizes the input.",
        "remediation": "Always use Parameterized Queries (PreparedStatement) instead of string concatenation. Never construct dynamic SQL queries from untrusted user inputs."
    },
    "Buffer Overflow": {
        "cwe": "CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "description": "The program copies an input buffer to a destination buffer without verifying that the size of the input buffer is less than the size of the destination buffer.",
        "remediation": "Ensure manual bounds and size checks are executed before copying arrays, using unsafe, or copying raw ByteBuffer allocations."
    },
    "Command Injection": {
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "description": "The software constructs an OS command using externally-influenced input but does not neutralize special command shell characters.",
        "remediation": "Avoid executing operating system shells directly. Use Java's native API alternatives. If unavoidable, use ProcessBuilder and pass arguments as separate array elements."
    },
    "Path Traversal": {
        "cwe": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": "The software uses external input to construct a pathname intended to identify a file or directory under a restricted directory, allowing file-system breakout ('..').",
        "remediation": "Normalize paths using File.getCanonicalPath() and verify that the canonical path begins with the allowed base directory prefix."
    },
    "Insecure Deserialization": {
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "description": "The application deserializes untrusted data without sufficient verification of the resulting data, leading to remote code execution (RCE).",
        "remediation": "Avoid native Java serialization for untrusted inputs. Use safe serialization schemas like JSON or Protobuf. If native deserialization is required, override resolveClass in ObjectInputStream to restrict classes to an allowlist."
    },
    "Secure Code": {
        "cwe": "Secure Code Architecture Verified",
        "description": "The code contains robust security countermeasures, validated input parsing, or parameterized execution, conforming to standard OWASP secure development practices.",
        "remediation": "No remediation required. The implementation is secure and handles inputs safely."
    }
}

KEYWORDS_MAP = {
    "Insecure Deserialization": [
        r"ObjectInputStream", r"readObject\s*\(", r"XMLDecoder"
    ],
    "Path Traversal": [
        r"FileInputStream", r"FileOutputStream", r"\.\."
    ],
    "SQL Injection": [
        r"Statement", r"executeQuery\s*\(", r"Connection\.createStatement", r"SELECT.*FROM", r"INSERT.*INTO"
    ],
    "Command Injection": [
        r"Runtime\.getRuntime\(\)\.exec", r"ProcessBuilder", r"exec\s*\("
    ],
    "Cross-Site Scripting (XSS)": [
        r"PrintWriter", r"getWriter\(\)", r"response\.write"
    ],
    "Buffer Overflow": [
        r"ByteBuffer", r"unsafe", r"System\.arraycopy"
    ]
}

def detect_vulnerability_type(code_content: str) -> str:
    """Uses regex heuristics to classify the vulnerability type in the code snippet."""
    if not code_content.strip():
        return "Secure Code"
        
    # Check if the code is already secure
    if "PreparedStatement" in code_content or "conn.prepareStatement" in code_content:
        return "Secure Code"
    if "getCanonicalPath" in code_content and "startsWith" in code_content:
        return "Secure Code"
        
    for vuln_type, patterns in KEYWORDS_MAP.items():
        for pattern in patterns:
            if re.search(pattern, code_content, re.IGNORECASE):
                if vuln_type == "Path Traversal" and "getCanonicalPath" in code_content:
                    continue
                return vuln_type
                
    return "Secure Code"

def retrieve_vulnerability_info(vuln_type: str) -> dict:
    """Retrieves MITRE CWE metadata for the specified vulnerability type."""
    return VULNERABILITY_DB.get(vuln_type, VULNERABILITY_DB["Secure Code"])

def build_augmented_prompt(code_content: str, vuln_type: str = None) -> tuple:
    """Combines the code snippet and the retrieved RAG metadata into an optimized system/user message list."""
    if not vuln_type or vuln_type == "Secure Code":
        vuln_type = detect_vulnerability_type(code_content)
        
    system_prompt = """You are an expert Java security auditor. Analyze the provided code.
If the code is secure, output:
"This Java code is completely secure and contains no vulnerabilities. No changes are required."

If the code is vulnerable, output your analysis in this exact format:
### 🛡️ Vulnerability Analysis
*   **Status**: VULNERABLE
*   **Type**: [Vulnerability Type]
*   **Severity**: HIGH

### 📝 Explanation
[Provide a brief explanation of the vulnerability]

### 🛠️ Fixed Code
```java
[Fixed complete Java code]
```"""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Analyze the following Java code. If a vulnerability exists, provide the fixed code. If it is safe, output the original code.\n\n{code_content}"}
    ], vuln_type

# ==========================================
# 2. TREE-SITTER SYNTAX VALIDATION ENGINE
# ==========================================
def get_java_language():
    """Initializes and returns the tree-sitter Java language grammar."""
    lang_obj = tree_sitter_java.language()
    if not isinstance(lang_obj, Language):
        return Language(lang_obj)
    return lang_obj

def is_java_syntax_valid(code_content: str) -> bool:
    """Parses a Java code snippet and returns True if it has no syntax errors."""
    if not code_content.strip():
        return True
    try:
        lang = get_java_language()
        try:
            parser = Parser(lang)
        except TypeError:
            parser = Parser()
            try:
                parser.language = lang
            except AttributeError:
                parser.set_language(lang)
                
        tree = parser.parse(bytes(code_content, "utf8"))
        
        def has_parsing_error(node):
            if node.type == "ERROR" or node.is_missing:
                return True
            for child in node.children:
                if has_parsing_error(child):
                    return True
            return False
            
        return not has_parsing_error(tree.root_node)
    except Exception:
        return False
