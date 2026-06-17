import os
import re
import sys
import torch
import gradio as gr

# Ensure local imports work regardless of execution context
try:
    from security_portal.rag import (
        detect_vulnerability_type,
        retrieve_vulnerability_info,
        build_augmented_prompt,
        is_java_syntax_valid
    )
except ImportError:
    from rag import (
        detect_vulnerability_type,
        retrieve_vulnerability_info,
        build_augmented_prompt,
        is_java_syntax_valid
    )

# 1. Mock deepgemm to avoid ROCm warnings/crashes
from unittest.mock import MagicMock
sys.modules['transformers.integrations.deepgemm'] = MagicMock()

MODEL_ID = "Qwen/Qwen2.5-Coder-32B-Instruct"

# Try multiple candidate paths to find the adapter weights directory
ADAPTER_PATH_CANDIDATES = [
    # 1. Parent directory level (where the notebooks live)
    "/workspace/shared/lavanya/Java-Dataset-New/java-dataset/java-vuln-adapter-32b-full",
    "../java-vuln-adapter-32b-full",
    "../../java-vuln-adapter-32b-full",
    # 2. Inside the current working directory
    "./java-vuln-adapter-32b-full",
    # 3. Old FastAPI session path
    "/workspace/shared/lavanya/Java-Dataset-New/java-dataset/RAG-Implemenation/java-vuln-adapter-32b-full"
]

ADAPTER_PATH = None
for candidate in ADAPTER_PATH_CANDIDATES:
    abs_candidate = os.path.abspath(candidate)
    if os.path.exists(abs_candidate) and os.path.exists(os.path.join(abs_candidate, "adapter_config.json")):
        ADAPTER_PATH = abs_candidate
        print(f"🎯 Successfully resolved model adapter path to: {ADAPTER_PATH}")
        break

if ADAPTER_PATH is None:
    # Default fallback if not found anywhere (so it prints the absolute path in the logs)
    ADAPTER_PATH = os.path.abspath(ADAPTER_PATH_CANDIDATES[0])
    print(f"⚠️ Warning: Could not find adapter directory. Falling back to: {ADAPTER_PATH}")

# ==========================================
# 2. MODEL LOADING & INFERENCE
# ==========================================
_global_model = None
_global_tokenizer = None

def get_model_and_tokenizer():
    """Checks the global notebook scope for model/tokenizer or loads them standalone."""
    global _global_model, _global_tokenizer
    
    if _global_model is not None and _global_tokenizer is not None:
        return _global_model, _global_tokenizer
        
    # Attempt to resolve from Jupyter notebook main kernel namespace
    try:
        import __main__
        if hasattr(__main__, 'model') and hasattr(__main__, 'tokenizer'):
            print("🔗 Connected to existing model and tokenizer found in Jupyter kernel namespace.")
            _global_model = __main__.model
            _global_tokenizer = __main__.tokenizer
            return _global_model, _global_tokenizer
    except Exception as e:
        print(f"Jupyter context check failed: {e}")

    # Fallback: Load model locally on the GPU
    print("🚀 Initializing model standalone (native bfloat16 on GPU)...")
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel
    
    _global_tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    _global_tokenizer.pad_token = _global_tokenizer.eos_token
    
    base_model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        device_map="auto",
        torch_dtype=torch.bfloat16
    )
    _global_model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
    _global_model.config.use_cache = True
    _global_model.eval()
    
    print("✅ Standalone GPU Model loaded successfully!")
    return _global_model, _global_tokenizer

def extract_content(output_text: str) -> tuple:
    """Extracts explanation and code block from the model's output structured format."""
    explanation_match = re.search(r"### 📝 Explanation\s*(.*?)\s*(### 🛠️|$)", output_text, re.DOTALL)
    explanation = explanation_match.group(1).strip() if explanation_match else "No explanation provided."
    
    code_match = re.search(r"```java\s*(.*?)\s*```", output_text, re.DOTALL)
    code = code_match.group(1).strip() if code_match else ""
    
    if not code:
        code_match = re.search(r"```\s*(.*?)\s*```", output_text, re.DOTALL)
        code = code_match.group(1).strip() if code_match else ""
        
    return explanation, code

def perform_remediation(input_code: str) -> tuple:
    """Full pipeline: classification, RAG lookup, LLM inference, parsing, and AST validation."""
    if not input_code.strip():
        return (
            "Please provide a Java code snippet.",
            "",
            gr.update(value="<span class='badge badge-syntax-error'>⚠️ No Input</span>", visible=True),
            gr.update(value=""),
            gr.update(visible=False)
        )
        
    try:
        model_obj, tokenizer_obj = get_model_and_tokenizer()
    except Exception as e:
        return (
            f"Failed to connect to GPU model. Make sure the model variables are loaded in your notebook: {str(e)}",
            "",
            gr.update(value=f"<span class='badge badge-vulnerable'>❌ Connection Error</span>"),
            gr.update(value=""),
            gr.update(visible=False)
        )
        
    detected_cat = detect_vulnerability_type(input_code)
    messages, _ = build_augmented_prompt(input_code, detected_cat)
    
    prompt_text = tokenizer_obj.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer_obj(prompt_text, return_tensors="pt").to(model_obj.device)
    
    with torch.no_grad():
        outputs = model_obj.generate(
            **inputs,
            max_new_tokens=512,
            temperature=0.1,
            do_sample=True,
            use_cache=True,
            pad_token_id=tokenizer_obj.eos_token_id
        )
        
    generated_text = tokenizer_obj.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    
    is_secure = "completely secure" in generated_text.lower() or "no changes are required" in generated_text.lower()
    
    if is_secure:
        final_cat = "Secure Code"
        explanation = "This Java code is completely secure and contains no vulnerabilities. No changes are required."
        fixed_code = input_code
    else:
        explanation, fixed_code = extract_content(generated_text)
        
        type_match = re.search(r"\*\s+\*\*Type\*\*:\s*([^\n\r]+)", generated_text, re.IGNORECASE)
        if type_match:
            final_cat = type_match.group(1).strip()
        else:
            final_cat = detected_cat

    cwe_info = retrieve_vulnerability_info(final_cat)
    is_valid = is_java_syntax_valid(fixed_code)
    
    severity = "SECURE" if final_cat == "Secure Code" else "HIGH"
    severity_class = "badge-secure" if severity == "SECURE" else "badge-vulnerable"
    syntax_class = "badge-syntax-valid" if is_valid else "badge-syntax-error"
    syntax_text = "✅ Validated (Tree-Sitter Clean)" if is_valid else "⚠️ Syntax Warning (Parse Error)"
    
    status_html = f"""
    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
        <span class="badge {severity_class}">Severity: {severity}</span>
        <span class="badge badge-vulnerable">CWE Classification: {cwe_info['cwe']}</span>
        <span class="badge {syntax_class}">{syntax_text}</span>
    </div>
    """
    
    cwe_card_html = f"""
    <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 15px; margin-top: 10px;">
        <h4 style="margin: 0 0 8px 0; color: #b0a8d4; font-size: 1rem;">CWE Reference Guidelines</h4>
        <p style="margin: 0 0 10px 0; font-size: 0.9rem; line-height: 1.4; color: #e2e8f0;"><strong>Description:</strong> {cwe_info['description']}</p>
        <p style="margin: 0; font-size: 0.9rem; line-height: 1.4; color: #a7f3d0;"><strong>Mitigation Guide:</strong> {cwe_info['remediation']}</p>
    </div>
    """
    
    return (
        explanation,
        fixed_code,
        gr.update(value=status_html, visible=True),
        gr.update(value=cwe_card_html, visible=True),
        gr.update(visible=True)
    )

# ==========================================
# 3. GRADIO APPLICATION DESIGN & STYLING
# ==========================================
custom_css = """
.container { 
    max-width: 1300px; 
    margin: 0 auto; 
    padding: 10px; 
}
.header-banner {
    background: linear-gradient(135deg, #1e1b4b, #4c1d95, #0f0c1b);
    border-radius: 12px;
    padding: 25px;
    margin-bottom: 20px;
    text-align: center;
    border: 1px solid rgba(255, 255, 255, 0.08);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
}
.header-banner h1 {
    color: #ffffff;
    font-size: 2.0rem;
    margin: 0;
    font-family: system-ui, -apple-system, sans-serif;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(to right, #ffffff, #c084fc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.header-banner p {
    color: #c084fc;
    font-size: 0.95rem;
    margin-top: 6px;
    margin-bottom: 0;
    font-weight: 500;
}
.badge {
    display: inline-block;
    padding: 5px 12px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.85rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
}
.badge-vulnerable { 
    background-color: rgba(239, 68, 68, 0.15); 
    color: #f87171; 
    border-color: rgba(239, 68, 68, 0.3); 
}
.badge-secure { 
    background-color: rgba(16, 185, 129, 0.15); 
    color: #34d399; 
    border-color: rgba(16, 185, 129, 0.3); 
}
.badge-syntax-valid { 
    background-color: rgba(59, 130, 246, 0.15); 
    color: #60a5fa; 
    border-color: rgba(59, 130, 246, 0.3); 
}
.badge-syntax-error { 
    background-color: rgba(245, 158, 11, 0.15); 
    color: #fbbf24; 
    border-color: rgba(245, 158, 11, 0.3); 
}
"""

theme = gr.themes.Soft(
    primary_hue="violet",
    secondary_hue="slate",
    neutral_hue="slate"
).set(
    body_background_fill="#0b0f19",
    block_background_fill="#111827",
    block_border_color="#1f2937",
    button_primary_background_fill="linear-gradient(90deg, #6d28d9, #7c3aed)",
    button_primary_background_fill_hover="linear-gradient(90deg, #7c3aed, #8b5cf6)",
    button_primary_text_color="#ffffff"
)

# Example Snippets
examples_list = [
    [
        "// SQL Injection Example\npublic void getUser(String userId) throws SQLException {\n    String query = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";\n    Statement stmt = connection.createStatement();\n    ResultSet rs = stmt.executeQuery(query);\n}"
    ],
    [
        "// Path Traversal Example\npublic File getProfilePicture(String filename) {\n    File baseDir = new File(\"/var/www/uploads\");\n    return new File(baseDir, filename);\n}"
    ],
    [
        "// Command Injection Example\npublic void pingHost(String host) throws IOException {\n    String command = \"ping -c 3 \" + host;\n    Runtime.getRuntime().exec(command);\n}"
    ],
    [
        "// Cross-Site Scripting (XSS) Example\npublic void renderUser(HttpServletRequest request, HttpServletResponse response) throws IOException {\n    String name = request.getParameter(\"name\");\n    response.getWriter().write(\"<html><body><h1>Hello \" + name + \"</h1></body></html>\");\n}"
    ],
    [
        "// Insecure Deserialization Example\npublic Object deserializeData(byte[] data) throws Exception {\n    ByteArrayInputStream bais = new ByteArrayInputStream(data);\n    ObjectInputStream ois = new ObjectInputStream(bais);\n    return ois.readObject();\n}"
    ],
    [
        "// Buffer Overflow Example\npublic void copyData(byte[] source) {\n    ByteBuffer buffer = ByteBuffer.allocate(10);\n    System.arraycopy(source, 0, buffer.array(), 0, source.length);\n}"
    ],
    [
        "// Secure Code Example\npublic void getUserSecure(String userId) throws SQLException {\n    String query = \"SELECT * FROM users WHERE id = ?\";\n    PreparedStatement pstmt = connection.prepareStatement(query);\n    pstmt.setString(1, userId);\n    ResultSet rs = pstmt.executeQuery();\n}"
    ]
]

# Create Gradio blocks layout
with gr.Blocks(title="AMD Instinct™ Java Security Portal") as demo:
    with gr.Column(elem_classes="container"):
        gr.HTML("""
        <div class="header-banner">
            <h1>AMD Instinct™ Java Security Portal</h1>
            <p>Fine-Tuned 32B Model & RAG-Augmented Remediation Pipeline</p>
        </div>
        """)
        
        with gr.Row():
            with gr.Column(scale=1):
                input_code = gr.Code(
                    label="Input Java Code",
                    lines=14
                )
                scan_btn = gr.Button("🔍 Scan & Remediate Code", variant="primary")
            
            with gr.Column(scale=1):
                remediated_code = gr.Code(
                    label="Remediated Java Code",
                    lines=14,
                    interactive=False
                )
        
        status_badges = gr.HTML(
            value="<div style='color: #6b7280; font-size: 0.9rem;'>Submit code to view scan results.</div>",
            visible=True
        )
        
        cwe_reference = gr.HTML(visible=False)
        
        with gr.Group(visible=False) as explanation_group:
            gr.Markdown("### 📝 Detailed Vulnerability & Fix Analysis")
            explanation_box = gr.Markdown()
            
        gr.Examples(
            examples=examples_list,
            inputs=[input_code],
            label="Interactive Vulnerability Snippets (Click to Load)"
        )
        
        scan_btn.click(
            fn=perform_remediation,
            inputs=[input_code],
            outputs=[explanation_box, remediated_code, status_badges, cwe_reference, explanation_group],
            show_progress="full"
        )

# Standalone execution
if __name__ == "__main__":
    demo.launch(theme=theme, css=custom_css, server_name="0.0.0.0", server_port=8001, share=True)
