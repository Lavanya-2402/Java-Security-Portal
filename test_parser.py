import sys
import os
import re
import torch

# Add path so imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from server import get_model_and_tokenizer
from rag import detect_vulnerability_type

def extract_content(output_text: str) -> tuple:
    # 1. Clean up separator lines
    output_text = re.sub(r"^[─═]+$", "", output_text, flags=re.MULTILINE)
    
    # 2. Extract code block
    code = ""
    # Try to find code block inside backticks first
    code_match = re.search(r"```(?:java)?\s*(.*?)(?:```|$)", output_text, re.DOTALL | re.IGNORECASE)
    if code_match and len(code_match.group(1).strip()) > 50:
        code = code_match.group(1).strip()
        
    if not code:
        # If no backticks, look for code block starting with import or class declaration
        code_start_match = re.search(
            r"((?:import\s+[a-z0-9_.]+;\s*)+(?:public\s+)?class\s+\w+.*|(?:public\s+)?class\s+\w+.*)", 
            output_text, 
            re.DOTALL | re.IGNORECASE
        )
        if code_start_match:
            code = code_start_match.group(1).strip()
            
    # 3. Extract explanation
    explanation = ""
    explanation_match = re.search(
        r"#+\s*.*Explanation\s*(.*?)\s*(#+\s*.*Fixed Code|#+\s*.*Code|```(?:java)?|$)", 
        output_text, 
        re.DOTALL | re.IGNORECASE
    )
    if explanation_match:
        explanation = explanation_match.group(1).strip()
        
    if explanation:
        explanation = re.sub(r"```(?:java)?", "", explanation, flags=re.IGNORECASE).strip()
        
    # If explanation is empty or contains the Java code itself (swapped case)
    if not explanation or "class " in explanation or "import " in explanation:
        temp_text = output_text
        if code:
            parts = output_text.split(code)
            temp_text = parts[0]
            
        temp_text = re.sub(r"#+\s*.*Finding\s*\d+", "", temp_text, flags=re.IGNORECASE)
        temp_text = re.sub(r"#+\s*.*Vulnerability\s*Analysis", "", temp_text, flags=re.IGNORECASE)
        temp_text = re.sub(r"#+\s*.*Explanation", "", temp_text, flags=re.IGNORECASE)
        temp_text = re.sub(r"#+\s*.*Fixed\s*Code", "", temp_text, flags=re.IGNORECASE)
        temp_text = re.sub(r"\*\s+\*\*Status\*\*:\s*.*", "", temp_text, flags=re.IGNORECASE)
        temp_text = re.sub(r"\*\s+\*\*Type\*\*:\s*.*", "", temp_text, flags=re.IGNORECASE)
        temp_text = re.sub(r"\*\s+\*\*Severity\*\*:\s*.*", "", temp_text, flags=re.IGNORECASE)
        temp_text = re.sub(r"```(?:java)?", "", temp_text, flags=re.IGNORECASE)
        
        explanation = temp_text.strip()
        
    if not explanation or len(explanation) < 10:
        explanation = "Vulnerability detected. Review the remediated code block above for mitigation fixes."
        
    return explanation, code

# =====================================================================
# Standalone build_augmented_prompt with notebook's exact prompts
# =====================================================================
def build_augmented_prompt(code_content: str, vuln_type: str = None) -> tuple:
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

# Sample vulnerable code
sample_code = """
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProductSearchService {
    private final Connection conn;
    public ProductSearchService(Connection conn) {
        this.conn = conn;
    }
    public ResultSet search(String category, double minPrice) throws SQLException {
        String sql = String.format(
            "SELECT * FROM products WHERE category = '%s' AND price >= %.2f",
            category, minPrice
        );
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"""

def test_inference_and_parse():
    print("⏳ Loading model on GPU...")
    model_obj, tokenizer_obj = get_model_and_tokenizer()
    
    category = detect_vulnerability_type(sample_code)
    messages, _ = build_augmented_prompt(sample_code, category)
    
    prompt_text = tokenizer_obj.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer_obj(prompt_text, return_tensors="pt").to(model_obj.device)
    
    print("⏳ Running inference...")
    with torch.no_grad():
        outputs = model_obj.generate(
            **inputs,
            max_new_tokens=1200,
            do_sample=False,
            use_cache=True,
            pad_token_id=tokenizer_obj.eos_token_id
        )
        
    generated_text = tokenizer_obj.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    
    print("\n=================== RAW GENERATED TEXT FROM MODEL ===================")
    print(generated_text)
    print("=====================================================================\n")
    
    explanation, fixed_code = extract_content(generated_text)
    
    print("=================== PARSED RESULT ===================")
    print(f"EXPLANATION:\n{explanation}\n")
    print(f"FIXED CODE:\n{fixed_code}")
    print("=====================================================")

if __name__ == "__main__":
    test_inference_and_parse()
