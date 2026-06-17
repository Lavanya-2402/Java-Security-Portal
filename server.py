import os
import re
import sys
import uuid
import threading
import torch
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# Ensure local imports work regardless of execution context
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from rag import detect_vulnerability_type, retrieve_vulnerability_info, build_augmented_prompt, is_java_syntax_valid

# Mock deepgemm to avoid ROCm warnings/crashes
from unittest.mock import MagicMock
sys.modules['transformers.integrations.deepgemm'] = MagicMock()

MODEL_ID = "Qwen/Qwen2.5-Coder-32B-Instruct"
ADAPTER_PATH = "/workspace/shared/lavanya/Java-Dataset-New/java-dataset/RAG-Implemenation/java-vuln-adapter-32b-full"

app = FastAPI(title="AMD Instinct™ Java Security Portal Backend")

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# MODEL LOADER & CACHING
# ==========================================
_global_model = None
_global_tokenizer = None

def get_model_and_tokenizer():
    """Loads tokenizer and PEFT model weights standalone on GPU."""
    global _global_model, _global_tokenizer
    
    if _global_model is not None and _global_tokenizer is not None:
        return _global_model, _global_tokenizer
        
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

# ==========================================
# ASYNCHRONOUS TASK QUEUE SYSTEM
# ==========================================
ACTIVE_TASKS = {}

class AnalyzeRequest(BaseModel):
    code: str

def run_remediation_task(task_id: str, code_content: str):
    """Background thread worker to execute inference and syntax check."""
    try:
        model_obj, tokenizer_obj = get_model_and_tokenizer()
        
        # 1. Run heuristic auto-classification
        category = detect_vulnerability_type(code_content)
        
        # 2. Build augmented prompt
        messages, _ = build_augmented_prompt(code_content, category)
        
        # 3. Model Inference
        prompt_text = tokenizer_obj.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer_obj(prompt_text, return_tensors="pt").to(model_obj.device)
        
        with torch.no_grad():
            outputs = model_obj.generate(
                **inputs,
                max_new_tokens=1200,
                do_sample=False,
                use_cache=True,
                pad_token_id=tokenizer_obj.eos_token_id
            )
            
        generated_text = tokenizer_obj.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
        
        print("\n=================== DEBUG: MODEL GENERATED TEXT ===================")
        print(generated_text)
        print("===================================================================\n")
        
        # 4. Parse Results
        is_secure = "completely secure" in generated_text.lower() or "no changes are required" in generated_text.lower()
        
        if is_secure:
            final_cat = "Secure Code"
            explanation = "This Java code is completely secure and contains no vulnerabilities. No changes are required."
            fixed_code = code_content
        else:
            explanation, fixed_code = extract_content(generated_text)
            
            print("\n=================== DEBUG: PARSED CONTENT ===================")
            print(f"EXPLANATION:\n{explanation}\n")
            print(f"FIXED CODE:\n{fixed_code}")
            print("=============================================================\n")
            
            # If the fixed code is identical to the input code, it means no changes were made (already secure)
            if fixed_code.strip() == code_content.strip():
                final_cat = "Secure Code"
                explanation = "This Java code is secure. No vulnerability was detected or remediation required."
            else:
                # Extract vulnerability type override from LLM finding section
                type_match = re.search(r"\*\s+\*\*Type\*\*:\s*([^\n\r]+)", generated_text, re.IGNORECASE)
                if type_match:
                    final_cat = type_match.group(1).strip()
                else:
                    final_cat = category
                
        cwe_info = retrieve_vulnerability_info(final_cat)
        
        # 5. Tree-Sitter validator check
        is_valid = is_java_syntax_valid(fixed_code)
        
        severity_label = "SECURE" if final_cat == "Secure Code" else "HIGH"
        validation_status = "Validated (Tree-Sitter Clean)" if is_valid else "Syntax Warning (Parse Error)"
        
        ACTIVE_TASKS[task_id] = {
            "status": "completed",
            "result": {
                "vulnerability_type": final_cat,
                "cwe": cwe_info["cwe"] if cwe_info else "CWE-Unknown",
                "description": cwe_info["description"] if cwe_info else "No description available.",
                "remediation": cwe_info["remediation"] if cwe_info else "No remediation guideline.",
                "severity": severity_label,
                "explanation": explanation,
                "fixed_code": fixed_code,
                "validation_status": validation_status,
                "is_valid": is_valid,
                "raw_output": generated_text
            }
        }
        print(f"Task {task_id} completed successfully.")
    except Exception as e:
        print(f"Task {task_id} failed: {e}")
        ACTIVE_TASKS[task_id] = {
            "status": "failed",
            "error": str(e)
        }

@app.on_event("startup")
def startup_event():
    """Load model on startup (main thread) so that background threads run safely."""
    print("⏳ Pre-loading GPU model on startup...")
    get_model_and_tokenizer()

@app.post("/api/analyze")
async def analyze_code(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    """Triggers analysis in a background task and returns immediately with a task_id."""
    code_content = request.code
    task_id = str(uuid.uuid4())
    
    ACTIVE_TASKS[task_id] = {
        "status": "processing",
        "result": None
    }
    
    # Start task in background thread so the HTTP request completes instantly
    background_tasks.add_task(run_remediation_task, task_id, code_content)
    
    return {
        "task_id": task_id,
        "status": "processing"
    }

@app.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str):
    """Retrieves status and results of a background task."""
    if task_id not in ACTIVE_TASKS:
        raise HTTPException(status_code=404, detail="Task not found")
        
    return ACTIVE_TASKS[task_id]

# Mount static frontend files
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # Defaults to port 8001 to bypass port 8000 kernel issues
    print("Starting uvicorn server on http://127.0.0.1:8001")
    uvicorn.run(app, host="127.0.0.1", port=8001)
