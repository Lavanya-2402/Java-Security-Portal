import sys
import os
import re
import torch

# Add path so imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from server import extract_content, get_model_and_tokenizer
from rag import detect_vulnerability_type, build_augmented_prompt

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
            max_new_tokens=1024,
            temperature=0.1,
            do_sample=True,
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
