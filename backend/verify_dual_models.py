
import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import get_settings
from backend.core.hugging_face_client import hf_client_ii
from backend.core.chatbot import SASTChatbot

async def verify_dual_models():
    settings = get_settings()
    print("=== Configuration ===")
    print(f"Repo Model: {hf_client_ii.repo_model}")
    print(f"Chat Model: {hf_client_ii.chat_model}")
    print(f"Configured: {hf_client_ii.is_configured}")
    print("====================\n")

    # Verify Chat (Qwen)
    print("1. Testing Chatbot (Expected: Qwen 7B)...")
    chatbot = SASTChatbot() 
    print(f"Chatbot Model: {chatbot.model}")
    
    chat_response = await chatbot._try_hf_ii([{"role": "user", "content": "Hello! Model check?"}])
    print(f"Chat Response: {chat_response}\n")

    # Verify Repo Analysis (Llama 3.3)
    print("2. Testing Repo Analysis (Expected: Llama 3.3)...")
    test_code = "def foo(): pass"
    
    analysis_result = await hf_client_ii.analyze_code(
        file_path="test.py", 
        code_content=test_code,
        bypass_rate_limit=True
    )
    
    print("Analysis Summary:")
    print(analysis_result.get("summary", "No summary"))
    if analysis_result.get("error"):
        print(f"Error: {analysis_result['error']}")

if __name__ == "__main__":
    asyncio.run(verify_dual_models())
