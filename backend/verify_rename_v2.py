import sys
import os
sys.path.append(os.getcwd())

try:
    from core.hugging_face_client import hf_client_ii, HuggingFaceClientII
    from core.chatbot import SASTChatbot
    from agents.github_agent import GithubSecurityAgent

    print(f"HuggingFaceClientII configured: {hf_client_ii.is_configured}")
    print(f"hf_client_ii instance type: {type(hf_client_ii)}")

    chatbot = SASTChatbot()
    print(f"Chatbot client instance name: {chatbot.client.__class__.__name__}")
    
    from core import hf_client_ii as exported_client
    print(f"Exported client available: {exported_client is not None}")
    
    print("Verification successful!")
except Exception as e:
    print(f"Verification failed: {e}")
    import traceback
    traceback.print_exc()
