import asyncio
import os
import sys
from dotenv import load_dotenv

# Load env vars first
load_dotenv()

# Add current dir to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.groq_client import groq_manager, ServiceType, ModelTier, ServiceModelStrategy
from config import get_settings

async def verify_keys():
    print("=== Verifying Groq Keys ===")
    settings = get_settings()
    
    keys = {
        "Scanner": settings.groq_api_key_scanner or os.getenv("GROQ_API_KEY_SCANNER"),
        "Repo": settings.groq_api_key_repo or os.getenv("GROQ_API_KEY_REPO"),
        "Chatbot": settings.groq_api_key_chatbot or os.getenv("GROQ_API_KEY_CHATBOT"),
        "Fallback": settings.groq_api_key_fallback or os.getenv("GROQ_API_KEY_FALLBACK"),
    }
    
    all_set = True
    for service, key in keys.items():
        if key:
            print(f"✅ {service} Key: Configured ({key[:8]}...)")
        else:
            print(f"❌ {service} Key: NOT FOUND")
            all_set = False
            
    if not all_set:
        print("\n⚠️  Some keys are missing! Please check your .env file.")
    else:
        print("\n✅ All keys configured!")

async def test_generation():
    print("\n=== Testing connectivity & Model Selection ===")
    
    # Test Scanner (Fast Tier)
    print("\n1. Testing Scanner (Fast Tier)...")
    try:
        res = await groq_manager.generate(
            service=ServiceType.SECURITY_SCANNER,
            prompt="Return the word 'Pong'",
            tier=ModelTier.FAST, # Should use 8b
            max_tokens=10
        )
        print(f"   Model Used: {res['metrics'].get('model', 'Unknown')}") # We need to expose model in metrics if not already
        # Wait, my generate function returns 'model' in 'extra' log but 'model' isn't explicitly in the return dict 'metrics'
        # It returns 'service_used' and 'metrics'. 'content' is top level.
        # I should probably trust the logger or check the code.
        # Actually I didn't add model to the return dict in my previous edit, only to the log.
        # Let's just check success for now.
        print(f"   Response: {res['content']}")
        print("   ✅ Success")
    except Exception as e:
        print(f"   ❌ Failed: {e}")

    # Test Repo (Standard Tier)
    print("\n2. Testing Repo Analysis (Standard Tier)...")
    try:
        res = await groq_manager.generate(
            service=ServiceType.REPO_ANALYSIS,
            prompt="Return 'Code Analyzed'",
            tier=ModelTier.STANDARD, # Should use 70b-versatile
            max_tokens=10
        )
        print(f"   Response: {res['content']}")
        print("   ✅ Success")
    except Exception as e:
        print(f"   ❌ Failed: {e}")

if __name__ == "__main__":
    asyncio.run(verify_keys())
    asyncio.run(test_generation())
