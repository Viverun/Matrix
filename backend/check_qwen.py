
import asyncio
import os
import sys
from huggingface_hub import InferenceClient

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import get_settings

async def check_model():
    settings = get_settings()
    token = settings.huggingface_api_key
    if not token:
        print("No API Key found")
        return

    # Try Qwen/Qwen2.5-7B-Instruct (Smaller alternative)
    model = "Qwen/Qwen2.5-7B-Instruct"
    print(f"Testing {model}...")
    
    client = InferenceClient(token=token)
    
    try:
        response = client.chat_completion(
            model=model,
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=10
        )
        print(f"Success! Response: {response.choices[0].message.content}")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    asyncio.run(check_model())
