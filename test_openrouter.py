import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")
print(f"Groq API Key loaded: {api_key[:20]}..." if api_key else "No API key found!")
print(f"API Key length: {len(api_key) if api_key else 0}")

try:
    client = OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=api_key
    )
    
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": "Say hello in one sentence"}],
        max_tokens=50
    )
    
    print("✅ SUCCESS! Groq is working!")
    print(f"Response: {response.choices[0].message.content}")
    
except Exception as e:
    print(f"❌ Error: {e}")
