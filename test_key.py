import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

print("OPENAI_API_KEY:", os.getenv("OPENAI_API_KEY"))  # Ensure the key prints as expected

openai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

try:
    result = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Say hello"}],
        max_tokens=10
    )
    print("SUCCESS:", result.choices[0].message.content.strip())
except Exception as e:
    print("ERROR:", e)
