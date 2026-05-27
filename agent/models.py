"""DeepSeek LLM interface."""
import json
import requests
from config import OPENAI_BASE_URL, OPENAI_API_KEY, MODEL_ID


def call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
    """Call DeepSeek chat API and return assistant response text."""
    resp = requests.post(
        f"{OPENAI_BASE_URL}/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
        json={
            "model": MODEL_ID,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.7,
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]
