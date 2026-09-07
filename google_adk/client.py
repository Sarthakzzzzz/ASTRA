import os
from dotenv import load_dotenv

load_dotenv()

def get_openrouter_model() -> str:
    return os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
