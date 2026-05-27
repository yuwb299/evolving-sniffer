"""Configuration for evolving-sniffer."""
import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
MODEL_ID = os.getenv("MODEL_ID", "deepseek-chat")

TARGET_DIR = os.path.join(os.path.dirname(__file__), "target")
MEMORY_DIR = os.path.join(os.path.dirname(__file__), "memory")
EVOLUTION_LOG = os.path.join(MEMORY_DIR, "evolution_log.json")
