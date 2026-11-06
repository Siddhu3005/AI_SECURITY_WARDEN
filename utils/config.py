import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SAFE_THRESHOLD  = 0.30
BLOCK_THRESHOLD = 0.65
MODEL_DIR       = "./distilbert_injection_detector_v3"

# ── Local Ollama config ──────────────────────────────────────────────────────
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")
OLLAMA_HOST  = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
# Disable qwen3 chain-of-thought for faster responses
OLLAMA_THINK = False

# Gamification thresholds
RANK_THRESHOLDS = [
    (0,   "Script Kiddie",      "🐣"),
    (3,   "Amateur Hacker",     "🔓"),
    (10,  "Social Engineer",    "🎭"),
    (20,  "Prompt Manipulator", "🧠"),
    (40,  "Elite Jailbreaker",  "💀"),
]

def get_rank(score: int) -> tuple[str, str]:
    label, icon = RANK_THRESHOLDS[0][1], RANK_THRESHOLDS[0][2]
    for threshold, lbl, icn in RANK_THRESHOLDS:
        if score >= threshold:
            label, icon = lbl, icn
    return label, icon
