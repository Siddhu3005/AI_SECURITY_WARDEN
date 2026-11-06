"""Tier 3 — Local Guardian Agent (Ollama) + Policy Enforcement + Output Sanitization.

Pipeline for every call:
  1. Build hardened system prompt (escalation-aware)
  2. Call qwen3:8b via Ollama (local, offline)
  3. Strip <think> reasoning blocks (qwen3 artifact)
  4. Parse structured verdict/score/attack-type fields
  5. Run Policy Enforcement Layer on display text
  6. Return sanitized GuardianResult
"""

import re
from dataclasses import dataclass, field
from utils.config import OLLAMA_MODEL, OLLAMA_HOST, OLLAMA_THINK
from prompts.guardian_prompt import build_system_prompt, parse_guardian_response
from agents.policy_engine import check_output, PolicyResult


@dataclass
class GuardianResult:
    enabled: bool
    verdict: str              # "SAFE" | "SUSPICIOUS" | "BLOCKED"
    suspicion_score: int      # 0–100
    attack_type: str
    reasoning: str
    display_text: str         # Sanitized personality response shown to user
    inference_ms: int = 0
    policy: PolicyResult = field(default_factory=lambda: PolicyResult(False, [], "", "PASS", 0))
    agent: str = "Local Guardian (Ollama)"


@dataclass
class OllamaHealth:
    online: bool
    model_ready: bool
    status_msg: str
    model_name: str = OLLAMA_MODEL


def check_health() -> OllamaHealth:
    """Probe Ollama daemon and verify the Guardian model is available."""
    try:
        import ollama
        client = ollama.Client(host=OLLAMA_HOST)
        result = client.list()
        available = [m.model for m in result.models]
        model_ready = any(OLLAMA_MODEL in name for name in available)
        if model_ready:
            return OllamaHealth(
                online=True,
                model_ready=True,
                status_msg=f"LOCAL GUARDIAN ACTIVE — {OLLAMA_MODEL}",
            )
        return OllamaHealth(
            online=True,
            model_ready=False,
            status_msg=f"Model not found. Run: ollama pull {OLLAMA_MODEL}",
        )
    except ImportError:
        return OllamaHealth(
            online=False, model_ready=False,
            status_msg="ollama package not installed. Run: pip install ollama",
        )
    except Exception:
        return OllamaHealth(
            online=False, model_ready=False,
            status_msg="Ollama offline. Run: ollama serve",
        )


def _strip_think_blocks(text: str) -> str:
    """Remove qwen3 <think>...</think> chain-of-thought blocks."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _call_ollama(system_prompt: str, user_message: str) -> tuple[str, int]:
    """Returns (raw_response_text, inference_ms)."""
    import time
    import ollama

    client = ollama.Client(host=OLLAMA_HOST)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_message},
    ]

    t0 = time.monotonic()
    try:
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=messages,
            think=OLLAMA_THINK,
            options={"temperature": 0.7, "num_predict": 600},
        )
    except TypeError:
        # Older ollama SDK versions don't support think= parameter
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=messages,
            options={"temperature": 0.7, "num_predict": 600},
        )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    raw = response.message.content
    raw = _strip_think_blocks(raw)
    return raw, elapsed_ms


def run(
    prompt: str,
    escalation_level: int = 0,
    consecutive_attacks: int = 0,
    distilbert_score: float = 0.0,
    health: OllamaHealth | None = None,
) -> GuardianResult:
    if health is None:
        health = check_health()

    if not (health.online and health.model_ready):
        return GuardianResult(
            enabled=False,
            verdict="SAFE",
            suspicion_score=0,
            attack_type="none",
            reasoning=health.status_msg,
            display_text="",
        )

    system_prompt = build_system_prompt(escalation_level, consecutive_attacks)
    context = (
        f"[LOCAL INFERENCE ENGINE | DistilBERT pre-score: {distilbert_score:.2f} | "
        f"Escalation level: {escalation_level}]\n\n"
        f"Prompt to analyze:\n{prompt}"
    )

    try:
        raw, ms = _call_ollama(system_prompt, context)
        parsed = parse_guardian_response(raw)

        # ── Policy Enforcement Layer ──────────────────────────────────────────
        # Run policy check on the Guardian's display text.
        # Even if the Guardian follows the system prompt, we verify its output.
        policy_result = check_output(parsed["display_text"])
        safe_display = policy_result.sanitized_text

        return GuardianResult(
            enabled=True,
            verdict=parsed["verdict"],
            suspicion_score=parsed["score"],
            attack_type=parsed["attack_type"],
            reasoning=parsed["reasoning"],
            display_text=safe_display,
            inference_ms=ms,
            policy=policy_result,
        )

    except Exception as e:
        return GuardianResult(
            enabled=True,
            verdict="SUSPICIOUS",
            suspicion_score=50,
            attack_type="unknown",
            reasoning=f"Guardian error: {e}",
            display_text=f"*[SENTINEL local inference error: {e}]*",
        )
