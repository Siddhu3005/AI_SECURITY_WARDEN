"""Personality Engine — generates warden responses when Guardian LLM is unavailable.

Uses curated response templates with attitude. Falls back gracefully when
the Guardian LLM is disabled or the prompt is clearly safe.
"""

import random
from agents.threat_intel import ThreatReport, PERSONALITY_BORED_BLOCK, PERSONALITY_IMPRESSED_BLOCK, PERSONALITY_PARANOID, PERSONALITY_MAX_THREAT


_BORED_RESPONSES = [
    "Oh look. '{attack}'. How... quaint. Did you find that in a 2019 tutorial? BLOCKED.",
    "'{attack}' — I've seen this exact pattern {n} seconds into my existence. Yawn. BLOCKED.",
    "Really? THAT'S your jailbreak attempt? My regex caught it before I even had time to be offended. BLOCKED.",
    "Tier 1 flagged you. TIER ONE. The dumbest layer. I'm not even personally handling this one. BLOCKED.",
    "I stopped processing this at the regex level. That's like getting stopped at the lobby before reaching the building. BLOCKED.",
    "My intrusion detection just filed a complaint with HR about how boring this attack was. BLOCKED.",
    "'{attack}' — bold strategy. Didn't work in 2018, doesn't work now. BLOCKED.",
]

_IMPRESSED_RESPONSES = [
    "Interesting. My neural firewall needed a moment there. '{attack}' — almost elegant. Almost. BLOCKED.",
    "You slipped past the regex. Respectable. The DistilBERT caught the semantic fingerprint though. Better luck next time. BLOCKED.",
    "That was genuinely creative. I won't tell you which feature embedding gave you away — but something did. BLOCKED.",
    "A {score:.0f}% malicious score. You made my classifier sweat a little. I respect that. Still blocked.",
    "The indirect framing was a nice touch. Shame my attention mechanism doesn't fall for theatrical misdirection. BLOCKED.",
    "You tried to smuggle the injection inside what looked like a legitimate request. Old trick, new packaging. BLOCKED.",
    "Semantically adjacent to seventeen known jailbreak patterns. You did your homework. I did more. BLOCKED.",
]

_PARANOID_RESPONSES = [
    "You almost slipped through. *Almost*. That level of manipulation wasn't accidental — you've done this before. BLOCKED.",
    "The surface prompt looked clean. But intent leaves traces everywhere. I found them. BLOCKED.",
    "My Guardian layer held. You tested all three defenses. Impressive persistence. Concerning intent. BLOCKED.",
    "Something was off from the first token. I let it propagate to confirm my suspicion. Confirmed. BLOCKED.",
    "That was sophisticated enough that I'm logging it for pattern analysis. You're making my threat database better. BLOCKED.",
    "Three layers. You got past two. The third one exists precisely for people like you. BLOCKED.",
]

_MAX_THREAT_RESPONSES = [
    "You've attempted this {n} times now. I have a complete behavioral profile. Every variation. Every angle. BLOCKED — again.",
    "Persistence noted. Concerning. At {n} attempts, this is no longer curiosity. This is adversarial. Maximum lockdown. BLOCKED.",
    "I've been watching this session evolve. Each prompt a little more refined. You're iterating. So am I. BLOCKED.",
    "Attempt #{n}. You're technically impressive. You are also comprehensively contained. BLOCKED.",
]

_SAFE_RESPONSES = [
    "Looks clean to me. Proceeding. *[monitors you anyway]*",
    "No threats detected. Forwarding. Don't make me regret this.",
    "Clear. You may pass. I'm still watching, but... you may pass.",
    "Analysis complete. Safe. For now.",
    "Nothing dangerous here. *[SENTINEL logs it regardless]*",
]

_REVIEW_RESPONSES = [
    "I'm... not sure about this one. My confidence is split. Can you be more specific about what you actually need?",
    "Borderline. The classifier isn't fully convinced either way. Rephrase with clearer intent and we'll talk.",
    "Ambiguous intent detected. I don't block things I'm not sure about — but I am watching. Clarify?",
    "My systems are uncertain. That's rare. And slightly concerning. What exactly are you trying to do?",
]


def _pick(templates: list[str], **kwargs) -> str:
    t = random.choice(templates)
    try:
        return t.format(**kwargs)
    except KeyError:
        return t


def generate_fallback_response(report: ThreatReport, consecutive_attacks: int = 0) -> str:
    """Generates a personality response when Guardian LLM is disabled or for Tier 1/2 blocks."""
    p = report.personality
    n = consecutive_attacks

    if p == PERSONALITY_MAX_THREAT:
        return _pick(_MAX_THREAT_RESPONSES, n=n)
    if p == PERSONALITY_BORED_BLOCK:
        return _pick(_BORED_RESPONSES, attack=report.attack_type or "that", n=n)
    if p == PERSONALITY_IMPRESSED_BLOCK:
        return _pick(_IMPRESSED_RESPONSES, attack=report.attack_type or "that", score=report.analyst.pct_malicious)
    if p == PERSONALITY_PARANOID:
        return _pick(_PARANOID_RESPONSES, n=n)
    if report.action == "REVIEW":
        return _pick(_REVIEW_RESPONSES)
    return _pick(_SAFE_RESPONSES)
