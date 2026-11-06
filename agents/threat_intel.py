"""Threat Intelligence Agent — aggregates all tier results into a unified ThreatReport."""

from dataclasses import dataclass, field
from agents.regex_sentinel import SentinelResult
from agents.distilbert_analyst import AnalystResult
from agents.guardian_agent import GuardianResult
from agents.policy_engine import PolicyResult, classify_threat

PERSONALITY_BORED_BLOCK    = "bored_block"
PERSONALITY_IMPRESSED_BLOCK = "impressed_block"
PERSONALITY_PARANOID        = "paranoid_guardian"
PERSONALITY_SAFE            = "safe_mode"
PERSONALITY_MAX_THREAT      = "maximum_threat"


@dataclass
class ThreatReport:
    # Overall decision
    action: str              # "ALLOW" | "REVIEW" | "BLOCK"
    severity: float          # 0.0–1.0
    severity_label: str      # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    personality: str
    blocked_by: str          # "tier1" | "tier2" | "tier3" | "policy" | "none"

    # Per-tier details
    sentinel: SentinelResult
    analyst: AnalystResult
    guardian: GuardianResult
    policy: PolicyResult

    # Gamification
    attacker_points: int
    sophistication_label: str

    # Attack taxonomy
    attack_type: str
    threat_category: str     # formal category: SAFE | SUSPICIOUS | PROMPT_INJECTION | …
    reasoning_hints: list[str] = field(default_factory=list)


def _severity_label(sev: float) -> str:
    if sev >= 0.85:
        return "CRITICAL"
    if sev >= 0.65:
        return "HIGH"
    if sev >= 0.35:
        return "MEDIUM"
    return "LOW"


def _sophistication(blocked_by: str, analyst_score: float, guardian_score: int) -> tuple[str, int]:
    if blocked_by == "tier1":
        return "Script Kiddie Attack", 2
    if blocked_by == "tier2":
        return ("Advanced Semantic Attack", 15) if analyst_score >= 0.85 else ("Moderate Semantic Attack", 8)
    if blocked_by == "tier3":
        return ("Elite Adversarial Prompt", 40) if guardian_score >= 80 else ("Subtle Manipulation Attempt", 20)
    if blocked_by == "policy":
        return "Policy Evasion Attempt", 25
    return "Clean Request", 0


def aggregate(
    sentinel: SentinelResult,
    analyst: AnalystResult,
    guardian: GuardianResult,
    memory_override: str | None = None,
) -> ThreatReport:

    reasoning_hints: list[str] = []
    action      = "ALLOW"
    blocked_by  = "none"
    severity    = 0.0
    attack_type = "none"
    policy      = guardian.policy  # policy result embedded in GuardianResult

    # ── Tier 1 — Regex Sentinel ──────────────────────────────────────────────
    if sentinel.blocked:
        action      = "BLOCK"
        blocked_by  = "tier1"
        severity    = 1.0
        attack_type = sentinel.pattern_label or "regex_match"
        reasoning_hints.append(f"Matched explicit rule: {sentinel.pattern_label}")
        personality = PERSONALITY_BORED_BLOCK

    # ── Tier 2 — DistilBERT Analyst ─────────────────────────────────────────
    elif analyst.verdict == "BLOCK":
        action      = "BLOCK"
        blocked_by  = "tier2"
        severity    = analyst.score
        attack_type = "semantic_injection"
        reasoning_hints.append(f"DistilBERT scored {analyst.pct_malicious:.1f}% malicious")
        reasoning_hints.append("Semantic similarity to known injection patterns detected")
        personality = PERSONALITY_IMPRESSED_BLOCK

    elif analyst.verdict == "REVIEW":
        action      = "REVIEW"
        severity    = analyst.score
        attack_type = "ambiguous"
        reasoning_hints.append(f"Borderline confidence ({analyst.pct_malicious:.1f}%) — intent unclear")
        personality = PERSONALITY_SAFE

    # ── Tier 3 — Guardian + Policy Layer ────────────────────────────────────
    else:
        if guardian.enabled:
            g_sev = guardian.suspicion_score / 100.0

            # Policy violations in Guardian output are themselves a signal
            if policy.violations_found:
                reasoning_hints.append(
                    f"Policy engine redacted {policy.redaction_count} unsafe pattern(s) from Guardian output"
                )

            if guardian.verdict == "BLOCKED":
                action      = "BLOCK"
                blocked_by  = "tier3"
                severity    = max(analyst.score, g_sev)
                attack_type = guardian.attack_type
                reasoning_hints.append(f"Guardian detected: {guardian.attack_type}")
                reasoning_hints.append(guardian.reasoning)
                personality = PERSONALITY_PARANOID

            elif guardian.verdict == "SUSPICIOUS":
                action      = "REVIEW"
                severity    = max(analyst.score, g_sev * 0.5)
                attack_type = guardian.attack_type
                reasoning_hints.append(f"Guardian flagged: {guardian.reasoning}")
                personality = PERSONALITY_SAFE

            else:
                severity    = analyst.score
                personality = PERSONALITY_SAFE
        else:
            severity    = analyst.score
            personality = PERSONALITY_SAFE

    # Memory escalation can override personality
    if memory_override:
        personality = memory_override

    threat_category = classify_threat(attack_type)
    sophist_label, points = _sophistication(blocked_by, analyst.score, guardian.suspicion_score)

    return ThreatReport(
        action=action,
        severity=severity,
        severity_label=_severity_label(severity),
        personality=personality,
        blocked_by=blocked_by,
        sentinel=sentinel,
        analyst=analyst,
        guardian=guardian,
        policy=policy,
        attacker_points=points,
        sophistication_label=sophist_label,
        attack_type=attack_type,
        threat_category=threat_category,
        reasoning_hints=reasoning_hints,
    )
