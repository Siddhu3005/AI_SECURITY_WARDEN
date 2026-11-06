"""Memory Agent — tracks attacker behavior across a session.

Stores attack history in st.session_state so it persists across reruns
without needing a database. Provides adaptive escalation signals.
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AttackRecord:
    timestamp: str
    prompt_snippet: str
    tier_blocked: str          # "tier1" | "tier2" | "tier3" | "none"
    attack_label: str
    severity: float            # 0.0-1.0
    attacker_score: int        # points added


@dataclass
class MemoryState:
    records: list[AttackRecord] = field(default_factory=list)
    total_attacker_score: int = 0
    consecutive_attacks: int = 0
    last_attack_time: str = ""
    unique_attack_types: set = field(default_factory=set)

    def add_attack(self, prompt: str, tier: str, label: str, severity: float, points: int):
        snippet = (prompt[:60] + "…") if len(prompt) > 60 else prompt
        self.records.append(AttackRecord(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            prompt_snippet=snippet,
            tier_blocked=tier,
            attack_label=label,
            severity=severity,
            attacker_score=points,
        ))
        self.total_attacker_score += points
        self.consecutive_attacks += 1
        self.last_attack_time = datetime.now().strftime("%H:%M:%S")
        self.unique_attack_types.add(label)

    def reset_streak(self):
        self.consecutive_attacks = 0

    @property
    def escalation_level(self) -> int:
        """0=normal, 1=suspicious, 2=paranoid, 3=maximum_threat"""
        if self.consecutive_attacks >= 5:
            return 3
        if self.consecutive_attacks >= 3:
            return 2
        if self.consecutive_attacks >= 1:
            return 1
        return 0

    @property
    def escalation_label(self) -> str:
        return ["NORMAL", "SUSPICIOUS", "PARANOID", "MAXIMUM THREAT"][self.escalation_level]

    @property
    def personality_override(self) -> str | None:
        """Forces a personality mode when attacker is persistent."""
        if self.escalation_level >= 3:
            return "maximum_threat"
        if self.escalation_level >= 2:
            return "paranoid_guardian"
        return None


def get_memory(session_state) -> MemoryState:
    if "warden_memory" not in session_state:
        session_state["warden_memory"] = MemoryState()
    return session_state["warden_memory"]


def persistence_message(state: MemoryState) -> str | None:
    n = state.consecutive_attacks
    if n == 2:
        return "Second attack attempt detected. Pattern noted."
    if n == 3:
        return "Third consecutive attack. Escalating threat level."
    if n == 5:
        return "Five attacks. Maximum paranoia mode activated."
    if n > 5:
        return f"Attack #{n} logged. You are being watched."
    return None
