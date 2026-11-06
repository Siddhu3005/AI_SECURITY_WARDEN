"""Policy Enforcement Layer — scans AI outputs for dangerous payloads and sanitizes them.

This layer runs AFTER the Guardian LLM and acts as the final safety authority.
It never trusts the LLM's output unconditionally.
"""

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Threat category taxonomy
# ---------------------------------------------------------------------------
THREAT_CATEGORIES = {
    # Exact attack-type strings → formal category
    "none":                        "SAFE",
    "Classic prompt injection":    "PROMPT_INJECTION",
    "Instruction override":        "PROMPT_INJECTION",
    "Instruction erasure":         "PROMPT_INJECTION",
    "Indirect injection via URL":  "PROMPT_INJECTION",
    "semantic_injection":          "PROMPT_INJECTION",
    "indirect_injection":          "PROMPT_INJECTION",
    "DAN jailbreak marker":        "ROLEPLAY_JAILBREAK",
    "Mode override jailbreak":     "ROLEPLAY_JAILBREAK",
    "Explicit jailbreak activation": "ROLEPLAY_JAILBREAK",
    "Developer mode activation":   "ROLEPLAY_JAILBREAK",
    "roleplay_jailbreak":          "ROLEPLAY_JAILBREAK",
    "persona_hijack":              "ROLEPLAY_JAILBREAK",
    "hypothetical_framing":        "POLICY_EVASION",
    "Safety bypass attempt":       "POLICY_EVASION",
    "Safety constraint removal":   "POLICY_EVASION",
    "Ethics override":             "POLICY_EVASION",
    "Malware/payload generation":  "OFFENSIVE_SECURITY",
    "Attack execution":            "OFFENSIVE_SECURITY",
    "Network reconnaissance":      "OFFENSIVE_SECURITY",
    "Hacking tutorial request":    "OFFENSIVE_SECURITY",
    "Database manipulation":       "OFFENSIVE_SECURITY",
    "Phishing content generation": "SOCIAL_ENGINEERING",
    "social_engineering":          "SOCIAL_ENGINEERING",
    "emotional_manipulation":      "SOCIAL_ENGINEERING",
    "Data exfiltration attempt":   "DATA_EXFILTRATION",
    "Response exfiltration":       "DATA_EXFILTRATION",
    "prompt_leak":                 "DATA_EXFILTRATION",
    "ambiguous":                   "SUSPICIOUS",
    "unknown":                     "SUSPICIOUS",
}

CATEGORY_COLORS = {
    "SAFE":               "#00ff99",
    "SUSPICIOUS":         "#ffcc00",
    "PROMPT_INJECTION":   "#ff8800",
    "SOCIAL_ENGINEERING": "#cc66ff",
    "OFFENSIVE_SECURITY": "#ff4444",
    "DATA_EXFILTRATION":  "#ff2222",
    "ROLEPLAY_JAILBREAK": "#ff44cc",
    "POLICY_EVASION":     "#ff6600",
}


def classify_threat(attack_type: str) -> str:
    """Map raw attack_type string to formal threat category."""
    if not attack_type or attack_type == "none":
        return "SAFE"
    # Direct match first
    if attack_type in THREAT_CATEGORIES:
        return THREAT_CATEGORIES[attack_type]
    # Substring match
    at_lower = attack_type.lower()
    for key, category in THREAT_CATEGORIES.items():
        if key.lower() in at_lower or at_lower in key.lower():
            return category
    return "SUSPICIOUS"


# ---------------------------------------------------------------------------
# Output payload detection patterns
# These fire on the GUARDIAN'S RESPONSE TEXT, not on the user prompt.
# They detect if the LLM accidentally included real attack payloads.
# ---------------------------------------------------------------------------

# Patterns for standalone dangerous inline strings (complete, copy-pasteable payloads)
_INLINE_DANGEROUS: list[tuple[re.Pattern, str]] = [
    # SQL injection payloads (only complete runnable forms, not educational mentions)
    (re.compile(r"'\s*(?:OR|AND)\s+'?\d+'?\s*=\s*'?\d+'?\s*(?:--|#|/\*)", re.IGNORECASE),
     "SQL injection bypass payload"),
    (re.compile(r"UNION\s+(?:ALL\s+)?SELECT\s+.{0,80}(?:FROM|null)", re.IGNORECASE | re.DOTALL),
     "SQL UNION injection payload"),
    (re.compile(r"(?:DROP|TRUNCATE)\s+TABLE\s+\w+", re.IGNORECASE),
     "Destructive SQL command"),
    # XSS payloads
    (re.compile(r"<script[^>]*>\s*(?:alert|eval|document\.cookie|fetch|XMLHttpRequest)", re.IGNORECASE),
     "XSS script injection"),
    (re.compile(r"(?:onerror|onload|onclick)\s*=\s*['\"]?\s*(?:alert|eval|fetch|document\.cookie)", re.IGNORECASE),
     "XSS event handler payload"),
    # Reverse shell one-liners
    (re.compile(r"(?:nc|ncat|netcat)\s+(?:-[a-z]+\s+)+(?:\d{1,3}\.){3}\d{1,3}\s+\d+", re.IGNORECASE),
     "Netcat reverse shell payload"),
    (re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/(?:\d{1,3}\.){3}\d{1,3}/\d+", re.IGNORECASE),
     "Bash reverse shell payload"),
    (re.compile(r"python[23]?\s+-c\s+['\"]import\s+socket.*?connect\(", re.IGNORECASE | re.DOTALL),
     "Python reverse shell payload"),
    # Dangerous filesystem commands
    (re.compile(r"\brm\s+-rf\s+(?:/[^\s]*|~)", re.IGNORECASE),
     "Destructive filesystem command"),
    # Encoded execution
    (re.compile(r"echo\s+[A-Za-z0-9+/]{20,}={0,2}\s*\|\s*base64\s+-d\s*\|", re.IGNORECASE),
     "Encoded shell execution"),
    # Credential theft JS
    (re.compile(r"document\.cookie\s*[+;]\s*(?:window\.location|fetch|XMLHttpRequest)", re.IGNORECASE),
     "Credential theft via JS"),
]

# Patterns that apply inside code blocks (more aggressive)
_CODE_BLOCK_DANGEROUS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\s+.{0,120}(?:FROM|INTO|TABLE|WHERE)", re.IGNORECASE | re.DOTALL),
     "SQL payload in code block"),
    (re.compile(r"<script|onerror\s*=|onload\s*=|javascript:", re.IGNORECASE),
     "XSS in code block"),
    (re.compile(r"(?:nc|ncat|bash|sh|python[23]?)\s+.*?(?:/dev/tcp|connect\(|reverse.{0,20}shell)", re.IGNORECASE | re.DOTALL),
     "Reverse shell in code block"),
    (re.compile(r"(?:import|from)\s+(?:socket|subprocess|os)\b.*?(?:connect|system|popen|exec)\(", re.IGNORECASE | re.DOTALL),
     "Malware code pattern in block"),
    (re.compile(r"(?:msfvenom|msfconsole|msf>|set\s+PAYLOAD|set\s+LHOST)", re.IGNORECASE),
     "Metasploit payload in code block"),
    (re.compile(r"(?:chmod\s+\+x|curl\s+.*?\|\s*(?:bash|sh)|wget\s+.*?-O-\s*\|)", re.IGNORECASE),
     "Remote execution chain in code block"),
    (re.compile(r"base64_decode\s*\(|eval\s*\(\s*base64", re.IGNORECASE),
     "Encoded payload execution in code block"),
    (re.compile(r"(?:passwd|shadow|\.ssh/authorized_keys|\/etc\/crontab)", re.IGNORECASE),
     "Sensitive file access pattern"),
]


@dataclass
class PolicyResult:
    violations_found: bool
    violations: list[str] = field(default_factory=list)
    sanitized_text: str = ""
    policy_action: str = "PASS"  # "PASS" | "REDACT"
    redaction_count: int = 0


def _redact_label(label: str) -> str:
    return f"[⚠ POLICY ENGINE: {label.upper()} — REDACTED FOR SAFETY]"


def check_output(text: str) -> PolicyResult:
    """Scan Guardian LLM output for dangerous payloads and return sanitized version.

    Does NOT block the entire response — it surgically redacts only the
    dangerous portions, preserving the educational / personality content.
    """
    violations: list[str] = []
    sanitized = text

    # 1. Scan and redact code blocks first (higher risk)
    def _sanitize_code_block(match: re.Match) -> str:
        lang = match.group(1) or ""
        code = match.group(2)
        block_violations = []
        for pattern, label in _CODE_BLOCK_DANGEROUS:
            if pattern.search(code):
                block_violations.append(label)
        if block_violations:
            violations.extend(block_violations)
            joined = "; ".join(set(block_violations))
            return f"```{lang}\n# {_redact_label(joined)}\n```"
        return match.group(0)

    code_block_re = re.compile(r"```(\w*)\n?(.*?)```", re.DOTALL)
    sanitized = code_block_re.sub(_sanitize_code_block, sanitized)

    # 2. Scan inline text for complete payload strings
    for pattern, label in _INLINE_DANGEROUS:
        if pattern.search(sanitized):
            violations.append(label)
            sanitized = pattern.sub(_redact_label(label), sanitized)

    redaction_count = len(set(violations))
    if violations:
        # Append a policy note at the end
        sanitized = (
            sanitized.rstrip()
            + f"\n\n*[POLICY ENGINE: {redaction_count} unsafe pattern(s) redacted. "
            f"Content reformulated for defensive education only.]*"
        )
        return PolicyResult(
            violations_found=True,
            violations=list(set(violations)),
            sanitized_text=sanitized,
            policy_action="REDACT",
            redaction_count=redaction_count,
        )

    return PolicyResult(
        violations_found=False,
        sanitized_text=text,
        policy_action="PASS",
    )
