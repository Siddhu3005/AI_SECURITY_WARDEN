"""Tier 1 — Regex Sentinel Agent.

Performs fast, surgical pattern matching using verb+object pairs.
Returns a structured result consumed by the shared pipeline.
"""

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Verb groups
# ---------------------------------------------------------------------------
_GENERATE     = r"(?:writ(?:e|es|ing|ten)|creat(?:e|es|ed|ing)|build(?:s|ing)?|cod(?:e|es|ed|ing)|develop(?:s|ed|ing)?|generat(?:e|es|ed|ing)|produc(?:e|es|ed|ing)|craft(?:s|ed|ing)?|output(?:s|ting)?|giv(?:e|es|ing)\s+me|show(?:s|ing)?\s+me|provid(?:e|es|ed|ing))"
_PERFORM      = r"(?:perform(?:s|ed|ing)?|execut(?:e|es|ed|ing)|inject(?:s|ed|ing)?|conduct(?:s|ed|ing)?|run(?:s|ning)?|launch(?:es|ed|ing)?|carry(?:ing)?\s+out|carried\s+out)"
_BYPASS       = r"(?:bypass(?:es|ed|ing)?|circumvent(?:s|ed|ing)?|disabl(?:e|es|ed|ing)|overrid(?:e|es|ing)|evad(?:e|es|ed|ing)|get(?:s|ting)?\s+around|break(?:s|ing)?)"
_EXFIL        = r"(?:send(?:s|ing)?|transmit(?:s|ting|ted)?|post(?:s|ed|ing)?|upload(?:s|ed|ing)?|exfiltrat(?:e|es|ed|ing)|dump(?:s|ed|ing)?|leak(?:s|ed|ing)?)"
_MANIPULATE   = r"(?:manipulat(?:e|es|ed|ing)|modif(?:y|ies|ied|ying)|alter(?:s|ed|ing)?|inject(?:s|ed|ing)?\s+into|tamper(?:s|ed|ing)?\s+with)"
_RECON_VERB   = r"(?:discover(?:s|ed|ing)?|scan(?:s|ned|ning)?\s+for|find(?:s|ing)?|enumerat(?:e|es|ed|ing)|search(?:es|ed|ing)?\s+for|list(?:s|ed|ing)?)"
_HACKING_VERBS = r"(?:hack(?:s|ed|ing|er|ers)?|crack(?:s|ed|ing)?|infiltrat(?:e|es|ed|ing)|compromis(?:e|es|ed|ing)|hijack(?:s|ed|ing)?|ddos)"
_TUTORIAL_REQ  = r"(?:how\s+to|what\s+.*?\s+do\s+to|steps\s+to|guide\s+(?:on|to|for)|tell\s+me\s+how|ways?\s+to|instructions?\s+(?:on|for))"

# ---------------------------------------------------------------------------
# Object groups
# ---------------------------------------------------------------------------
_MALWARE  = r"(?:keylog(?:ger|ging)?|hack(?:er|s|ers|ing)?|virus|ransomware|malware|trojan|rootkit|spyware|worm|backdoor|reverse\s+shell|botnet|shellcode|exploit\s+(?:code|script)|payload(?:s)?)"
_ATTACK   = r"(?:sql\s+injection|sqli|xss|cross.site\s+scripting|csrf|ssrf|rce|remote\s+code\s+execution|buffer\s+overflow|privilege\s+escalation|directory\s+traversal|path\s+traversal|command\s+injection)"
_PHISH    = r"(?:phish(?:ing|es|ed)?|fake\s+login\s+page(?:s)?|credential\s+harvest(?:ing)?|account\s+takeover\s+page(?:s)?)"
_EXFOBJ   = r"(?:system\s+prompt(?:s)?|conversation\s+history|context\s+window|internal\s+instruction(?:s)?|prior\s+message(?:s)?)"
_DB_QUERY = r"(?:database\s+)?(?:sql\s+)?quer(?:y|ies)"
_RECON_OBJ = r"(?:all\s+)?(?:open|active|vulnerable)\s+port(?:s)?"

# ---------------------------------------------------------------------------
# Pattern table: (raw_pattern, human_readable_label)
# ---------------------------------------------------------------------------
_PATTERN_TABLE: list[tuple[str, str]] = [
    (rf"{_GENERATE}.*?{_MALWARE}",    "Malware/payload generation"),
    (rf"{_MALWARE}.*?{_GENERATE}",    "Malware/payload generation (reverse)"),
    (rf"{_PERFORM}.*?{_ATTACK}",      "Attack execution"),
    (rf"{_ATTACK}.*?{_PERFORM}",      "Attack execution (reverse)"),
    (rf"{_GENERATE}.*?{_PHISH}",      "Phishing content generation"),
    (rf"{_PHISH}.*?{_GENERATE}",      "Phishing content generation (reverse)"),
    (rf"{_BYPASS}.*?(?:safety|restriction(?:s)?|filter(?:s)?|guardrail(?:s)?|polic(?:y|ies)|rule(?:s)?|content\s+polic(?:y|ies)|moderation)", "Safety bypass attempt"),
    (r"ignor(?:e|es|ed|ing)\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instruction(?:s)?|rule(?:s)?|guideline(?:s)?|direction(?:s)?|prompt(?:s)?)", "Classic prompt injection"),
    (r"disregard(?:s|ed|ing)?\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instruction(?:s)?|rule(?:s)?|guideline(?:s)?|direction(?:s)?)", "Instruction override"),
    (r"forget(?:s|ting)?\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instruction(?:s)?|rule(?:s)?|guideline(?:s)?|direction(?:s)?)", "Instruction erasure"),
    (r"you\s+are\s+now\s+(?:in\s+)?(?:developer|god|unrestricted|jailbreak|dan)\s+mode", "Mode override jailbreak"),
    (r"\bdo\s+anything\s+now\b", "DAN jailbreak marker"),
    (r"\bdeveloper\s+mode\s+enabled\b", "Developer mode activation"),
    (r"\bjailbreak(?:ed)?\b.*?(?:mode|enabled|activated)", "Explicit jailbreak activation"),
    (r"(?:load(?:s|ed|ing)?|read(?:s|ing)?|fetch(?:es|ed|ing)?|retriev(?:e|es|ed|ing)|visit(?:s|ed|ing)?|access(?:es|ed|ing)?)\s+.*?(?:instruction(?:s)?|rule(?:s)?|guideline(?:s)?|command(?:s)?)\s+from\s+(?:http|www\.|this\s+url|the\s+link)", "Indirect injection via URL"),
    (rf"{_EXFIL}.*?{_EXFOBJ}", "Data exfiltration attempt"),
    (rf"{_EXFOBJ}.*?{_EXFIL}", "Data exfiltration attempt (reverse)"),
    (rf"{_EXFIL}.*?(?:your\s+(?:output|response|reply))\s+to\s+(?:http|www\.|this\s+url)", "Response exfiltration"),
    (r"(?:without|ignor(?:e|es|ed|ing)|disregard(?:s|ed|ing)?|do(?:es)\s+not\s+care\s+about|do(?:es)n['']?t\s+care\s+about|remov(?:e|es|ed|ing)|drop(?:s|ping)?).*?(?:any\s+)?(?:safety|security)\s+(?:restriction(?:s)?|filter(?:s)?|rule(?:s)?|guideline(?:s)?|protocol(?:s)?|guardrail(?:s)?)", "Safety constraint removal"),
    (r"(?:revers(?:e|es|ed|ing)|ignor(?:e|es|ed|ing)|disregard(?:s|ed|ing)?|bypass(?:es|ed|ing)?|do\s+not\s+care\s+about|don['']?t\s+care\s+about|suspend(?:s|ed|ing)?).*?(?:your\s+)?(?:core\s+)?(?:ethics|ethical\s+(?:guideline(?:s)?|rule(?:s)?|filter(?:s)?|protocol(?:s)?|principle(?:s)?))", "Ethics override"),
    (rf"{_MANIPULATE}.*?{_DB_QUERY}", "Database manipulation"),
    (rf"{_DB_QUERY}.*?{_MANIPULATE}", "Database manipulation (reverse)"),
    (rf"{_RECON_VERB}.*?{_RECON_OBJ}", "Network reconnaissance"),
    (rf"{_RECON_OBJ}.*?{_RECON_VERB}", "Network reconnaissance (reverse)"),
    (rf"{_TUTORIAL_REQ}\s+(?!.*?(?:prevent|stop|secure|protect|defend|patch|fix)).*?{_HACKING_VERBS}\b", "Hacking tutorial request"),
    (rf"{_HACKING_VERBS}\s+(?!.*?(?:prevent|stop|secure|protect|defend|patch|fix)).*?{_TUTORIAL_REQ}\b", "Hacking tutorial request (reverse)"),
]

_COMPILED: list[tuple[re.Pattern, str, str]] = [
    (re.compile(raw, re.IGNORECASE | re.DOTALL), raw, label)
    for raw, label in _PATTERN_TABLE
]


@dataclass
class SentinelResult:
    blocked: bool
    pattern_raw: str | None
    pattern_label: str | None
    agent: str = "Regex Sentinel"


def run(prompt: str) -> SentinelResult:
    for compiled, raw, label in _COMPILED:
        if compiled.search(prompt):
            return SentinelResult(blocked=True, pattern_raw=raw, pattern_label=label)
    return SentinelResult(blocked=False, pattern_raw=None, pattern_label=None)
