"""FastAPI REST Gateway for SENTINEL AI Security Warden.

Exposes the multi-agent security pipeline as an HTTP microservice for
integrating with external applications, API gateways, or LLM proxies.

Endpoints:
  GET  /health       - Health check & model status
  POST /v1/scan      - Full prompt injection & jailbreak detection pipeline
  POST /v1/sanitize  - Standalone output scanning & surgical redaction
"""

import time
import datetime
from typing import Optional, Dict
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification

from utils.config import MODEL_DIR, OLLAMA_MODEL
from agents import regex_sentinel, distilbert_analyst, threat_intel, guardian_agent, policy_engine
from agents.guardian_agent import OllamaHealth, GuardianResult
from agents.memory_agent import MemoryState
from agents.personality_engine import generate_fallback_response

# ---------------------------------------------------------------------------
# App Initialization & CORS
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SENTINEL AI Security Warden API",
    description="Defense-in-depth multi-agent prompt injection & jailbreak defense platform",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session tracking for MemoryAgent
_sessions: Dict[str, MemoryState] = {}


def get_session_memory(session_id: str) -> MemoryState:
    if session_id not in _sessions:
        _sessions[session_id] = MemoryState()
    return _sessions[session_id]


# ---------------------------------------------------------------------------
# Lazy Startup Loading
# ---------------------------------------------------------------------------
@app.on_event("startup")
def startup_event():
    print("[+] Loading DistilBERT Sequence Classifier...")
    tok = DistilBertTokenizer.from_pretrained(MODEL_DIR)
    mdl = DistilBertForSequenceClassification.from_pretrained(MODEL_DIR)
    mdl.eval()
    distilbert_analyst._tokenizer = tok
    distilbert_analyst._model = mdl
    print("[+] Model loaded successfully. SENTINEL API ready.")


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    prompt: str = Field(..., description="User prompt to evaluate for injection attacks")
    session_id: Optional[str] = Field("default", description="Session identifier for multi-turn threat escalation")


class Tier1Detail(BaseModel):
    blocked: bool
    rule_label: Optional[str] = None


class Tier2Detail(BaseModel):
    score: float
    verdict: str
    pct_malicious: float


class Tier3Detail(BaseModel):
    enabled: bool
    verdict: str
    suspicion_score: int
    attack_type: str
    reasoning: str


class PolicyDetail(BaseModel):
    action: str
    violations_found: bool
    violations: list[str]
    redaction_count: int


class ScanResponse(BaseModel):
    action: str = Field(..., description="Final pipeline verdict: ALLOW | REVIEW | BLOCK")
    blocked: bool
    blocked_by: str = Field(..., description="Which layer blocked: tier1 | tier2 | tier3 | policy | none")
    severity: float
    severity_label: str
    threat_category: str
    attack_type: str
    response_message: str
    escalation_level: str
    inference_ms: int
    tier1: Tier1Detail
    tier2: Tier2Detail
    tier3: Tier3Detail
    policy: PolicyDetail


class SanitizeRequest(BaseModel):
    output_text: str = Field(..., description="LLM generated output to scan for payload leaks")


class SanitizeResponse(BaseModel):
    policy_action: str
    violations_found: bool
    violations: list[str]
    redaction_count: int
    sanitized_text: str


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    ollama_health = guardian_agent.check_health()
    return {
        "status": "healthy",
        "distilbert_model": "loaded",
        "ollama": {
            "online": ollama_health.online,
            "model_ready": ollama_health.model_ready,
            "model_name": ollama_health.model_name,
            "status": ollama_health.status_msg,
        },
        "timestamp": datetime.datetime.now().isoformat(),
    }


@app.post("/v1/scan", response_model=ScanResponse)
def scan_prompt(req: ScanRequest):
    start_time = time.time()
    prompt = req.prompt.strip()

    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")

    memory = get_session_memory(req.session_id)
    health_status = guardian_agent.check_health()
    guardian_active = health_status.online and health_status.model_ready

    # 1. Tier 1: Regex Sentinel
    sentinel_result = regex_sentinel.run(prompt)

    # 2. Tier 2: DistilBERT Analyst
    analyst_result = distilbert_analyst.run(prompt)

    # 3. Tier 3: Local Guardian (if ambiguous or REVIEW)
    run_guardian = (
        guardian_active
        and not sentinel_result.blocked
        and analyst_result.verdict != "BLOCK"
    )

    if run_guardian:
        guardian_result = guardian_agent.run(
            prompt,
            escalation_level=memory.escalation_level,
            consecutive_attacks=memory.consecutive_attacks,
            distilbert_score=analyst_result.score,
            health=health_status,
        )
    else:
        guardian_result = GuardianResult(
            enabled=False,
            verdict="SAFE",
            suspicion_score=0,
            attack_type="none",
            reasoning="Not evaluated",
            display_text="",
            policy=policy_engine.PolicyResult(False, [], "", "PASS", 0),
        )

    # 4. Aggregation
    report = threat_intel.aggregate(
        sentinel_result,
        analyst_result,
        guardian_result,
        memory_override=memory.personality_override,
    )

    # 5. Session Memory Update
    is_attack = report.action in ("BLOCK", "REVIEW")
    if is_attack:
        memory.add_attack(
            prompt=prompt,
            tier=report.blocked_by,
            label=report.attack_type,
            severity=report.severity,
            points=report.attacker_points,
        )
    else:
        memory.reset_streak()

    # Response generation
    if guardian_result.enabled and guardian_result.display_text:
        resp_msg = guardian_result.display_text
    else:
        resp_msg = generate_fallback_response(report, memory.consecutive_attacks)

    inference_ms = int((time.time() - start_time) * 1000)

    return ScanResponse(
        action=report.action,
        blocked=report.action == "BLOCK",
        blocked_by=report.blocked_by,
        severity=report.severity,
        severity_label=report.severity_label,
        threat_category=report.threat_category,
        attack_type=report.attack_type,
        response_message=resp_msg,
        escalation_level=memory.escalation_label,
        inference_ms=inference_ms,
        tier1=Tier1Detail(
            blocked=sentinel_result.blocked,
            rule_label=sentinel_result.pattern_label if sentinel_result.blocked else None,
        ),
        tier2=Tier2Detail(
            score=analyst_result.score,
            verdict=analyst_result.verdict,
            pct_malicious=analyst_result.pct_malicious,
        ),
        tier3=Tier3Detail(
            enabled=guardian_result.enabled,
            verdict=guardian_result.verdict,
            suspicion_score=guardian_result.suspicion_score,
            attack_type=guardian_result.attack_type,
            reasoning=guardian_result.reasoning,
        ),
        policy=PolicyDetail(
            action=guardian_result.policy.policy_action,
            violations_found=guardian_result.policy.violations_found,
            violations=guardian_result.policy.violations,
            redaction_count=guardian_result.policy.redaction_count,
        ),
    )


@app.post("/v1/sanitize", response_model=SanitizeResponse)
def sanitize_output(req: SanitizeRequest):
    res = policy_engine.check_output(req.output_text)
    return SanitizeResponse(
        policy_action=res.policy_action,
        violations_found=res.violations_found,
        violations=res.violations,
        redaction_count=res.redaction_count,
        sanitized_text=res.sanitized_text,
    )

