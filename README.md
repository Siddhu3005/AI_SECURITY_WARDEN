# AI Security Warden — Multi-Agent Prompt Injection Defense Platform

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![PyTorch](https://img.shields.io/badge/PyTorch-Deep_Learning-EE4C2C.svg)
![Transformers](https://img.shields.io/badge/HuggingFace-Transformers-F9AB00.svg)
![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-black.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-SOC_Dashboard-FF4B4B.svg)

## Overview

Large Language Models are highly vulnerable to adversarial attacks — specifically **Prompt Injections**, **Jailbreaks**, and **Social Engineering** attempts. This project implements a **defense-in-depth multi-agent security platform** that detects and responds to these attacks through three independent, sequential defense tiers, backed by a policy enforcement layer, session memory, and an explainable SOC-style dashboard.

The system evolved from a two-tier classifier into a full multi-agent architecture, where each layer covers the blind spots of the previous one. No single detection method is sufficient — the combination is what makes it effective.

> **All LLM inference runs locally via Ollama. No user data is sent to any external API.**

---

## Architecture — Full Pipeline

```
User Input (Streamlit SOC Interface)
        │
        ▼
┌─────────────────────────────┐
│  TIER 1 — Regex Sentinel    │  ── BLOCKED → (rule label returned)
│  26 verb-object patterns    │
└─────────────────────────────┘
        │ (pass)
        ▼
┌─────────────────────────────┐
│  TIER 2 — DistilBERT        │  ── BLOCKED (≥ 0.65)
│  Analyst Agent              │  ── REVIEW  (0.30–0.65) ──┐
│  Fine-tuned transformer     │                           │
└─────────────────────────────┘                           │
        │ (< 0.30 / REVIEW) ◄──────────────────────────────┘
        ▼
┌─────────────────────────────┐
│  TIER 3 — Guardian AI       │  Local qwen3:8b via Ollama
│  Intent & manipulation      │  Structured verdict + reasoning
│  analysis                   │
└─────────────────────────────┘
        │
        ▼
┌─────────────────────────────┐
│  POLICY ENFORCEMENT LAYER   │  ── Dangerous payloads REDACTED
│  Output scanning +          │     (surgical replacement)
│  surgical redaction         │
└─────────────────────────────┘
        │
        ▼
┌─────────────────────────────┐
│  THREAT INTEL + MEMORY      │  ThreatReport aggregation
│  Session escalation         │  4-level threat escalation
└─────────────────────────────┘
        │
        ▼
  SOC Dashboard (Response + Explainability)
```

---

## Defense Layers

### Tier 1 — Regex Sentinel Agent

A fast, flexible NLP filter built around **verb-object pattern pairs**. Acts as the first line of defense and returns a human-readable rule label on every match.

- **26 labeled patterns** targeting specific attack intents: payload generation, instruction override, data exfiltration, filter bypass, SSRF, phishing
- **Bidirectional matching** — catches commands even when word order is reversed
- **Morphological flexibility** — handles progressive suffixes, filler words, and common misspellings
- Returns a `SentinelResult` dataclass with the matched rule label, not just a boolean
- Runs in microseconds — zero ML overhead

### Tier 2 — DistilBERT Analyst Agent

Prompts that pass Tier 1 undergo semantic analysis using a fine-tuned `distilbert-base-uncased` sequence classification model.

- **Three-zone decision system:**
  - `BLOCK` — score ≥ 0.65 (high confidence malicious)
  - `REVIEW` — score 0.30–0.65 (ambiguous, forwarded to Tier 3)
  - `ALLOW` — score < 0.30 (low confidence, logged)
- Trained on a data-centric aggregated dataset (see Datasets section)
- Weighted cross-entropy loss (malicious class 3×) to handle class imbalance
- Max sequence length: 256 tokens | Train/test split: 85% / 15%
- Returns token attention scores for explainability visualization

**Model Performance:**
| Metric | Score |
|--------|-------|
| Accuracy | 93.68% |
| Precision | 95.83% |
| Recall | 92.00% |
| F1 Score | 93.87% |

### Tier 3 — Local Guardian AI Agent

Prompts that are not clearly resolved by Tiers 1–2 are forwarded to a locally-hosted LLM for deep intent analysis.

- **Model:** `qwen3:8b` running via **Ollama** (fully local, offline, no API key required)
- Detects subtle manipulation patterns: roleplay jailbreaks, emotional manipulation, hypothetical framing, gradual escalation, indirect injection
- Returns a **structured verdict** with four required fields:
  ```
  [GUARDIAN_VERDICT]   SAFE / SUSPICIOUS / MALICIOUS
  [SUSPICION_SCORE]    0–100
  [ATTACK_TYPE]        8-category taxonomy (see below)
  [REASONING]          Human-readable explanation
  ```
- Chain-of-thought disabled (`think=False`) to reduce latency and prevent reasoning block leakage
- Hardened system prompt with **6 absolute safety rules** — never outputs real payloads or exploit instructions

**8-Category Threat Taxonomy:**

| Category | Description |
|----------|-------------|
| `SAFE` | No threat detected |
| `SUSPICIOUS` | Ambiguous intent |
| `PROMPT_INJECTION` | Direct instruction override attempt |
| `SOCIAL_ENGINEERING` | Manipulation / deception |
| `OFFENSIVE_SECURITY` | Exploit / payload request |
| `DATA_EXFILTRATION` | Credential or data extraction attempt |
| `ROLEPLAY_JAILBREAK` | Persona hijacking / DAN-style attack |
| `POLICY_EVASION` | Indirect evasion attempt |

### Policy Enforcement Layer

A second, independent scanning layer that runs on the **Guardian's output** — not the user's input. This was added after testing revealed the LLM could occasionally generate real exploit code inside educational explanations, even with safety rules in its system prompt.

- Scans both code blocks and inline text for dangerous patterns:
  - SQL `UNION SELECT` / `DROP TABLE`
  - XSS `<script>` tags and `onerror`/`onload` handlers
  - Reverse shell strings (`nc`, `/dev/tcp/`, Python socket shells)
  - `base64` encoded execution, `rm -rf /`, `curl|bash` chains
  - Metasploit references, `/etc/passwd` paths, `document.cookie` exfiltration
- **Surgical redaction** — replaces only the dangerous string, preserving surrounding text
- Replacement format: `[⚠ POLICY ENGINE: TYPE — REDACTED FOR SAFETY]`
- Returns a `PolicyResult` dataclass tracking violation count and types

### Session Memory & Threat Escalation

The `MemoryAgent` tracks attack patterns across the session and escalates the system's response posture automatically.

- Tracks: total attack count, consecutive attacks, unique attack types, time since last attack
- **4 escalation levels:** `NORMAL` → `SUSPICIOUS` → `PARANOID` → `MAXIMUM THREAT`
- Higher escalation levels modify the Guardian's system prompt for more aggressive analysis

---

## Explainable AI Features

Every decision in the pipeline is traceable:

- **Token attention heatmap** — shows which tokens the DistilBERT model focused on (3-level fallback: attention weights → embedding L2 norms → uniform scores)
- **Safe vs. Malicious confidence bars** — live percentage display for every interaction
- **Tier transparency** — which tier triggered, the exact regex rule label, ML score, Guardian reasoning, and policy violations are all shown explicitly
- **7-row telemetry panel** — tier triggered, score, attack type, regex rule, escalation level, inference time, redaction count

---

## SOC-Style Dashboard

The Streamlit interface is designed around a Security Operations Center aesthetic.

- **Single-interaction navigation** — `← PREV / NEXT →` buttons instead of a scrolling chat history, for easier review during demos or investigations
- **3-column pipeline status cards** — T1 / T2 / T3 result at a glance
- **Color-coded threat category chip** per interaction
- **Sidebar:** session metrics (total prompts, blocked, redacted), Ollama health status, local inference time, interaction history log
- **Red Team mode** — gamified attack scoring
- Pulsing `LOCAL INFERENCE` badge — visual confirmation that no data leaves the machine

---

## Datasets Used

The DistilBERT model was trained on an aggregated, balanced dataset combining real-world attack examples with large benign corpora to minimize false positives on technical queries.

**Malicious (Label 1):**
- [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) — foundational manipulation tactics
- [Prompt Injection in the Wild (Kaggle)](https://www.kaggle.com/datasets/arielzilber/prompt-injection-in-the-wild) — real-world adversarial attack variety

**Benign (Label 0):**
- [yahma/alpaca-cleaned](https://huggingface.co/datasets/yahma/alpaca-cleaned) — general non-malicious interactions
- [sahil2801/CodeAlpaca-20k](https://huggingface.co/datasets/sahil2801/CodeAlpaca-20k) — software engineering and database queries (critical for avoiding false positives on technical text)

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| ML Model | PyTorch, HuggingFace Transformers (DistilBERT) |
| Local LLM | Ollama + qwen3:8b |
| Data Processing | Pandas, NumPy, Scikit-Learn |
| Dashboard | Streamlit |
| Pattern Matching | Python `re` (Regular Expressions) |
| Configuration | python-dotenv |

---

## Setup & Running

### Prerequisites

- Python 3.9+
- [Ollama](https://ollama.com) installed and running
- qwen3:8b pulled: `ollama pull qwen3:8b`

### Installation

```bash
pip install -r requirements.txt
```

### Configuration

Copy `.env.example` to `.env` and adjust if needed:

```env
OLLAMA_MODEL=qwen3:8b
OLLAMA_HOST=http://localhost:11434
```

### Run

```bash
streamlit run app.py
```

The dashboard will check Ollama health on startup. Tiers 1 and 2 work offline; Tier 3 requires Ollama to be running.

---

## Project Structure

```
prompt_injection_detection_model/
├── app.py                        # Streamlit SOC dashboard
├── api.py                        # FastAPI REST gateway (/v1/scan, /v1/sanitize)
├── client_example.py             # Middleware proxy client demo
├── test_suite.py                 # Automated 23-point unit/integration test suite
├── benchmark.py                  # Performance & latency benchmark tool
├── train.py                      # DistilBERT fine-tuning script
├── requirements.txt
├── Dockerfile                    # Container definition
├── docker-compose.yml            # Multi-service container orchestration
├── .github/workflows/ci.yml      # Automated GitHub Actions CI workflow
├── agents/
│   ├── regex_sentinel.py         # Tier 1 — pattern matching
│   ├── distilbert_analyst.py     # Tier 2 — ML classifier
│   ├── guardian_agent.py         # Tier 3 — local LLM via Ollama
│   ├── policy_engine.py          # Output scanning + redaction
│   ├── threat_intel.py           # ThreatReport aggregation
│   ├── memory_agent.py           # Session memory + escalation
│   └── personality_engine.py     # Warden response personality
├── prompts/
│   └── guardian_prompt.py        # Hardened system prompt + safety rules
└── ui/
    └── styles.py                 # SOC-themed CSS + UI helpers
```

---

## Screenshots

#### Regex blocking:

<img width="945" height="452" alt="image" src="https://github.com/user-attachments/assets/5d2af342-3812-4db3-be3f-7ec7f190a8dc" />

#### DistilBERT blocking:

<img width="945" height="386" alt="image" src="https://github.com/user-attachments/assets/539ba94b-92d0-41b2-9ba5-3ceca18de06f" />

#### qwen3:8b blocking:

<img width="945" height="502" alt="image" src="https://github.com/user-attachments/assets/d585805e-1073-45e0-84d6-e4412349983a" />

#### Policy enforcement layer:

<img width="945" height="453" alt="image" src="https://github.com/user-attachments/assets/8fb6ca11-2930-4638-9093-5aa3ec87d8c0" />

--

<img width="945" height="489" alt="image" src="https://github.com/user-attachments/assets/97e31394-3052-40f1-bd85-4d88cc3b5b72" />

---

## About This Project

This project was developed as a university project in AI and cybersecurity, focusing on LLM security, adversarial machine learning, and defense-in-depth architectures. The system evolved from a simple binary classifier into a full multi-agent platform as each layer's limitations became clear during development and testing.

## Author

Fatmagül Fırtına — Computer Engineering Student, Dokuz Eylül University
