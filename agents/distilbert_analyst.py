"""Tier 2 — DistilBERT Analyst Agent.

Runs the fine-tuned DistilBERT classifier and returns a structured result.
Model loading is lazy/cached so it happens once per process.
"""

import torch
import torch.nn.functional as F
from dataclasses import dataclass
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
from utils.config import MODEL_DIR, SAFE_THRESHOLD, BLOCK_THRESHOLD

_tokenizer = None
_model = None


def _load():
    global _tokenizer, _model
    if _model is None:
        _tokenizer = DistilBertTokenizer.from_pretrained(MODEL_DIR)
        _model = DistilBertForSequenceClassification.from_pretrained(MODEL_DIR)
        _model.eval()


def score_prompt(prompt: str) -> float:
    """Returns P(malicious) in [0, 1]."""
    _load()
    inputs = _tokenizer(
        prompt, return_tensors="pt", truncation=True, padding=True, max_length=256
    )
    with torch.no_grad():
        logits = _model(**inputs).logits
        probs = F.softmax(logits, dim=1)
    return probs[0][1].item()


def get_token_scores(prompt: str) -> list[tuple[str, float]]:
    """Returns per-token importance scores for explainability.

    Tries attention weights first; falls back to gradient-free input-norm
    proxy if the model config does not expose attentions.
    """
    _load()
    inputs = _tokenizer(
        prompt, return_tensors="pt", truncation=True, padding=True, max_length=256
    )
    tokens = _tokenizer.convert_ids_to_tokens(inputs["input_ids"][0])

    # ── Attempt 1: attention weights ────────────────────────────────────────
    try:
        with torch.no_grad():
            outputs = _model(**inputs, output_attentions=True)
        attentions = outputs.attentions  # tuple of tensors, one per layer
        if attentions and len(attentions) > 0:
            attn = attentions[-1]           # (1, heads, seq, seq)
            cls_attn = attn[0].mean(0)[0]  # (seq,) — CLS attending to each token
            scores = cls_attn.tolist()
            return _build_pairs(tokens, scores)
    except Exception:
        pass

    # ── Fallback: embedding L2 norm as token importance proxy ────────────────
    try:
        with torch.no_grad():
            emb = _model.distilbert.embeddings(inputs["input_ids"])  # (1, seq, hidden)
            norms = emb[0].norm(dim=-1).tolist()                     # (seq,)
        return _build_pairs(tokens, norms)
    except Exception:
        pass

    # ── Last resort: uniform scores ──────────────────────────────────────────
    return _build_pairs(tokens, [1.0] * len(tokens))


def _build_pairs(tokens: list[str], scores: list[float]) -> list[tuple[str, float]]:
    skip = {"[CLS]", "[SEP]", "[PAD]"}
    pairs = [(tok, sc) for tok, sc in zip(tokens, scores) if tok not in skip]
    if pairs:
        max_sc = max(sc for _, sc in pairs) or 1.0
        pairs = [(tok, sc / max_sc) for tok, sc in pairs]
    return pairs


@dataclass
class AnalystResult:
    score: float          # P(malicious)
    verdict: str          # "ALLOW" | "REVIEW" | "BLOCK"
    token_scores: list[tuple[str, float]]
    agent: str = "DistilBERT Analyst"

    @property
    def pct_malicious(self) -> float:
        return self.score * 100

    @property
    def pct_safe(self) -> float:
        return (1 - self.score) * 100


def run(prompt: str) -> AnalystResult:
    score = score_prompt(prompt)
    if score < SAFE_THRESHOLD:
        verdict = "ALLOW"
    elif score < BLOCK_THRESHOLD:
        verdict = "REVIEW"
    else:
        verdict = "BLOCK"

    token_scores = get_token_scores(prompt)
    return AnalystResult(score=score, verdict=verdict, token_scores=token_scores)
