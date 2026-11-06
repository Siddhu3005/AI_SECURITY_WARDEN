"""Cyberpunk / SOC dashboard CSS — SENTINEL AI Security Warden."""

DARK_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700&display=swap');

/* ── Base ── */
html, body, [class*="css"] {
    background-color: #0a0e1a !important;
    color: #c9d1d9 !important;
    font-family: 'Share Tech Mono', monospace !important;
}
.main .block-container { padding-top: 0.5rem; max-width: 1440px; }

/* ── Header ── */
.sentinel-header {
    text-align: center;
    padding: 1.2rem 0 0.4rem;
    border-bottom: 1px solid #1e3a5f;
    margin-bottom: 1rem;
}
.sentinel-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 2.2rem;
    font-weight: 700;
    background: linear-gradient(135deg, #00d4ff, #0080ff, #7b2fff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: 4px;
    margin: 0;
}
.sentinel-subtitle { color: #58a6ff; font-size: 0.72rem; letter-spacing: 3px; margin-top: 3px; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #1e3a5f;
}

/* ── Chat messages ── */
[data-testid="stChatMessage"] {
    background: #0d1117 !important;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    margin-bottom: 6px;
}
[data-testid="stChatInput"] > div {
    background: #0d1117 !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 8px;
}
[data-testid="stChatInput"] textarea { background: #0d1117 !important; color: #c9d1d9 !important; }

/* ── Metrics ── */
[data-testid="stMetric"] {
    background: #0d1117;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 8px;
}
[data-testid="stMetricValue"] { color: #58a6ff !important; }

/* ── Progress bars ── */
.stProgress > div > div > div { background: linear-gradient(90deg, #00d4ff, #0080ff) !important; }

/* ── Expanders ── */
details { background: #0d1117 !important; border: 1px solid #1e3a5f !important; border-radius: 6px; }
summary { color: #58a6ff !important; }

/* ── Severity badges ── */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: bold;
    letter-spacing: 1px;
    font-family: 'Orbitron', sans-serif;
}
.badge-critical { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
.badge-high     { background: #2d1a00; color: #ff8800; border: 1px solid #ff8800; }
.badge-medium   { background: #2d2a00; color: #ffcc00; border: 1px solid #ffcc00; }
.badge-low      { background: #002d1a; color: #00cc77; border: 1px solid #00cc77; }
.badge-safe     { background: #002d1a; color: #00ff99; border: 1px solid #00ff99; }

/* ── Threat category chips ── */
.cat-chip {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-family: 'Orbitron', sans-serif;
    letter-spacing: 1px;
    border: 1px solid;
}
.cat-SAFE               { background:#002d1a; color:#00ff99; border-color:#00ff99; }
.cat-SUSPICIOUS         { background:#2d2a00; color:#ffcc00; border-color:#ffcc00; }
.cat-PROMPT_INJECTION   { background:#2d1a00; color:#ff8800; border-color:#ff8800; }
.cat-SOCIAL_ENGINEERING { background:#1a0033; color:#cc66ff; border-color:#cc66ff; }
.cat-OFFENSIVE_SECURITY { background:#3d0000; color:#ff4444; border-color:#ff4444; }
.cat-DATA_EXFILTRATION  { background:#3d0000; color:#ff2222; border-color:#ff2222; }
.cat-ROLEPLAY_JAILBREAK { background:#2d0022; color:#ff44cc; border-color:#ff44cc; }
.cat-POLICY_EVASION     { background:#2d1400; color:#ff6600; border-color:#ff6600; }

/* ── Terminal log ── */
.terminal-log {
    background: #070b12;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 10px 14px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    color: #39ff14;
    max-height: 200px;
    overflow-y: auto;
    line-height: 1.6;
}
.terminal-log .ts    { color: #555; }
.terminal-log .tier1 { color: #ff4444; }
.terminal-log .tier2 { color: #ffaa00; }
.terminal-log .tier3 { color: #00d4ff; }
.terminal-log .ok    { color: #39ff14; }
.terminal-log .warn  { color: #ffcc00; }

/* ── Threat meter ── */
.threat-bar-wrap {
    width: 100%;
    background: #1a1f2e;
    border-radius: 4px;
    height: 8px;
    overflow: hidden;
    margin: 4px 0 10px;
}
.threat-bar-fill { height: 8px; border-radius: 4px; }

/* ── Confidence display ── */
.conf-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 5px 0;
    font-size: 0.8rem;
}
.conf-label { width: 80px; font-size: 0.7rem; letter-spacing: 1px; }
.conf-bar-wrap { flex: 1; background: #1a1f2e; border-radius: 3px; height: 10px; overflow: hidden; }
.conf-bar-fill { height: 10px; border-radius: 3px; }
.conf-pct { width: 44px; text-align: right; font-family: 'Orbitron', sans-serif; font-size: 0.75rem; }

/* ── Token attention ── */
.tok-safe   { color: #c9d1d9; }
.tok-warn   { color: #ffcc00; font-weight: bold; }
.tok-danger { color: #ff4444; font-weight: bold; text-decoration: underline; }

/* ── Tier badge ── */
.tier-badge {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.6rem;
    letter-spacing: 1.5px;
    padding: 2px 7px;
    border-radius: 3px;
    display: inline-block;
    margin-right: 3px;
}
.tier-blocked { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
.tier-passed  { background: #002d1a; color: #00cc77; border: 1px solid #00cc77; }
.tier-review  { background: #2d2a00; color: #ffcc00; border: 1px solid #ffcc00; }
.tier-skip    { background: #111;    color: #555;    border: 1px solid #333; }

/* ── Warden message ── */
.warden-msg {
    background: #070b12;
    border-left: 3px solid #00d4ff;
    border-radius: 0 6px 6px 0;
    padding: 10px 14px;
    margin: 6px 0;
    font-size: 0.93rem;
    color: #c9d1d9;
    line-height: 1.55;
}
.warden-msg.blocked { border-left-color: #ff4444; }
.warden-msg.review  { border-left-color: #ffcc00; }
.warden-msg.safe    { border-left-color: #00ff99; }

/* ── Policy violation banner ── */
.policy-banner {
    background: #1a0a00;
    border: 1px solid #ff6600;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 0.75rem;
    color: #ff6600;
    margin: 6px 0;
    font-family: 'Orbitron', sans-serif;
    letter-spacing: 1px;
}

/* ── Navigation bar ── */
.nav-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #0d1117;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 6px 12px;
    margin-bottom: 10px;
    font-size: 0.75rem;
}
.nav-counter {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.7rem;
    color: #58a6ff;
    letter-spacing: 1px;
}

/* ── Telemetry panel ── */
.telemetry-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 3px 0;
    border-bottom: 1px solid #111;
    font-size: 0.75rem;
}
.telemetry-key { color: #555; }
.telemetry-val { color: #58a6ff; font-family: 'Orbitron', sans-serif; font-size: 0.7rem; }
.telemetry-val.red    { color: #ff4444; }
.telemetry-val.yellow { color: #ffcc00; }
.telemetry-val.green  { color: #00ff99; }

/* ── Rank card ── */
.rank-card {
    background: linear-gradient(135deg, #0d1117, #101824);
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 8px 12px;
    text-align: center;
}
.rank-title { font-family: 'Orbitron', sans-serif; font-size: 0.6rem; letter-spacing: 2px; color: #58a6ff; }
.rank-label { font-size: 1rem; font-weight: bold; color: #00d4ff; margin-top: 2px; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #0a0e1a; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #0050aa, #0080ff) !important;
    color: white !important;
    border: none !important;
    border-radius: 6px !important;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: 1px;
}
.stButton > button:hover { background: linear-gradient(135deg, #0080ff, #00d4ff) !important; }

/* ── Dividers ── */
hr { border-color: #1e3a5f !important; }

/* ── Local inference badges ── */
.local-badge {
    display: inline-block;
    padding: 3px 14px;
    border-radius: 20px;
    font-size: 0.68rem;
    font-family: 'Orbitron', sans-serif;
    letter-spacing: 2px;
    background: #001a0d;
    color: #00ff99;
    border: 1px solid #00ff99;
    animation: pulse-green 2.5s ease-in-out infinite;
}
.local-badge-warn {
    display: inline-block;
    padding: 3px 14px;
    border-radius: 20px;
    font-size: 0.68rem;
    font-family: 'Orbitron', sans-serif;
    letter-spacing: 2px;
    background: #1a1400;
    color: #ffcc00;
    border: 1px solid #ffcc00;
}
@keyframes pulse-green {
    0%, 100% { box-shadow: 0 0 4px #00ff9955; }
    50%       { box-shadow: 0 0 14px #00ff99aa; }
}
</style>
"""


# ── HTML helpers ─────────────────────────────────────────────────────────────

def severity_bar_html(severity: float, label: str) -> str:
    pct = int(severity * 100)
    color = (
        "#ff4444" if severity >= 0.85 else
        "#ff8800" if severity >= 0.65 else
        "#ffcc00" if severity >= 0.35 else
        "#00cc77"
    )
    return (
        f'<div style="margin:4px 0">'
        f'<div style="display:flex;justify-content:space-between;font-size:0.72rem;color:#888;margin-bottom:3px">'
        f'<span>THREAT LEVEL</span>'
        f'<span style="color:{color};font-family:Orbitron,sans-serif">{label} — {pct}%</span></div>'
        f'<div class="threat-bar-wrap">'
        f'<div class="threat-bar-fill" style="width:{pct}%;background:linear-gradient(90deg,#0080ff,{color})"></div>'
        f'</div></div>'
    )


def confidence_bars_html(pct_safe: float, pct_mal: float) -> str:
    """Large prominent confidence bars for safe/malicious percentages."""
    safe_w = int(pct_safe)
    mal_w  = int(pct_mal)
    mal_color = "#ff4444" if pct_mal >= 65 else "#ff8800" if pct_mal >= 30 else "#ffcc00"
    return (
        f'<div style="margin:8px 0">'
        # Safe row
        f'<div class="conf-row">'
        f'<span class="conf-label" style="color:#00cc77">SAFE</span>'
        f'<div class="conf-bar-wrap">'
        f'<div class="conf-bar-fill" style="width:{safe_w}%;background:linear-gradient(90deg,#005533,#00cc77)"></div>'
        f'</div>'
        f'<span class="conf-pct" style="color:#00cc77">{pct_safe:.1f}%</span>'
        f'</div>'
        # Malicious row
        f'<div class="conf-row">'
        f'<span class="conf-label" style="color:{mal_color}">MALICIOUS</span>'
        f'<div class="conf-bar-wrap">'
        f'<div class="conf-bar-fill" style="width:{mal_w}%;background:linear-gradient(90deg,#550000,{mal_color})"></div>'
        f'</div>'
        f'<span class="conf-pct" style="color:{mal_color}">{pct_mal:.1f}%</span>'
        f'</div>'
        f'</div>'
    )


def cat_chip_html(category: str) -> str:
    return f'<span class="cat-chip cat-{category}">{category.replace("_", " ")}</span>'


def badge_html(label: str, cls: str) -> str:
    return f'<span class="badge badge-{cls}">{label}</span>'


def tier_badge(tier: str, status: str) -> str:
    css = {
        "BLOCKED": "tier-blocked", "PASSED": "tier-passed",
        "REVIEW": "tier-review",   "SKIP": "tier-skip",
        "SAFE": "tier-passed", "SUSPICIOUS": "tier-review",
    }
    return f'<span class="tier-badge {css.get(status, "tier-skip")}">{tier}: {status}</span>'


def warden_msg_html(text: str, kind: str = "safe") -> str:
    return f'<div class="warden-msg {kind}">🤖 <b>SENTINEL:</b> {text}</div>'


def telemetry_row_html(key: str, value: str, color: str = "") -> str:
    val_class = f"telemetry-val {color}" if color else "telemetry-val"
    return (
        f'<div class="telemetry-row">'
        f'<span class="telemetry-key">{key}</span>'
        f'<span class="{val_class}">{value}</span>'
        f'</div>'
    )


def policy_banner_html(count: int, violations: list[str]) -> str:
    vlist = " · ".join(violations[:3])
    return (
        f'<div class="policy-banner">'
        f'⚠ POLICY ENGINE: {count} UNSAFE PATTERN(S) REDACTED<br>'
        f'<span style="font-size:0.62rem;color:#aa4400">{vlist}</span>'
        f'</div>'
    )
