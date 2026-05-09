"""
Central risk-scoring engine for SecureShield AI.

Formula (weights sum to 1.0):
  score = perm_score   * 0.35   # dangerous permissions
        + source_score * 0.25   # install source provenance
        + clone_score  * 0.30   # clone / fake-app probability
        + behav_score  * 0.10   # overlay / accessibility abuse

  0–33  → safe
  34–66 → warning
  67–100→ danger
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List

_PERM_W   = 0.35
_SOURCE_W = 0.25
_CLONE_W  = 0.30
_BEHAV_W  = 0.10

_KNOWN_STORES = {
    "com.android.vending",          # Google Play
    "com.amazon.venezia",           # Amazon Appstore
    "com.sec.android.app.samsungapps",
    "org.fdroid.fdroid",
    "com.huawei.appmarket",
    "com.xiaomi.market",
}


@dataclass
class RiskResult:
    score:  int             # 0-100 aggregate risk score
    level:  str             # safe / warning / danger
    tags:   List[str] = field(default_factory=list)   # human-readable signals

    # Component breakdown (useful for UI detail views)
    perm_contribution:   int = 0
    source_contribution: int = 0
    clone_contribution:  int = 0
    behav_contribution:  int = 0


def compute_risk(
    dangerous_perm_count: int,
    is_unknown_source: bool,
    installer: str | None,
    clone_probability: int,     # 0-100 (from clone analyzer)
    has_overlay: bool = False,
    has_accessibility: bool = False,
) -> RiskResult:
    """
    Compute an aggregate risk score (0-100) for an installed app.

    All inputs are observable from Android PackageManager + AppOpsManager.
    clone_probability is provided by the CloneAnalyzer service.
    """
    tags: List[str] = []

    # ── Permission component (0-35 pts) ──────────────────────────────────────
    perm_norm  = min(1.0, dangerous_perm_count / 5.0)
    perm_pts   = int(perm_norm * 100 * _PERM_W)
    if dangerous_perm_count >= 5:
        tags.append(f"Requests {dangerous_perm_count} sensitive permissions (very high)")
    elif dangerous_perm_count >= 3:
        tags.append(f"Requests {dangerous_perm_count} sensitive permissions")
    elif dangerous_perm_count >= 1:
        tags.append(f"Requests {dangerous_perm_count} sensitive permission(s)")

    # ── Source component (0-25 pts) ───────────────────────────────────────────
    if is_unknown_source or installer is None:
        source_pts = int(100 * _SOURCE_W)
        tags.append("Sideloaded from unknown source — not from Play Store")
    elif installer in _KNOWN_STORES:
        source_pts = 0
    else:
        # Known but third-party store
        source_pts = int(30 * _SOURCE_W)
        tags.append(f"Installed via non-standard store: {installer}")

    # ── Clone component (0-30 pts) ─────────────────────────────────────────────
    clone_pts = int(clone_probability * _CLONE_W)
    if clone_probability >= 85:
        tags.append("Very high similarity to a known legitimate app — likely fake/clone")
    elif clone_probability >= 65:
        tags.append("Significant similarity to a known legitimate app")
    elif clone_probability >= 40:
        tags.append("Moderate similarity to a known app — verify before trusting")

    # ── Behaviour component (0-10 pts) ──────────────────────────────────────────
    behav_pts = 0
    if has_overlay:
        behav_pts += int(50 * _BEHAV_W)
        tags.append("Can draw over other apps (overlay) — phishing risk")
    if has_accessibility:
        behav_pts += int(50 * _BEHAV_W)
        tags.append("Registered as accessibility service — can read screen contents")

    # ── Aggregate ──────────────────────────────────────────────────────────────
    total = max(0, min(100, perm_pts + source_pts + clone_pts + behav_pts))

    if total >= 67:
        level = "danger"
    elif total >= 34:
        level = "warning"
    else:
        level = "safe"

    return RiskResult(
        score=total,
        level=level,
        tags=tags,
        perm_contribution=perm_pts,
        source_contribution=source_pts,
        clone_contribution=clone_pts,
        behav_contribution=behav_pts,
    )


def risk_level_from_score(score: int) -> str:
    if score >= 67:
        return "danger"
    if score >= 34:
        return "warning"
    return "safe"
