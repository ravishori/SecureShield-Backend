"""Adapters that turn each detector's EXISTING result into the shared ``scam_verdict/1`` contract.

Design rules (see docs/development/X1_IMPLEMENTATION_PLAN.md):

* Detection logic and thresholds are not changed here: every adapter reuses the detector's own score and its own cut-offs.
* Nothing is invented: evidence is what the detector actually matched; confidence is always ``null``.
* A provider outage is *neutral evidence plus a limitation*, never a clean result; a provider's "not listed" is neutral too
  (providers only know listed threats), so neither can ever produce ``safe``.
* No user-submitted content (URL, message text, phone numbers, payment details) is copied into a verdict.
* An adapter must never break an endpoint: :func:`safe_verdict` returns ``None`` if anything goes wrong.
"""

from __future__ import annotations

import logging
import math
from typing import Any, Callable, Dict, Iterable, List, Optional

from app.schemas.scam_verdict import (
    Action,
    Evidence,
    EvidenceKind,
    Polarity,
    Reason,
    RiskLevel,
    ScamVerdict,
    SourceType,
)
from app.services.threat_analyzer import Signal

logger = logging.getLogger(__name__)

ENGINE_URL = "url-heuristics/1"
ENGINE_MESSAGE = "message-patterns/1"
ENGINE_JOB = "job-offer-patterns/1"
ENGINE_AGGREGATE = "daily-alerts/1"

# The sender-registry adjustments the message router applies to its score (kept equal to the router's constants; a contract
# test compares the two).
SENDER_UNREGISTERED_BOOST = 20.0
SENDER_PHONE_NUMBER_BOOST = 10.0

_PROVIDERS = ("google_safe_browsing", "urlhaus")
_CATEGORY_CODE = {
    "malware": "threat_malware",
    "phishing": "threat_phishing",
    "unwanted_software": "threat_unwanted_software",
    "harmful_app": "threat_harmful_app",
    "exploit": "threat_exploit",
    "malicious_url": "threat_malicious_url",
}
_RAW_THREAT = {
    "MALWARE": "malware",
    "MALWARE_DOWNLOAD": "malware",
    "SOCIAL_ENGINEERING": "phishing",
    "PHISHING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted_software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful_app",
    "EXPLOIT": "exploit",
}
# Stored categories (link history keeps no signal list) that correspond to a heuristic signal code.
_STORED_CATEGORY_SIGNAL = {
    "known_scam_domain": "known_scam_domain",
    "phishing": "phishing_pattern",
    "insecure_http": "insecure_http",
    "ip_based_url": "ip_based_url",
}


def safe_verdict(
    build: Callable[..., ScamVerdict], *args: Any, **kwargs: Any
) -> Optional[ScamVerdict]:
    """Build a verdict, or return ``None`` if anything fails. Never raises, never logs submitted content."""
    try:
        return build(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - a verdict is additive and must never break the legacy response
        logger.warning("scam verdict adapter failed: %s", type(exc).__name__)
        return None


def _valid_score(score: Any) -> Optional[int]:
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    if isinstance(score, float) and (math.isnan(score) or math.isinf(score)):
        return None
    if score < 0 or score > 100:
        return None
    return int(round(score))


def _signal_evidence(signals: Iterable[Signal], source: str) -> List[Evidence]:
    out = []
    for s in signals:
        out.append(
            Evidence(
                kind=EvidenceKind.SIGNAL,
                polarity=Polarity.ADVERSE,
                code=s.code,
                source=source,
                weight=max(0, min(100, int(s.weight))),
                count=s.count if s.count > 1 else None,
            )
        )
    return out


def _ensure_evidence_for_level(
    level: RiskLevel,
    evidence: List[Evidence],
    reason_codes: List[str],
    score: int,
    source: str,
) -> None:
    """A medium-or-higher level must rest on evidence. If the detector gave a high score without itemised signals (a stored row,
    or a signal-less input), the detector's own score IS the evidence; record it as such instead of inventing a signal."""
    if level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL) and not any(
        e.polarity is Polarity.ADVERSE for e in evidence
    ):
        evidence.append(
            Evidence(
                kind=EvidenceKind.SIGNAL,
                polarity=Polarity.ADVERSE,
                code="detector_score",
                source=source,
                weight=min(100, score),
            )
        )
        reason_codes.append("detector_score")


def _dedupe_reasons(codes: Iterable[str]) -> List[Reason]:
    seen: List[str] = []
    for c in codes:
        if c not in seen:
            seen.append(c)
    return [Reason.of(c) for c in seen]


def _actions(*codes: str) -> List[Action]:
    return [Action.of(c) for c in codes]


# ======================================================================================================================
# URL
# ======================================================================================================================
def provider_outcome(envelope: Any) -> str:
    """'malicious' | 'not_listed' | 'unavailable'. Anything malformed, missing or inconclusive is 'unavailable'."""
    if not isinstance(envelope, dict):
        return "unavailable"
    status = envelope.get("status")
    if status == "malicious":
        return "malicious"
    if status == "safe":
        return "not_listed"
    return "unavailable"


def _provider_threat_categories(envelope: Any) -> List[str]:
    cats: List[str] = []
    threats = envelope.get("threats") if isinstance(envelope, dict) else None
    if isinstance(threats, list):
        for t in threats:
            raw = t.get("threat_type") if isinstance(t, dict) else None
            cat = _RAW_THREAT.get(raw) if isinstance(raw, str) else None
            if cat and cat not in cats:
                cats.append(cat)
    return cats or ["malicious_url"]


def _url_level(
    score: float, category: Optional[str], provider_malicious: bool
) -> RiskLevel:
    if provider_malicious or category == "known_scam_domain":
        return RiskLevel.CRITICAL
    if score >= 60:  # the detector's own is_malicious cut-off
        return RiskLevel.HIGH
    if score >= 40:  # the detector's own is_phishing cut-off
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _url_actions(level: RiskLevel) -> List[Action]:
    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return _actions("do_not_open", "do_not_enter_details", "report_to_authorities")
    if level is RiskLevel.MEDIUM:
        return _actions("verify_independently", "do_not_enter_details")
    return _actions("verify_independently")


def from_url_scan(
    *,
    risk_score: Any,
    threat_category: Optional[str],
    signals: Optional[List[Signal]],
    gsb: Any = None,
    urlhaus: Any = None,
    stored_only: bool = False,
) -> ScamVerdict:
    """Verdict for one link scan.

    ``gsb`` / ``urlhaus`` are the provider envelopes (anything malformed counts as unavailable). ``signals`` are the
    heuristic signals (``None`` when unknown, as for stored history rows, which fall back to the stored category).
    """
    score = _valid_score(risk_score)
    if score is None:
        return ScamVerdict.unknown(
            SourceType.URL, ENGINE_URL, "The scan result was missing or malformed."
        )

    outcomes = {
        "google_safe_browsing": provider_outcome(gsb),
        "urlhaus": provider_outcome(urlhaus),
    }
    envelopes = {"google_safe_browsing": gsb, "urlhaus": urlhaus}
    malicious_by = [p for p in _PROVIDERS if outcomes[p] == "malicious"]
    provider_malicious = bool(malicious_by)
    # the level uses the detector's own cut-offs on its UNROUNDED score; the rounded integer is only what is displayed
    level = _url_level(float(risk_score), threat_category, provider_malicious)

    evidence: List[Evidence] = []
    reason_codes: List[str] = []
    for p in _PROVIDERS:
        if outcomes[p] == "malicious":
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PROVIDER_RESULT,
                    polarity=Polarity.ADVERSE,
                    code="listed_malicious",
                    source=f"provider:{p}",
                )
            )
            reason_codes.append("provider_confirmed_malicious")
            for cat in _provider_threat_categories(envelopes[p]):
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.PROVIDER_RESULT,
                        polarity=Polarity.ADVERSE,
                        code=_CATEGORY_CODE[cat],
                        source=f"provider:{p}",
                    )
                )
        elif outcomes[p] == "not_listed":
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PROVIDER_RESULT,
                    polarity=Polarity.NEUTRAL,
                    code="not_listed",
                    source=f"provider:{p}",
                )
            )
        else:
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PROVIDER_UNAVAILABLE,
                    polarity=Polarity.NEUTRAL,
                    code="provider_unavailable",
                    source=f"provider:{p}",
                )
            )

    if signals is not None:
        evidence.extend(_signal_evidence(signals, "heuristic:url"))
        reason_codes.extend(s.code for s in signals)
    elif threat_category in _STORED_CATEGORY_SIGNAL:
        code = _STORED_CATEGORY_SIGNAL[threat_category]
        evidence.append(
            Evidence(
                kind=EvidenceKind.SIGNAL,
                polarity=Polarity.ADVERSE,
                code=code,
                source="heuristic:url",
                weight=None,
            )
        )
        reason_codes.append(code)
    if (
        signals is None
        and not any(e.polarity is Polarity.ADVERSE for e in evidence)
        and 0 < score < 40
    ):
        # stored low-score row with no recorded signals: the detector's own score is the only evidence there is
        evidence.append(
            Evidence(
                kind=EvidenceKind.SIGNAL,
                polarity=Polarity.ADVERSE,
                code="detector_score",
                source="heuristic:url",
                weight=min(100, score),
            )
        )
        reason_codes.append("detector_score")
    _ensure_evidence_for_level(level, evidence, reason_codes, score, "heuristic:url")

    all_unavailable = all(o == "unavailable" for o in outcomes.values())
    adverse = any(e.polarity is Polarity.ADVERSE for e in evidence)
    if all_unavailable:
        reason_codes.append("reputation_unavailable")
    if all_unavailable and not adverse:
        # outage with nothing independent to go on: legitimacy cannot be established, so this is UNKNOWN, not LOW
        return ScamVerdict(
            risk_level=RiskLevel.UNKNOWN,
            risk_score=None,
            reasons=[Reason.of("reputation_unavailable")],
            evidence=[
                e for e in evidence if e.kind is EvidenceKind.PROVIDER_UNAVAILABLE
            ],
            source_type=SourceType.URL,
            limitations=[
                "Only the form of the link is checked; the page itself is never opened.",
                "Reputation services were unavailable, so known-bad lists were not consulted and the link's legitimacy could not be established.",
                *(
                    ["Details were not stored for this earlier scan."]
                    if stored_only
                    else []
                ),
            ],
            recommended_actions=_actions("verify_independently"),
            engine_version=ENGINE_URL,
        )
    if not adverse:
        reason_codes.append("no_signals_found")
    # keep evidence within the contract's bound, adverse items first
    evidence.sort(key=lambda e: 0 if e.polarity is Polarity.ADVERSE else 1)
    evidence = evidence[:20]

    limitations = [
        "Only the form of the link is checked; the page itself is never opened."
    ]
    if all_unavailable:
        limitations.append(
            "Reputation services were unavailable, so known-bad lists were not consulted."
        )
    elif not provider_malicious:
        limitations.append(
            "Reputation services only know listed threats; 'not listed' is not proof that a link is safe."
        )
    if level is RiskLevel.LOW:
        limitations.append("No adverse signal does not mean the link is trustworthy.")
    if stored_only:
        limitations.append("Details were not stored for this earlier scan.")

    return ScamVerdict(
        risk_level=level,
        risk_score=score,
        reasons=_dedupe_reasons(reason_codes)[:20],
        evidence=evidence,
        source_type=SourceType.URL,
        limitations=limitations,
        recommended_actions=_url_actions(level),
        engine_version=ENGINE_URL,
    )


def from_stored_url_scan(
    *,
    scan_provider: Optional[str],
    is_malicious: bool,
    risk_score: Any,
    threat_category: Optional[str],
    gsb_threats: Any,
) -> ScamVerdict:
    """Verdict rebuilt from a stored link-history row (no signals and no provider envelopes were kept)."""
    provider = scan_provider if isinstance(scan_provider, str) else ""
    envelopes: Dict[str, Any] = {"gsb": None, "urlhaus": None}
    threats = gsb_threats if isinstance(gsb_threats, list) else []
    if is_malicious and provider in ("google_safe_browsing", "urlhaus"):
        envelopes["gsb" if provider == "google_safe_browsing" else "urlhaus"] = {
            "status": "malicious",
            "threats": threats,
        }
    elif provider == "google_safe_browsing+urlhaus":
        envelopes = {"gsb": {"status": "safe"}, "urlhaus": {"status": "safe"}}
    elif provider == "google_safe_browsing":
        envelopes["gsb"] = {"status": "safe"}
    elif provider == "urlhaus_clean_internal_score":
        envelopes["urlhaus"] = {"status": "safe"}
    # "internal_fallback" or anything unrecognised: both providers unavailable
    return from_url_scan(
        risk_score=risk_score,
        threat_category=threat_category,
        signals=None,
        gsb=envelopes["gsb"],
        urlhaus=envelopes["urlhaus"],
        stored_only=True,
    )


# ======================================================================================================================
# Message and job offer
# ======================================================================================================================
def _message_level(score: float) -> RiskLevel:
    if score >= 70:  # the detector's high_risk_scam cut-off
        return RiskLevel.CRITICAL
    if score >= 40:  # suspicious_message
        return RiskLevel.HIGH
    if score >= 20:  # potentially_suspicious
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def from_message(
    *, pattern_score: Any, signals: List[Signal], sender_verdict: Optional[str]
) -> ScamVerdict:
    """Verdict for a message from the PATTERN analysis only (never from an AI result), plus the sender-registry result.

    ``sender_verdict`` is the registry verdict string (REGISTERED, UNREGISTERED, PHONE_NUMBER, UNKNOWN) or ``None`` when no
    sender was supplied.
    """
    base = _valid_score(pattern_score)
    if base is None:
        return ScamVerdict.unknown(
            SourceType.MESSAGE,
            ENGINE_MESSAGE,
            "The message analysis result was missing or malformed.",
        )
    score = float(pattern_score)
    evidence = _signal_evidence(signals, "heuristic:message")
    reason_codes = [s.code for s in signals]
    limitations = [
        "Pattern matching only: it cannot understand context or intent.",
        "No external reputation or AI check was used.",
    ]
    if sender_verdict == "UNREGISTERED":
        score = min(score + SENDER_UNREGISTERED_BOOST, 100.0)
        evidence.append(
            Evidence(
                kind=EvidenceKind.REGISTRY_MATCH,
                polarity=Polarity.ADVERSE,
                code="sender_not_registered",
                source="registry:trai_sender",
                weight=20,
            )
        )
        reason_codes.append("sender_not_registered")
    elif sender_verdict == "PHONE_NUMBER":
        score = min(score + SENDER_PHONE_NUMBER_BOOST, 100.0)
        evidence.append(
            Evidence(
                kind=EvidenceKind.REGISTRY_MATCH,
                polarity=Polarity.ADVERSE,
                code="sender_is_phone_number",
                source="registry:trai_sender",
                weight=10,
            )
        )
        reason_codes.append("sender_is_phone_number")
    elif sender_verdict == "REGISTERED":
        # a registered sender id says nothing about whether THIS message is honest: positive about the sender, not the content
        evidence.append(
            Evidence(
                kind=EvidenceKind.REGISTRY_MATCH,
                polarity=Polarity.POSITIVE,
                code="sender_registered",
                source="registry:trai_sender",
            )
        )
        limitations.append(
            "A registered sender name does not prove that this message is genuine."
        )
    elif sender_verdict is None:
        limitations.append("No sender was supplied, so the sender was not checked.")
    else:
        limitations.append("The sender could not be verified against the registry.")
    final = int(round(score))
    level = _message_level(score)  # unrounded, like the detector's own cut-offs
    _ensure_evidence_for_level(
        level, evidence, reason_codes, final, "heuristic:message"
    )
    adverse = any(e.polarity is Polarity.ADVERSE for e in evidence)
    if not adverse:
        reason_codes.append("no_signals_found")
    if level is RiskLevel.LOW:
        limitations.append(
            "No adverse signal does not mean the message is trustworthy."
        )
    actions = (
        _actions(
            "do_not_open",
            "do_not_share_otp",
            "contact_bank_directly",
            "report_to_authorities",
        )
        if level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        else _actions("verify_independently", "do_not_share_otp")
    )
    evidence.sort(key=lambda e: 0 if e.polarity is Polarity.ADVERSE else 1)
    return ScamVerdict(
        risk_level=level,
        risk_score=final,
        reasons=_dedupe_reasons(reason_codes)[:20],
        evidence=evidence[:20],
        source_type=SourceType.MESSAGE,
        limitations=limitations,
        recommended_actions=actions,
        engine_version=ENGINE_MESSAGE,
    )


def from_job_offer(
    *, pattern_score: Any, is_fake: Any, signals: List[Signal]
) -> ScamVerdict:
    """Verdict for a job offer from the PATTERN analysis only. Its cut-off is the detector's own ``is_fake`` (score >= 50)."""
    score = _valid_score(pattern_score)
    if score is None or not isinstance(is_fake, bool):
        return ScamVerdict.unknown(
            SourceType.JOB_OFFER,
            ENGINE_JOB,
            "The job-offer analysis result was missing or malformed.",
        )
    evidence = _signal_evidence(signals, "heuristic:job_offer")
    reason_codes = [s.code for s in signals]
    if not evidence:
        reason_codes.append("no_signals_found")
    level = RiskLevel.HIGH if is_fake else RiskLevel.LOW
    _ensure_evidence_for_level(
        level, evidence, reason_codes, score, "heuristic:job_offer"
    )
    limitations = [
        "Wording analysis only: it cannot check whether the employer exists.",
        "No external reputation or AI check was used.",
    ]
    if level is RiskLevel.LOW:
        limitations.append(
            "No strong adverse signal does not mean the offer is genuine."
        )
    return ScamVerdict(
        risk_level=level,
        risk_score=score,
        reasons=_dedupe_reasons(reason_codes)[:20],
        evidence=evidence[:20],
        source_type=SourceType.JOB_OFFER,
        limitations=limitations,
        recommended_actions=_actions(
            "do_not_pay", "verify_independently", "report_to_authorities"
        )
        if is_fake
        else _actions("verify_independently", "do_not_pay"),
        engine_version=ENGINE_JOB,
    )


# ======================================================================================================================
# Daily aggregate (F05, API only)
# ======================================================================================================================
def from_daily_report(
    *, threats_detected: Any, apps_scanned: Any, links_scanned: Any, calls_analyzed: Any
) -> ScamVerdict:
    """API-only aggregate verdict.

    Risk evidence is ONLY the alerts recorded that day (each alert is a detector outcome). **Scan activity is never risk
    evidence**: the number of apps, links or calls checked is used solely to tell "nothing was checked" (unknown) from
    "checks ran and raised no alert" (low). The score is the existing per-alert weight (10 points per alert, capped at 100)
    and the levels use the existing report cut-offs (25 / 50 / 75). The dashboard's own score and wording are unchanged.
    """
    counts = [threats_detected, apps_scanned, links_scanned, calls_analyzed]
    if any(isinstance(c, bool) or not isinstance(c, int) or c < 0 for c in counts):
        return ScamVerdict.unknown(
            SourceType.DAILY_AGGREGATE,
            ENGINE_AGGREGATE,
            "The daily counts were missing or malformed.",
        )
    limitations = [
        "Counts alerts raised that day only; the severity of each alert is not included.",
        "Scan activity is not used as risk evidence, and behaviour events are not included.",
        "This is not the dashboard protection score; that score also counts scan activity (tracked as F05-1).",
    ]
    checks_ran = (apps_scanned + links_scanned + calls_analyzed) > 0
    if threats_detected == 0 and not checks_ran:
        return ScamVerdict(
            risk_level=RiskLevel.UNKNOWN,
            risk_score=None,
            reasons=[Reason.of("no_activity")],
            evidence=[],
            source_type=SourceType.DAILY_AGGREGATE,
            limitations=limitations,
            recommended_actions=[],
            engine_version=ENGINE_AGGREGATE,
        )
    score = min(threats_detected * 10, 100)
    if score >= 75:
        level = RiskLevel.CRITICAL
    elif score >= 50:
        level = RiskLevel.HIGH
    elif score >= 25:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
    evidence: List[Evidence] = []
    reasons: List[Reason]
    if threats_detected > 0:
        evidence.append(
            Evidence(
                kind=EvidenceKind.SIGNAL,
                polarity=Polarity.ADVERSE,
                code="alerts_recorded",
                source="aggregate:alerts",
                weight=min(100, score),
                count=min(threats_detected, 10_000),
            )
        )
        reasons = [Reason.of("alerts_recorded")]
    else:
        reasons = [Reason.of("no_signals_found")]
    return ScamVerdict(
        risk_level=level,
        risk_score=score,
        reasons=reasons,
        evidence=evidence,
        source_type=SourceType.DAILY_AGGREGATE,
        limitations=limitations,
        recommended_actions=_actions("review_alerts") if threats_detected > 0 else [],
        engine_version=ENGINE_AGGREGATE,
    )
