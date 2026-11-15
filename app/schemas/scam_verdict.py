"""Shared, versioned scam-verdict contract (``scam_verdict/1``).

One explainable shape that every detector can report in, so the app can show risk consistently. It is **advisory only**:
nothing in it blocks, quarantines or reports anything automatically.

Rules enforced here (each has a test in ``tests/unit/test_scam_verdict_schema.py``):

* ``unknown`` is its own level and is never coerced to ``safe``; ``risk_score`` is ``null`` when the level is ``unknown`` and
  also, only for the rule-based on-device detectors (QR, fake-bank SMS, digital-arrest, payment screenshot), when the detector
  reports no 0-100 score; a score is never invented for them. Server detectors always carry the detector's own score.
* ``safe`` needs at least one trustworthy positive evidence item and no adverse evidence. Provider "not listed" and
  provider outages are *neutral*: a reputation provider can never supply positive evidence.
* ``medium``, ``high`` and ``critical`` need at least one adverse evidence item and one reason (no risk without evidence).
* ``low`` means "no known adverse signals, legitimacy unverified". With no adverse evidence it must carry the reason
  ``no_signals_found``.
* ``confidence`` is ``null`` in version 1 for every detector (none produces a calibrated probability).
* ``limitations`` is never empty: every detector has things it did not check.
* Reasons, evidence and actions use fixed registries of codes and fixed English text, so no user-submitted content
  (URL, message text, phone number, payment address, amount) can enter a verdict, and clients can localise by code.
* Unknown or malformed input fails validation; it is never repaired into ``safe``.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = 1


class RiskLevel(StrEnum):
    UNKNOWN = "unknown"
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(StrEnum):
    URL = "url"
    MESSAGE = "message"
    JOB_OFFER = "job_offer"
    QR = "qr"
    FAKE_BANK_SMS = "fake_bank_sms"
    DIGITAL_ARREST = "digital_arrest"
    PAYMENT_SCREENSHOT = "payment_screenshot"
    DAILY_AGGREGATE = "daily_aggregate"


# Detectors that classify by rules and report a category, not a 0-100 score. Their non-unknown verdicts may have a null score.
RULE_BASED_SOURCES = frozenset(
    {"qr", "fake_bank_sms", "digital_arrest", "payment_screenshot"}
)


class EvidenceKind(StrEnum):
    SIGNAL = "signal"
    PROVIDER_RESULT = "provider_result"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    REGISTRY_MATCH = "registry_match"
    POSITIVE = "positive"


class Polarity(StrEnum):
    ADVERSE = "adverse"  # counts toward risk
    NEUTRAL = "neutral"  # recorded, proves nothing either way (provider "not listed", outage, absent data)
    POSITIVE = "positive"  # trustworthy evidence of legitimacy (never from a reputation provider)


# ---------------------------------------------------------------------------------------------------------------- registries
REASON_TEXT = {
    "no_signals_found": "No risk signals were found by the built-in checks.",
    "reputation_unavailable": "Reputation services could not be consulted.",
    "analysis_unavailable": "The analysis could not be completed.",
    "provider_confirmed_malicious": "A reputation service lists this link as dangerous.",
    "known_scam_domain": "The link points to a domain on the built-in scam list.",
    "phishing_pattern": "The web address imitates a well-known brand.",
    "insecure_http": "The link does not use an encrypted connection.",
    "long_url": "The web address is unusually long.",
    "suspicious_keyword": "The web address contains words often used in scams.",
    "ip_based_url": "The link uses a numeric IP address instead of a name.",
    "many_subdomains": "The web address has an unusual number of sub-domains.",
    "threat_malware": "The listed threat type is malware.",
    "threat_phishing": "The listed threat type is phishing.",
    "threat_unwanted_software": "The listed threat type is unwanted software.",
    "threat_harmful_app": "The listed threat type is a potentially harmful application.",
    "threat_exploit": "The listed threat type is an exploit.",
    "threat_malicious_url": "The link is listed as malicious.",
    "detector_score": "The built-in checks gave an elevated score.",
    "scam_message_pattern": "The message matches known scam wording.",
    "fake_job_wording": "The text contains wording typical of fake job offers.",
    "risky_link_in_message": "The message contains a link that looks risky.",
    "urgency_language": "The message pressures you to act immediately.",
    "financial_bait": "The message promises money or prizes.",
    "sender_not_registered": "The sender name is not in the telecom sender registry.",
    "sender_is_phone_number": "The message came from an ordinary phone number, not a registered business sender.",
    "job_suspicious_phrase": "The offer uses phrases typical of fake jobs.",
    "job_upfront_payment": "The offer asks for payment before any work.",
    "job_unrealistic_income": "The offer promises unrealistic income.",
    "job_messaging_app_hiring": "The offer asks you to apply through a chat app.",
    "job_no_company_name": "The offer does not name a company.",
    "job_artificial_urgency": "The offer pressures you with artificial urgency.",
    "alerts_recorded": "Security alerts were recorded for this day.",
    "no_activity": "Nothing was checked on this day.",
    "rule_matches": "The detector's rules flagged this item.",
}
# Evidence codes: every reason code plus the codes below (which describe an observation rather than a conclusion).
EVIDENCE_EXTRA = {
    "listed_malicious",
    "not_listed",
    "provider_unavailable",
    "sender_registered",
    "registry_header_match",
    "verified_payment_suffix",
}
EVIDENCE_CODES = frozenset(REASON_TEXT) | EVIDENCE_EXTRA

ACTION_TEXT = {
    "verify_independently": "If you did not expect this, check it another way before acting.",
    "do_not_open": "Do not open the link.",
    "do_not_enter_details": "Do not enter passwords, OTPs or card details.",
    "do_not_pay": "Do not make any payment.",
    "do_not_share_otp": "Do not share OTPs or PINs with anyone.",
    "contact_bank_directly": "Contact your bank using the number printed on your card or on its official website.",
    "report_to_authorities": "Consider reporting this to the national cyber-crime portal.",
    "review_alerts": "Review the alerts raised today.",
}
# Advisory only. The contract has no code that blocks, deletes, quarantines or reports on the user's behalf.

_SOURCE_RE = re.compile(
    r"^(heuristic|provider|registry|rule|aggregate|detector):[a-z0-9_+.\-]{1,48}$"
)
_ENGINE_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{1,48}/[0-9]{1,3}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Reason(_Strict):
    code: str
    text: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def _registered(self) -> "Reason":
        if self.code not in REASON_TEXT:
            raise ValueError(f"unknown reason code: {self.code!r}")
        if self.text != REASON_TEXT[self.code]:
            raise ValueError("reason text must be the registered text (no free text)")
        return self

    @classmethod
    def of(cls, code: str) -> "Reason":
        return cls(code=code, text=REASON_TEXT[code])


class Evidence(_Strict):
    kind: EvidenceKind
    polarity: Polarity
    code: str
    source: str
    weight: Optional[int] = Field(default=None, ge=0, le=100)
    count: Optional[int] = Field(default=None, ge=1, le=10_000)

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        if not _SOURCE_RE.match(v):
            raise ValueError("source must look like 'heuristic:url' (no free text)")
        return v

    @model_validator(mode="after")
    def _rules(self) -> "Evidence":
        if self.code not in EVIDENCE_CODES:
            raise ValueError(f"unknown evidence code: {self.code!r}")
        if (
            self.kind is EvidenceKind.POSITIVE
            and self.polarity is not Polarity.POSITIVE
        ):
            raise ValueError("positive evidence must have positive polarity")
        if self.polarity is Polarity.POSITIVE and self.kind not in (
            EvidenceKind.POSITIVE,
            EvidenceKind.REGISTRY_MATCH,
        ):
            raise ValueError(
                "only registry matches or explicit positive evidence can be positive"
            )
        if self.polarity is Polarity.POSITIVE and self.source.startswith("provider:"):
            raise ValueError(
                "a reputation provider can never supply positive trust evidence ('not listed' is neutral)"
            )
        if (
            self.kind is EvidenceKind.PROVIDER_UNAVAILABLE
            and self.polarity is not Polarity.NEUTRAL
        ):
            raise ValueError("a provider outage is neutral evidence")
        if self.kind in (
            EvidenceKind.PROVIDER_RESULT,
            EvidenceKind.PROVIDER_UNAVAILABLE,
        ) and not self.source.startswith("provider:"):
            raise ValueError("provider evidence must name a provider source")
        return self


class Action(_Strict):
    code: str
    text: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def _registered(self) -> "Action":
        if self.code not in ACTION_TEXT:
            raise ValueError(f"unknown action code: {self.code!r}")
        if self.text != ACTION_TEXT[self.code]:
            raise ValueError("action text must be the registered text")
        return self

    @classmethod
    def of(cls, code: str) -> "Action":
        return cls(code=code, text=ACTION_TEXT[code])


class ScamVerdict(_Strict):
    schema_version: Literal[1] = SCHEMA_VERSION
    risk_level: RiskLevel
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    reasons: List[Reason] = Field(default_factory=list, max_length=20)
    evidence: List[Evidence] = Field(default_factory=list, max_length=20)
    source_type: SourceType
    confidence: Optional[float] = None
    limitations: List[str] = Field(min_length=1, max_length=10)
    recommended_actions: List[Action] = Field(default_factory=list, max_length=10)
    engine_version: str

    @field_validator("engine_version")
    @classmethod
    def _engine(cls, v: str) -> str:
        if not _ENGINE_RE.match(v):
            raise ValueError("engine_version must look like 'url-heuristics/1'")
        return v

    @field_validator("limitations")
    @classmethod
    def _limitations(cls, v: List[str]) -> List[str]:
        for item in v:
            if not item.strip() or len(item) > 200:
                raise ValueError("each limitation must be 1-200 characters")
        return v

    @model_validator(mode="after")
    def _invariants(self) -> "ScamVerdict":
        if self.confidence is not None:
            raise ValueError(
                "confidence must be null in scam_verdict/1: no detector produces a calibrated probability"
            )
        unknown = self.risk_level is RiskLevel.UNKNOWN
        if unknown and self.risk_score is not None:
            raise ValueError("an 'unknown' verdict must not carry a score")
        if (
            not unknown
            and self.risk_score is None
            and self.source_type.value not in RULE_BASED_SOURCES
        ):
            raise ValueError(
                "risk_score may be null only for 'unknown' (or for rule-based detectors that report no score)"
            )
        if len({r.code for r in self.reasons}) != len(self.reasons):
            raise ValueError("duplicate reason codes")
        if len({a.code for a in self.recommended_actions}) != len(
            self.recommended_actions
        ):
            raise ValueError("duplicate action codes")
        adverse = any(e.polarity is Polarity.ADVERSE for e in self.evidence)
        positive = any(e.polarity is Polarity.POSITIVE for e in self.evidence)
        if self.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
            if not adverse or not self.reasons:
                raise ValueError(
                    "medium, high and critical need adverse evidence and at least one reason"
                )
        if self.risk_level is RiskLevel.SAFE:
            if not positive or adverse:
                raise ValueError(
                    "'safe' needs positive evidence and no adverse evidence"
                )
        if self.risk_level is RiskLevel.LOW and not adverse:
            if "no_signals_found" not in {r.code for r in self.reasons}:
                raise ValueError(
                    "'low' without adverse evidence must carry the reason 'no_signals_found'"
                )
        return self

    @classmethod
    def unknown(
        cls,
        source_type: SourceType,
        engine_version: str,
        limitation: str = "The analysis could not be completed, so no judgement is made.",
        evidence: Optional[List[Evidence]] = None,
    ) -> "ScamVerdict":
        """The safe degradation: nothing could be assessed. Never `safe`, never a score."""
        return cls(
            risk_level=RiskLevel.UNKNOWN,
            risk_score=None,
            reasons=[Reason.of("analysis_unavailable")],
            evidence=evidence or [],
            source_type=source_type,
            limitations=[limitation],
            recommended_actions=[Action.of("verify_independently")],
            engine_version=engine_version,
        )
