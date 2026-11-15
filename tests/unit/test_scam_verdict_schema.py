"""scam_verdict/1: strict schema, cross-field invariants, registries (no database, no network)."""

import pytest
from pydantic import ValidationError

from app.schemas.scam_verdict import (
    ACTION_TEXT,
    REASON_TEXT,
    Action,
    Evidence,
    EvidenceKind,
    Polarity,
    Reason,
    RiskLevel,
    ScamVerdict,
    SourceType,
)

LIM = ["Only the form of the link is checked."]


def adverse(code="insecure_http", source="heuristic:url"):
    return Evidence(
        kind=EvidenceKind.SIGNAL,
        polarity=Polarity.ADVERSE,
        code=code,
        source=source,
        weight=15,
    )


def positive():
    return Evidence(
        kind=EvidenceKind.REGISTRY_MATCH,
        polarity=Polarity.POSITIVE,
        code="registry_header_match",
        source="registry:trai_sender",
    )


def make(**over):
    base = dict(
        risk_level=RiskLevel.MEDIUM,
        risk_score=45,
        reasons=[Reason.of("insecure_http")],
        evidence=[adverse()],
        source_type=SourceType.URL,
        limitations=LIM,
        recommended_actions=[Action.of("verify_independently")],
        engine_version="url-heuristics/1",
    )
    base.update(over)
    return ScamVerdict(**base)


# ------------------------------------------------------------------------------------------------ valid shapes
def test_a_complete_verdict_is_valid_and_versioned():
    v = make()
    assert v.schema_version == 1 and v.confidence is None
    assert ScamVerdict.model_validate_json(v.model_dump_json()) == v  # JSON round trip


def test_the_nine_required_fields_and_the_version_are_serialised():
    d = make().model_dump(mode="json")
    assert set(d) == {
        "schema_version",
        "risk_level",
        "risk_score",
        "reasons",
        "evidence",
        "source_type",
        "confidence",
        "limitations",
        "recommended_actions",
        "engine_version",
    }


def test_low_without_any_adverse_evidence_needs_the_no_signals_reason():
    v = make(
        risk_level=RiskLevel.LOW,
        risk_score=0,
        reasons=[Reason.of("no_signals_found")],
        evidence=[],
    )
    assert v.risk_level is RiskLevel.LOW
    with pytest.raises(ValidationError):
        make(risk_level=RiskLevel.LOW, risk_score=0, reasons=[], evidence=[])


def test_low_may_carry_weak_adverse_signals():
    assert make(risk_level=RiskLevel.LOW, risk_score=15).risk_level is RiskLevel.LOW


# ------------------------------------------------------------------------------------------------ risk-level / score invariants
@pytest.mark.parametrize("score", [0, 1, 50, 99, 100])
def test_score_boundaries_accepted(score):
    assert make(risk_score=score).risk_score == score


@pytest.mark.parametrize("score", [-1, 101, 1000])
def test_score_outside_0_100_is_rejected(score):
    with pytest.raises(ValidationError):
        make(risk_score=score)


def test_unknown_requires_a_null_score_and_only_unknown_may_have_one():
    v = ScamVerdict.unknown(SourceType.URL, "url-heuristics/1")
    assert (v.risk_level, v.risk_score) == (RiskLevel.UNKNOWN, None)
    with pytest.raises(ValidationError):
        make(risk_level=RiskLevel.UNKNOWN, risk_score=0)  # an unknown with a score
    with pytest.raises(ValidationError):
        make(
            risk_level=RiskLevel.LOW,
            risk_score=None,
            reasons=[Reason.of("no_signals_found")],
            evidence=[],
        )  # a score-less server verdict


def test_unknown_is_never_safe_and_the_factory_makes_no_claims():
    v = ScamVerdict.unknown(SourceType.MESSAGE, "message-patterns/1")
    assert (
        v.risk_level is not RiskLevel.SAFE and v.recommended_actions and v.limitations
    )


@pytest.mark.parametrize(
    "level", [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
)
def test_risk_levels_need_adverse_evidence_and_a_reason(level):
    assert make(risk_level=level).risk_level is level
    with pytest.raises(ValidationError):
        make(risk_level=level, evidence=[])
    with pytest.raises(ValidationError):
        make(risk_level=level, reasons=[])
    neutral = Evidence(
        kind=EvidenceKind.PROVIDER_RESULT,
        polarity=Polarity.NEUTRAL,
        code="not_listed",
        source="provider:urlhaus",
    )
    with pytest.raises(ValidationError):
        make(
            risk_level=level, evidence=[neutral]
        )  # "not listed" is not adverse evidence


def test_safe_needs_positive_evidence_and_no_adverse_evidence():
    ok = make(
        risk_level=RiskLevel.SAFE, risk_score=0, reasons=[], evidence=[positive()]
    )
    assert ok.risk_level is RiskLevel.SAFE
    with pytest.raises(ValidationError):
        make(
            risk_level=RiskLevel.SAFE, risk_score=0, reasons=[], evidence=[]
        )  # nothing found is not safe
    with pytest.raises(ValidationError):
        make(
            risk_level=RiskLevel.SAFE,
            risk_score=0,
            reasons=[],
            evidence=[positive(), adverse()],
        )  # contradictory signals


# ------------------------------------------------------------------------------------------------ providers are never trust evidence
def test_a_reputation_provider_cannot_supply_positive_evidence():
    with pytest.raises(ValidationError):
        Evidence(
            kind=EvidenceKind.REGISTRY_MATCH,
            polarity=Polarity.POSITIVE,
            code="registry_header_match",
            source="provider:google_safe_browsing",
        )
    with pytest.raises(ValidationError):
        Evidence(
            kind=EvidenceKind.POSITIVE,
            polarity=Polarity.POSITIVE,
            code="not_listed",
            source="provider:urlhaus",
        )


def test_a_provider_outage_is_neutral_and_must_name_a_provider():
    Evidence(
        kind=EvidenceKind.PROVIDER_UNAVAILABLE,
        polarity=Polarity.NEUTRAL,
        code="provider_unavailable",
        source="provider:urlhaus",
    )
    with pytest.raises(ValidationError):
        Evidence(
            kind=EvidenceKind.PROVIDER_UNAVAILABLE,
            polarity=Polarity.ADVERSE,
            code="provider_unavailable",
            source="provider:urlhaus",
        )
    with pytest.raises(ValidationError):
        Evidence(
            kind=EvidenceKind.PROVIDER_UNAVAILABLE,
            polarity=Polarity.NEUTRAL,
            code="provider_unavailable",
            source="heuristic:url",
        )


def test_a_provider_outage_plus_nothing_found_can_never_validate_as_safe():
    outage = Evidence(
        kind=EvidenceKind.PROVIDER_UNAVAILABLE,
        polarity=Polarity.NEUTRAL,
        code="provider_unavailable",
        source="provider:urlhaus",
    )
    with pytest.raises(ValidationError):
        make(risk_level=RiskLevel.SAFE, risk_score=0, reasons=[], evidence=[outage])


# ------------------------------------------------------------------------------------------------ strictness
def test_confidence_must_be_null_in_version_1():
    for c in (0.0, 0.5, 1.0, 87):
        with pytest.raises(ValidationError):
            make(confidence=c)


def test_limitations_are_mandatory_and_bounded():
    with pytest.raises(ValidationError):
        make(limitations=[])
    with pytest.raises(ValidationError):
        make(limitations=["  "])
    with pytest.raises(ValidationError):
        make(limitations=["x" * 201])
    with pytest.raises(ValidationError):
        make(limitations=["ok"] * 11)


def test_extra_fields_and_wrong_versions_are_rejected():
    d = make().model_dump(mode="json")
    with pytest.raises(ValidationError):
        ScamVerdict.model_validate({**d, "surprise": 1})
    with pytest.raises(ValidationError):
        ScamVerdict.model_validate({**d, "schema_version": 2})


def test_reasons_and_actions_must_come_from_the_registries_with_the_registered_text():
    with pytest.raises(ValidationError):
        Reason(code="made_up", text="x")
    with pytest.raises(ValidationError):
        Reason(
            code="insecure_http", text="free text containing http://victim.example"
        )  # no user content can enter
    with pytest.raises(ValidationError):
        Action(code="block_link", text="Block it.")
    with pytest.raises(ValidationError):
        Evidence(
            kind=EvidenceKind.SIGNAL,
            polarity=Polarity.ADVERSE,
            code="not_a_code",
            source="heuristic:url",
        )
    with pytest.raises(ValidationError):
        Evidence(
            kind=EvidenceKind.SIGNAL,
            polarity=Polarity.ADVERSE,
            code="insecure_http",
            source="http://evil.example/x",
        )


def test_duplicate_codes_and_oversized_lists_are_rejected():
    with pytest.raises(ValidationError):
        make(reasons=[Reason.of("insecure_http"), Reason.of("insecure_http")])
    with pytest.raises(ValidationError):
        make(recommended_actions=[Action.of("do_not_pay"), Action.of("do_not_pay")])
    with pytest.raises(ValidationError):
        make(reasons=[Reason.of(c) for c in list(REASON_TEXT)[:21]])
    with pytest.raises(ValidationError):
        make(evidence=[adverse()] * 21)


@pytest.mark.parametrize(
    "bad", ["", "URL", "url", "url-heuristics", "url heuristics/1", "x/1"]
)
def test_engine_version_must_look_like_name_slash_number(bad):
    with pytest.raises(ValidationError):
        make(engine_version=bad)


@pytest.mark.parametrize("raw", ["safe ", "SAFE!", "ok", "", None, 0, "none"])
def test_unrecognised_levels_fail_instead_of_becoming_safe(raw):
    d = make().model_dump(mode="json")
    d["risk_level"] = raw
    with pytest.raises(ValidationError):
        ScamVerdict.model_validate(d)


def test_the_contract_has_no_blocking_action():
    words = ("block", "quarantine", "delete", "uninstall", "disable", "remove", "wipe")
    for code, text in ACTION_TEXT.items():
        assert not any(w in code.lower() or w in text.lower() for w in words), code


def test_every_registered_reason_text_is_fixed_english_without_placeholders():
    for code, text in REASON_TEXT.items():
        assert text and "{" not in text and "%s" not in text and len(text) <= 200, code


@pytest.mark.parametrize(
    "source", ["qr", "fake_bank_sms", "digital_arrest", "payment_screenshot"]
)
def test_rule_based_detectors_may_report_no_score_but_never_for_unknown_with_a_score(
    source,
):
    v = make(
        source_type=SourceType(source),
        risk_score=None,
        risk_level=RiskLevel.HIGH,
        engine_version="qr-rules/1",
    )
    assert v.risk_score is None and v.risk_level is RiskLevel.HIGH
    with pytest.raises(ValidationError):
        make(
            source_type=SourceType(source), risk_score=10, risk_level=RiskLevel.UNKNOWN
        )


@pytest.mark.parametrize("source", ["url", "message", "job_offer", "daily_aggregate"])
def test_server_detectors_must_carry_a_score_unless_unknown(source):
    with pytest.raises(ValidationError):
        make(source_type=SourceType(source), risk_score=None)
