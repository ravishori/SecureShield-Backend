"""Adapters: each detector's existing result -> scam_verdict/1. Boundaries, provider failure, timeout, malformed and
contradictory inputs, privacy and the 'never safe from absence' rules (no database, no network)."""

import math

import pytest

from app.schemas.scam_verdict import (
    ACTION_TEXT,
    EVIDENCE_CODES,
    EvidenceKind,
    Polarity,
    RiskLevel,
    ScamVerdict,
)
from app.services import scam_verdict_adapters as ad
from app.services import threat_analyzer as t
from app.services.threat_analyzer import Signal

ALLOWED_ACTIONS = set(ACTION_TEXT)


def env(status, threats=None, reason=None):
    return {
        "status": status,
        "safe": status == "safe",
        "threats": threats or [],
        "provider": "x",
        "reason": reason,
        "http_status": None,
        "cached": False,
    }


MAL = env("malicious", [{"threat_type": "SOCIAL_ENGINEERING"}])
SAFE = env("safe")
OUT = [
    env(s)
    for s in (
        "no_api_key",
        "rate_limited",
        "network_error",
        "http_error",
        "unknown_error",
    )
]


def url(score=0, category=None, signals=(), gsb=None, uh=None):
    return ad.from_url_scan(
        risk_score=score,
        threat_category=category,
        signals=list(signals),
        gsb=gsb,
        urlhaus=uh,
    )


def codes(v, attr):
    return {x.code for x in getattr(v, attr)}


def assert_clean(v):
    """Rules every verdict must satisfy."""
    assert v.confidence is None and v.schema_version == 1
    assert v.limitations
    assert {a.code for a in v.recommended_actions} <= ALLOWED_ACTIONS
    assert {e.code for e in v.evidence} <= EVIDENCE_CODES
    assert not any(
        e.polarity is Polarity.POSITIVE and e.source.startswith("provider:")
        for e in v.evidence
    )
    ScamVerdict.model_validate_json(v.model_dump_json())  # always re-validates


# ------------------------------------------------------------------------------------------------ URL levels use the detector's own cut-offs
@pytest.mark.parametrize(
    "score,expected",
    [
        (0, RiskLevel.LOW),
        (5, RiskLevel.LOW),
        (39.9, RiskLevel.LOW),
        (40, RiskLevel.MEDIUM),
        (59.9, RiskLevel.MEDIUM),
        (60, RiskLevel.HIGH),
        (89.9, RiskLevel.HIGH),
        (100, RiskLevel.HIGH),
    ],
)
def test_url_score_boundaries(score, expected):
    sig = [Signal("insecure_http", 15)] if score else []
    v = url(score, signals=sig, gsb=SAFE, uh=SAFE)
    assert v.risk_level is expected
    assert_clean(v)


def test_a_known_scam_domain_and_a_provider_hit_are_critical():
    assert (
        url(90, "known_scam_domain", [Signal("known_scam_domain", 90)]).risk_level
        is RiskLevel.CRITICAL
    )
    v = url(95, "phishing", [], gsb=MAL, uh=SAFE)
    assert (
        v.risk_level is RiskLevel.CRITICAL
        and "listed_malicious" in codes(v, "evidence")
        and "threat_phishing" in codes(v, "evidence")
    )
    assert_clean(v)


# ------------------------------------------------------------------------------------------------ provider failure, timeout, malformed
def assert_outage_unknown(v):
    """All reputation providers down and nothing independent found: UNKNOWN, never LOW/SAFE, no 'analysis complete' claim."""
    assert v.risk_level is RiskLevel.UNKNOWN and v.risk_score is None
    assert v.confidence is None
    assert codes(v, "reasons") == {"reputation_unavailable"}
    assert "no_signals_found" not in codes(v, "reasons")
    assert [e.kind for e in v.evidence] == [EvidenceKind.PROVIDER_UNAVAILABLE] * 2
    assert any("legitimacy could not be established" in lim for lim in v.limitations)
    assert_clean(v)


@pytest.mark.parametrize("failure", OUT, ids=lambda e: e["status"])
def test_every_provider_failure_is_an_outage_never_a_clean_result(failure):
    v = url(0, None, [], gsb=failure, uh=failure)
    assert_outage_unknown(v)


def test_a_timeout_envelope_is_an_outage():
    timeout = env("network_error", reason="timeout")
    v = url(0, None, [], gsb=timeout, uh=timeout)
    assert_outage_unknown(v)


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "malicious",
        7,
        [],
        {},
        {"status": None},
        {"status": 5},
        {"status": "weird"},
        {"status": "MALICIOUS"},
    ],
)
def test_malformed_provider_envelopes_count_as_unavailable(bad):
    assert ad.provider_outcome(bad) == "unavailable"
    v = url(0, None, [], gsb=bad, uh=bad)
    assert_outage_unknown(v)


def test_one_provider_unavailable_but_another_valid_is_low_not_unknown():
    for first, second in ((SAFE, OUT[2]), (OUT[2], SAFE)):
        v = url(0, None, [], gsb=first, uh=second)
        assert v.risk_level is RiskLevel.LOW and v.risk_score == 0
        assert "no_signals_found" in codes(v, "reasons")
        assert "reputation_unavailable" not in codes(v, "reasons")
        assert {"not_listed", "provider_unavailable"} <= codes(v, "evidence")
        assert_clean(v)


def test_outage_plus_independent_adverse_heuristic_keeps_both_facts():
    v = url(55, "ip_based_url", [Signal("ip_based_url", 55)], gsb=OUT[2], uh=OUT[2])
    assert v.risk_level is RiskLevel.MEDIUM and v.risk_score == 55
    assert {"reputation_unavailable", "ip_based_url"} <= codes(v, "reasons")
    assert "no_signals_found" not in codes(v, "reasons")
    assert_clean(v)


def test_provider_not_listed_is_neutral_and_never_positive_trust_evidence():
    v = url(0, None, [], gsb=SAFE, uh=SAFE)
    assert (
        v.risk_level is RiskLevel.LOW
    )  # not SAFE; analysis was complete and found nothing adverse
    assert "no_signals_found" in codes(v, "reasons")
    assert [(e.code, e.polarity) for e in v.evidence] == [
        ("not_listed", Polarity.NEUTRAL)
    ] * 2
    assert "reputation_unavailable" not in codes(v, "reasons")
    assert any("not proof" in lim for lim in v.limitations)
    assert_clean(v)


def test_outage_and_not_listed_are_distinguishable_from_each_other():
    outage = url(0, None, [], gsb=OUT[2], uh=OUT[2])
    clean = url(0, None, [], gsb=SAFE, uh=SAFE)
    assert codes(outage, "evidence") != codes(clean, "evidence")
    assert "reputation_unavailable" in codes(
        outage, "reasons"
    ) and "reputation_unavailable" not in codes(clean, "reasons")


# ------------------------------------------------------------------------------------------------ contradictory signals
def test_one_provider_malicious_and_the_other_not_listed_is_critical_with_both_recorded():
    v = url(
        90,
        "malware",
        [],
        gsb=SAFE,
        uh=env("malicious", [{"threat_type": "MALWARE_DOWNLOAD"}]),
    )
    assert v.risk_level is RiskLevel.CRITICAL
    assert {"listed_malicious", "not_listed", "threat_malware"} <= codes(v, "evidence")


def test_not_listed_does_not_cancel_strong_heuristics():
    sig = [Signal("phishing_pattern", 70)]
    v = url(70, "phishing", sig, gsb=SAFE, uh=SAFE)
    assert v.risk_level is RiskLevel.HIGH
    assert "phishing_pattern" in codes(v, "reasons")


def test_provider_outage_does_not_hide_strong_heuristics():
    v = url(
        75,
        "phishing",
        [Signal("phishing_pattern", 70), Signal("insecure_http", 5)],
        gsb=OUT[3],
        uh=OUT[0],
    )
    assert v.risk_level is RiskLevel.HIGH and "reputation_unavailable" in codes(
        v, "reasons"
    )


def test_provider_hit_wins_even_when_the_heuristics_found_nothing():
    v = url(0, None, [], gsb=MAL, uh=OUT[1])
    assert v.risk_level is RiskLevel.CRITICAL


# ------------------------------------------------------------------------------------------------ malformed scores degrade to unknown
@pytest.mark.parametrize(
    "bad", [None, "55", True, False, float("nan"), float("inf"), -1, 101, [], {}]
)
def test_a_missing_or_malformed_score_is_unknown_with_a_null_score(bad):
    v = url(bad, None, [], gsb=SAFE, uh=SAFE)
    assert (v.risk_level, v.risk_score) == (RiskLevel.UNKNOWN, None)
    assert v.risk_level is not RiskLevel.SAFE
    assert_clean(v)


# ------------------------------------------------------------------------------------------------ stored history rows
@pytest.mark.parametrize(
    "provider,malicious,expect_outage,expect_not_listed",
    [
        ("internal_fallback", False, True, False),
        ("google_safe_browsing", False, False, True),
        ("urlhaus_clean_internal_score", False, False, True),
        ("google_safe_browsing+urlhaus", False, False, True),
        ("something_new", False, True, False),
        (None, False, True, False),
    ],
)
def test_stored_rows_rebuild_the_provider_picture_and_say_details_were_not_kept(
    provider, malicious, expect_outage, expect_not_listed
):
    v = ad.from_stored_url_scan(
        scan_provider=provider,
        is_malicious=malicious,
        risk_score=0.0,
        threat_category=None,
        gsb_threats=None,
    )
    assert v.risk_level is (RiskLevel.UNKNOWN if expect_outage else RiskLevel.LOW)
    assert (v.risk_score is None) == expect_outage
    assert ("reputation_unavailable" in codes(v, "reasons")) == expect_outage
    assert ("not_listed" in codes(v, "evidence")) == expect_not_listed
    assert any("not stored" in lim for lim in v.limitations)
    assert_clean(v)


def test_a_stored_provider_hit_is_critical_and_a_stored_score_without_category_still_has_evidence():
    v = ad.from_stored_url_scan(
        scan_provider="google_safe_browsing",
        is_malicious=True,
        risk_score=95.0,
        threat_category="phishing",
        gsb_threats=[{"threat_type": "SOCIAL_ENGINEERING"}],
    )
    assert v.risk_level is RiskLevel.CRITICAL
    v2 = ad.from_stored_url_scan(
        scan_provider="internal_fallback",
        is_malicious=False,
        risk_score=55.0,
        threat_category=None,
        gsb_threats=None,
    )
    assert v2.risk_level is RiskLevel.MEDIUM and "detector_score" in codes(
        v2, "evidence"
    )
    v3 = ad.from_stored_url_scan(
        scan_provider="internal_fallback",
        is_malicious=True,
        risk_score=90.0,
        threat_category="known_scam_domain",
        gsb_threats=None,
    )
    assert v3.risk_level is RiskLevel.CRITICAL


# ------------------------------------------------------------------------------------------------ messages
@pytest.mark.parametrize(
    "score,expected",
    [
        (0, RiskLevel.LOW),
        (19.9, RiskLevel.LOW),
        (20, RiskLevel.MEDIUM),
        (39.9, RiskLevel.MEDIUM),
        (40, RiskLevel.HIGH),
        (69.9, RiskLevel.HIGH),
        (70, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_message_boundaries_follow_the_pattern_engine_cut_offs(score, expected):
    sig = (
        [Signal("scam_message_pattern", 25)]
        if score >= 20
        else ([Signal("financial_bait", 15)] if score else [])
    )
    v = ad.from_message(pattern_score=score, signals=sig, sender_verdict=None)
    assert v.risk_level is expected
    assert_clean(v)


def test_a_message_with_no_signals_is_low_not_safe_and_says_what_was_not_checked():
    v = ad.from_message(pattern_score=0.0, signals=[], sender_verdict=None)
    assert v.risk_level is RiskLevel.LOW and "no_signals_found" in codes(v, "reasons")
    assert any("not checked" in lim for lim in v.limitations)


def test_sender_registry_results_adjust_the_score_like_the_router_does():
    clean = lambda sv: ad.from_message(pattern_score=0.0, signals=[], sender_verdict=sv)  # noqa: E731
    assert (clean("UNREGISTERED").risk_score, clean("UNREGISTERED").risk_level) == (
        20,
        RiskLevel.MEDIUM,
    )
    assert (clean("PHONE_NUMBER").risk_score, clean("PHONE_NUMBER").risk_level) == (
        10,
        RiskLevel.LOW,
    )
    assert "sender_not_registered" in codes(clean("UNREGISTERED"), "evidence")
    assert ad.SENDER_UNREGISTERED_BOOST == 20.0 and ad.SENDER_PHONE_NUMBER_BOOST == 10.0


def test_a_registered_sender_is_positive_about_the_sender_only_never_safe():
    v = ad.from_message(pattern_score=0.0, signals=[], sender_verdict="REGISTERED")
    assert (
        v.risk_level is RiskLevel.LOW
    )  # registered sender, no signals: still not SAFE
    assert [(e.code, e.polarity) for e in v.evidence] == [
        ("sender_registered", Polarity.POSITIVE)
    ]
    assert any("does not prove" in lim for lim in v.limitations)


def test_registered_sender_with_scam_wording_is_still_high_contradictory_signals():
    sig = [Signal("scam_message_pattern", 50, 2)]
    v = ad.from_message(pattern_score=50.0, signals=sig, sender_verdict="REGISTERED")
    assert v.risk_level is RiskLevel.HIGH
    assert {"sender_registered", "scam_message_pattern"} <= codes(v, "evidence")


@pytest.mark.parametrize("sv", ["UNKNOWN", "garbage", ""])
def test_an_unknown_sender_result_is_a_limitation_not_trust(sv):
    v = ad.from_message(pattern_score=0.0, signals=[], sender_verdict=sv)
    assert v.risk_level is RiskLevel.LOW and any(
        "could not be verified" in lim for lim in v.limitations
    )


@pytest.mark.parametrize("bad", [None, "x", float("nan"), -5, 400, True])
def test_a_malformed_message_score_is_unknown(bad):
    v = ad.from_message(pattern_score=bad, signals=[], sender_verdict=None)
    assert (v.risk_level, v.risk_score) == (RiskLevel.UNKNOWN, None)


# ------------------------------------------------------------------------------------------------ job offers
def test_job_offer_uses_the_detectors_own_fake_flag():
    score, fake, _flags, sig = t.analyze_job_offer_signals(
        "Work from home earn 50000 per month. Pay registration fee 500 and apply on whatsapp today only"
    )
    assert fake is True
    v = ad.from_job_offer(pattern_score=score, is_fake=fake, signals=sig)
    assert v.risk_level is RiskLevel.HIGH and "job_upfront_payment" in codes(
        v, "evidence"
    )
    assert_clean(v)


def test_a_job_offer_just_below_the_cut_off_is_low_with_its_signals_listed():
    v = ad.from_job_offer(
        pattern_score=49.0, is_fake=False, signals=[Signal("job_no_company_name", 10)]
    )
    assert v.risk_level is RiskLevel.LOW and "job_no_company_name" in codes(
        v, "evidence"
    )
    assert any("does not mean the offer is genuine" in lim for lim in v.limitations)


def test_a_clean_job_offer_is_low_not_safe():
    v = ad.from_job_offer(pattern_score=0.0, is_fake=False, signals=[])
    assert v.risk_level is RiskLevel.LOW and "no_signals_found" in codes(v, "reasons")


@pytest.mark.parametrize(
    "score,fake", [(None, False), (10, None), (10, "yes"), (float("nan"), False)]
)
def test_malformed_job_results_are_unknown(score, fake):
    assert (
        ad.from_job_offer(pattern_score=score, is_fake=fake, signals=[]).risk_level
        is RiskLevel.UNKNOWN
    )


# ------------------------------------------------------------------------------------------------ daily aggregate (activity is never risk evidence)
def agg(alerts=0, apps=0, links=0, calls=0):
    return ad.from_daily_report(
        threats_detected=alerts,
        apps_scanned=apps,
        links_scanned=links,
        calls_analyzed=calls,
    )


def test_no_activity_and_no_alerts_is_unknown_not_safe():
    v = agg()
    assert (v.risk_level, v.risk_score) == (
        RiskLevel.UNKNOWN,
        None,
    ) and "no_activity" in codes(v, "reasons")
    assert v.evidence == []
    assert_clean(v)


def test_checks_that_ran_with_no_alert_are_low_with_no_adverse_evidence():
    v = agg(apps=3, links=2)
    assert (v.risk_level, v.risk_score) == (RiskLevel.LOW, 0) and v.evidence == []
    assert "no_signals_found" in codes(v, "reasons")


@pytest.mark.parametrize(
    "alerts,expected",
    [
        (1, RiskLevel.LOW),
        (2, RiskLevel.LOW),
        (3, RiskLevel.MEDIUM),
        (4, RiskLevel.MEDIUM),
        (5, RiskLevel.HIGH),
        (7, RiskLevel.HIGH),
        (8, RiskLevel.CRITICAL),
        (50, RiskLevel.CRITICAL),
    ],
)
def test_alert_count_uses_the_existing_ten_points_per_alert_and_report_cut_offs(
    alerts, expected
):
    v = agg(alerts=alerts, apps=1)
    assert v.risk_level is expected and v.risk_score == min(alerts * 10, 100)
    assert_clean(v)


def test_scan_activity_never_changes_the_risk():
    base = agg(alerts=3)
    heavy = agg(alerts=3, apps=1000, links=1000, calls=1000)
    assert (base.risk_level, base.risk_score) == (heavy.risk_level, heavy.risk_score)
    assert codes(base, "evidence") == codes(heavy, "evidence") == {"alerts_recorded"}
    assert (
        agg(links=500).risk_level is RiskLevel.LOW and agg(links=500).risk_score == 0
    )  # a lot of scanning alone adds no risk


@pytest.mark.parametrize(
    "bad",
    [(-1, 0, 0, 0), (None, 0, 0, 0), (0, "3", 0, 0), (0, 0, 1.5, 0), (True, 0, 0, 0)],
)
def test_malformed_daily_counts_are_unknown(bad):
    v = ad.from_daily_report(
        threats_detected=bad[0],
        apps_scanned=bad[1],
        links_scanned=bad[2],
        calls_analyzed=bad[3],
    )
    assert v.risk_level is RiskLevel.UNKNOWN


def test_the_aggregate_states_that_it_is_not_the_dashboard_score():
    assert any("F05-1" in lim for lim in agg(alerts=1).limitations)


# ------------------------------------------------------------------------------------------------ cross-cutting rules
def test_safe_is_never_produced_by_any_backend_adapter_for_any_input_mix():
    outcomes = [None, SAFE, MAL, *OUT, "junk"]
    seen = set()
    for g in outcomes:
        for u in outcomes:
            for score in (0, 10, 40, 70, 95, None):
                seen.add(url(score, None, [], gsb=g, uh=u).risk_level)
    for sv in (None, "REGISTERED", "UNREGISTERED", "PHONE_NUMBER", "UNKNOWN"):
        for score in (0, 20, 50, 80, None):
            seen.add(
                ad.from_message(
                    pattern_score=score, signals=[], sender_verdict=sv
                ).risk_level
            )
    for a in (0, 1, 9):
        for act in (0, 5):
            seen.add(agg(alerts=a, apps=act).risk_level)
    assert RiskLevel.SAFE not in seen and RiskLevel.UNKNOWN in seen


def test_confidence_is_null_everywhere():
    vs = [
        url(0, None, [], gsb=SAFE, uh=SAFE),
        ad.from_message(
            pattern_score=30.0,
            signals=[Signal("financial_bait", 15)],
            sender_verdict=None,
        ),
        agg(alerts=2),
    ]
    assert all(v.confidence is None for v in vs)


def test_nothing_ever_recommends_blocking_and_every_action_is_advisory_text():
    for lvl_score in (0, 45, 65, 95):
        v = url(
            lvl_score,
            None,
            [Signal("insecure_http", 15)] if lvl_score else [],
            gsb=MAL if lvl_score == 95 else SAFE,
            uh=SAFE,
        )
        for a in v.recommended_actions:
            assert not any(
                w in a.text.lower()
                for w in ("block", "quarantine", "delete", "uninstall")
            )


def test_verdicts_never_contain_the_submitted_content():
    secret_url = "http://192.168.77.12/login/verify?token=TOPSECRET123&acct=9876543210"
    _p, _m, score, cat, sig = t.analyze_url_signals(secret_url)
    blob = ad.from_url_scan(
        risk_score=score, threat_category=cat, signals=sig, gsb=SAFE, urlhaus=OUT[2]
    ).model_dump_json()
    for leak in ("TOPSECRET123", "192.168", "9876543210", "login", "http://"):
        assert leak not in blob, leak
    text = "URGENT your SBI KYC expired click http://bit.ly/zzTOPSECRET and share OTP now. Call 9876543210 or pay via secret@upi"
    s, _c, _pat, msig = t.analyze_message_signals(text)
    mblob = ad.from_message(
        pattern_score=s, signals=msig, sender_verdict="UNREGISTERED"
    ).model_dump_json()
    for leak in ("TOPSECRET", "9876543210", "secret@upi", "bit.ly", "KYC"):
        assert leak not in mblob, leak


def test_safe_verdict_swallows_any_adapter_failure():
    def boom(**_):
        raise RuntimeError("boom with http://private.example")

    assert ad.safe_verdict(boom) is None
    assert (
        ad.safe_verdict(
            ad.from_daily_report,
            threats_detected=0,
            apps_scanned=0,
            links_scanned=0,
            calls_analyzed=0,
        )
        is not None
    )


def test_real_detector_outputs_roundtrip_through_the_adapters():
    for text in (
        "https://example.com",
        "http://fakebank.com/login",
        "http://192.168.4.4/verify",
        "x.y",
    ):
        _p, _m, score, cat, sig = t.analyze_url_signals(text)
        v = ad.from_url_scan(
            risk_score=score,
            threat_category=cat,
            signals=sig,
            gsb=OUT[2],
            urlhaus=OUT[2],
        )
        assert_clean(v)
        if v.risk_level is RiskLevel.UNKNOWN:
            assert v.risk_score is None
        else:
            assert not math.isnan(v.risk_score)
