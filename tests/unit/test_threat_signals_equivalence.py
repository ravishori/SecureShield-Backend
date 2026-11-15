"""X-1: the detectors were extended with signal reporting. Their detection must be IDENTICAL to what it was before.

`data/threat_golden.json` was generated from the unmodified functions BEFORE the change; these tests replay it."""

import json
import pathlib

from app.services import threat_analyzer as t

G = json.loads(
    (pathlib.Path(__file__).parent / "data" / "threat_golden.json").read_text(
        encoding="utf-8"
    )
)


def test_url_detection_is_unchanged():
    assert G["urls"], "golden corpus missing"
    for e in G["urls"]:
        assert list(t.analyze_url(e["in"])) == e["out"], e["in"]
        a, b, c, d, _signals = t.analyze_url_signals(e["in"])
        assert [a, b, c, d] == e["out"], e["in"]


def test_message_detection_is_unchanged():
    assert G["messages"]
    for e in G["messages"]:
        score, cat, patterns = t.analyze_message_content(e["in"])
        assert [score, cat, patterns] == e["out"], e["in"]
        s2, c2, p2, _signals = t.analyze_message_signals(e["in"])
        assert [s2, c2, p2] == e["out"], e["in"]


def test_job_offer_detection_is_unchanged():
    assert G["jobs"]
    for e in G["jobs"]:
        assert list(t.analyze_job_offer(e["in"])) == e["out"], e["in"]
        s, fake, flags, _signals = t.analyze_job_offer_signals(e["in"])
        assert [s, fake, flags] == e["out"], e["in"]


def test_signal_weights_explain_the_uncapped_score_for_every_url():
    for e in G["urls"]:
        _a, _b, score, _c, signals = t.analyze_url_signals(e["in"])
        total = sum(s.weight for s in signals)
        assert min(total, 100.0) == score or (
            score == 90.0 and signals and signals[0].code == "known_scam_domain"
        ), (e["in"], total, score)


def test_signal_codes_are_fixed_identifiers_never_input_text():
    from app.schemas.scam_verdict import EVIDENCE_CODES

    for e in G["urls"]:
        for s in t.analyze_url_signals(e["in"])[-1]:
            assert s.code in EVIDENCE_CODES
    for e in G["messages"]:
        for s in t.analyze_message_signals(e["in"])[-1]:
            assert s.code in EVIDENCE_CODES
    for e in G["jobs"]:
        for s in t.analyze_job_offer_signals(e["in"])[-1]:
            assert s.code in EVIDENCE_CODES


def test_empty_and_degenerate_inputs_do_not_raise():
    for text in ("", " ", "\x00", "a" * 10_000):
        t.analyze_url_signals(text)
        t.analyze_message_signals(text)
        t.analyze_job_offer_signals(text)
