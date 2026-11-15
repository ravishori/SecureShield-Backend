"""Production endpoint registry rules (Stage 1.1)."""

import pytest

from app.db_identity import DatabaseIdentityError, endpoint_id, load_registry

pytestmark = [pytest.mark.unit, pytest.mark.security]


def _file(tmp_path, text):
    p = tmp_path / "registry.txt"
    p.write_text(text, encoding="utf-8")
    return p


def test_g1_missing_registry_file_refuses_even_with_the_variable(tmp_path):
    with pytest.raises(DatabaseIdentityError, match="missing or unreadable"):
        load_registry("ep-extra", tmp_path / "nope.txt")


def test_g2_comment_only_file_is_refused(tmp_path):
    with pytest.raises(DatabaseIdentityError, match="empty"):
        load_registry("", _file(tmp_path, "# nothing\n   \n# still nothing\n"))


def test_g3_variable_adds_to_the_file(tmp_path):
    reg = load_registry("ep-two, ep-three", _file(tmp_path, "ep-one\n"))
    assert reg == {"ep-one", "ep-two", "ep-three"}


def test_g4_empty_variable_keeps_file_entries(tmp_path):
    assert load_registry("", _file(tmp_path, "ep-one # production\n")) == {"ep-one"}
    assert load_registry("  ,  ", _file(tmp_path, "ep-one\n")) == {"ep-one"}


def test_g5_case_and_pooler_forms_are_the_same_endpoint():
    assert (
        endpoint_id("EP-Cool-Silence-X-pooler.region.aws.neon.tech")
        == endpoint_id("ep-cool-silence-x", from_entry=True)
        == "ep-cool-silence-x"
    )
    assert endpoint_id("LocalHost") == "localhost"


@pytest.mark.parametrize(
    "entry",
    [
        "postgres://u:p@ep-x/db",
        "user@ep-x",
        "ep x",
        "ep-*",
        "*.neon.tech",
        "https://ep-x.neon.tech",
    ],
)
def test_g6_urls_credentials_spaces_and_wildcards_are_refused(tmp_path, entry):
    with pytest.raises(DatabaseIdentityError, match="not an endpoint id") as info:
        load_registry("", _file(tmp_path, f"ep-ok\n{entry}\n"))
    assert entry not in str(info.value)
    with pytest.raises(DatabaseIdentityError, match="not an endpoint id"):
        load_registry(entry, _file(tmp_path, "ep-ok\n"))


def test_variable_cannot_remove_file_entries(tmp_path):
    assert "ep-one" in load_registry("ep-two", _file(tmp_path, "ep-one\n"))
