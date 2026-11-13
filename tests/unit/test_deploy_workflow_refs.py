"""The staging deploy workflow must accept only the exact branch staging/railway-snapshot; tags and every other branch are rejected (CI-only)."""

import re
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows"


def _guard():
    wf = yaml.safe_load((WF / "deploy-staging.yml").read_text(encoding="utf-8"))
    steps = wf["jobs"]["deploy"]["steps"]
    guard = next(s for s in steps if "approved refs" in s.get("name", ""))
    assert steps.index(guard) < next(
        i for i, s in enumerate(steps) if "checkout" in s.get("uses", "")
    ), "guard must run before checkout"
    return guard["run"]


def _bash():
    for cand in ("bash", r"C:\Program Files\Git\bin\bash.exe"):
        try:
            subprocess.run([cand, "-c", "true"], check=True, capture_output=True)
            return cand
        except Exception:
            continue
    pytest.skip("bash unavailable")


@pytest.mark.parametrize(
    "ref,ok",
    [
        ("staging/railway-snapshot", True),
        ("staging/candidate-2026-11-13", False),
        ("staging/candidate-anything", False),
        ("staging/other", False),
        ("staging/railway-snapshot-evil", False),
        ("staging/railway-snapshot/x", False),
        ("refs/heads/staging/railway-snapshot", False),
        ("v1", False),
        ("v1.2.3", False),
        ("v0.0.1-rc1", False),
        ("v9999", False),
        ("release/1", False),
        ("main", False),
        ("", False),
    ],
)
def test_guard_accepts_only_the_approved_refs(ref, ok):
    r = subprocess.run(
        [_bash(), "-c", _guard()],
        env={"REF": ref, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert (r.returncode == 0) is ok, r.stdout + r.stderr


def test_deploy_workflow_is_manual_only_and_ci_still_covers_candidates():
    wf = yaml.safe_load((WF / "deploy-staging.yml").read_text(encoding="utf-8"))
    triggers = wf.get("on") or wf.get(True)
    assert set(triggers) == {"workflow_dispatch"}
    ci = yaml.safe_load((WF / "backend-ci.yml").read_text(encoding="utf-8"))
    push = (ci.get("on") or ci.get(True))["push"]["branches"]
    assert "staging/**" in push
    assert not re.search(
        r"railway up", (WF / "backend-ci.yml").read_text(encoding="utf-8")
    )
