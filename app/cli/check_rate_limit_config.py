"""Preflight for the BH-1 per-user rate-limit configuration (run before migrations).

    python -m app.cli.check_rate_limit_config                       # validate the current process environment
    python -m app.cli.check_rate_limit_config --environment production   # validate it against the production policy

It calls the SAME validator as application startup (``app.services.user_rate_limits.validate_rate_limit_config``), reads
only environment variables (no database, no network), and prints variable NAMES and rules, never values.

Exit codes: 0 no fatal issue (warnings are printed); 1 at least one fatal issue; 2 the preflight itself failed, which a
``&&`` chain also treats as a failure, so an internal error can never let a deployment through.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Mapping, Optional, Sequence, TextIO

from app.services.user_rate_limits import (
    _PASSTHROUGH_ENV,
    SETTING_NAMES,
    validate_rate_limit_config,
)

_KEYS = tuple(SETTING_NAMES) + tuple(_PASSTHROUGH_ENV) + ("ENVIRONMENT",)


_IDENTITY_KEYS = (
    "DATABASE_URL",
    "MIGRATOR_DATABASE_URL",
    "ENVIRONMENT",
    "DATABASE_ENVIRONMENT",
    "DEV_DATABASE_ALLOWED_HOSTS",
    "PRODUCTION_DATABASE_ENDPOINTS",
    "PRODUCTION_DATABASE_NAMES",
)


def _identity_problem(source: Mapping[str, str]) -> Optional[str]:
    """Database identity preflight (no connection). Skipped, with no error, when no database URL is in the environment."""
    if not source.get("DATABASE_URL") or not source.get("MIGRATOR_DATABASE_URL"):
        return None
    from types import SimpleNamespace

    from app.db_identity import DatabaseIdentityError, validate_identity

    try:
        validate_identity(
            SimpleNamespace(**{k: source.get(k, "") for k in _IDENTITY_KEYS})
        )
    except DatabaseIdentityError as exc:
        return str(exc)
    return None


def run(
    argv: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
    out: Optional[TextIO] = None,
) -> int:
    out = out or sys.stdout
    try:
        parser = argparse.ArgumentParser(
            prog="check_rate_limit_config", description=__doc__.splitlines()[0]
        )
        parser.add_argument(
            "--environment",
            default=None,
            help="validate against this environment's policy",
        )
        args = parser.parse_args(list(argv) if argv is not None else None)
        source = os.environ if env is None else env
        mapping = {k: source[k] for k in _KEYS if k in source}
        identity_problem = _identity_problem(source)
        if identity_problem:
            print(f"database identity: REFUSED ({identity_problem})", file=out)
            print("FAILED: fix the variables named above before deploying", file=out)
            return 1
        result = validate_rate_limit_config(mapping, args.environment)
        backend = result.policy.backend if result.policy else "unresolved"
        print(
            f"rate-limit preflight: environment={result.environment} backend={backend}",
            file=out,
        )
        for issue in result.issues:
            print(str(issue), file=out)
        if result.fatal:
            print("FAILED: fix the variables named above before deploying", file=out)
            return 1
        print("OK", file=out)
        return 0
    except (
        SystemExit
    ) as exc:  # argparse error: a usage mistake must still block the chain
        return 2 if exc.code not in (0, None) else 0
    except Exception as exc:  # noqa: BLE001
        print(f"preflight failed unexpectedly: {type(exc).__name__}", file=out)
        return 2


if __name__ == "__main__":
    sys.exit(run())
