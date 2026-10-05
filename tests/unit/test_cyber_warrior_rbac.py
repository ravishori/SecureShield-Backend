"""RBAC helper tests for the Cyber Warriors Network.

These test the pure `role_meets` ordering function directly. The
`require_warrior_role` dependency itself requires a database to properly
test end-to-end — that will land in the integration test tier (Phase 2)
when the test Postgres container is added. For now we lock in the
ordering guarantees that drive the dependency's decisions.
"""

import pytest

from app.models.cyber_warrior import WarriorRole, role_meets


class TestRoleOrdering:
    @pytest.mark.unit
    def test_admin_meets_every_tier(self):
        for required in WarriorRole:
            assert role_meets(WarriorRole.admin, required), (
                f"admin should satisfy {required.value}"
            )

    @pytest.mark.unit
    def test_trainee_only_meets_trainee(self):
        assert role_meets(WarriorRole.trainee, WarriorRole.trainee)
        assert not role_meets(WarriorRole.trainee, WarriorRole.verified_warrior)
        assert not role_meets(WarriorRole.trainee, WarriorRole.mentor)
        assert not role_meets(WarriorRole.trainee, WarriorRole.moderator)
        assert not role_meets(WarriorRole.trainee, WarriorRole.admin)

    @pytest.mark.unit
    def test_moderator_does_not_meet_admin(self):
        # Moderator is one tier below admin — must not pass admin-only gate
        assert not role_meets(WarriorRole.moderator, WarriorRole.admin)
        # But must satisfy its own tier and below
        assert role_meets(WarriorRole.moderator, WarriorRole.moderator)
        assert role_meets(WarriorRole.moderator, WarriorRole.mentor)
        assert role_meets(WarriorRole.moderator, WarriorRole.verified_warrior)
        assert role_meets(WarriorRole.moderator, WarriorRole.trainee)

    @pytest.mark.unit
    def test_mentor_sits_between_verified_and_moderator(self):
        assert role_meets(WarriorRole.mentor, WarriorRole.verified_warrior)
        assert role_meets(WarriorRole.mentor, WarriorRole.mentor)
        assert not role_meets(WarriorRole.mentor, WarriorRole.moderator)
        assert not role_meets(WarriorRole.mentor, WarriorRole.admin)

    @pytest.mark.unit
    @pytest.mark.security
    def test_ordering_matches_string_names(self):
        """If someone adds a new role to the enum, this test fails to force
        them to update the `_ROLE_ORDER` dict in cyber_warrior.py.
        """
        # Expected ordering: trainee < verified < mentor < moderator < admin
        expected = [
            WarriorRole.trainee,
            WarriorRole.verified_warrior,
            WarriorRole.mentor,
            WarriorRole.moderator,
            WarriorRole.admin,
        ]
        # Any new role would mean this length check fails, forcing attention
        assert len(list(WarriorRole)) == len(expected), (
            "WarriorRole enum changed — update _ROLE_ORDER in cyber_warrior.py "
            "AND update the expected list in this test together."
        )
        # Pair-wise strictly increasing
        for lower, higher in zip(expected, expected[1:]):
            assert role_meets(higher, lower)
            assert not role_meets(lower, higher)
