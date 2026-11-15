"""Schema-level tests for the account deletion endpoint.

The confirmation guard ("confirm must equal DELETE") is the Play-Store-
required safeguard against accidental deletion. If it ever regresses to
accept arbitrary input, every tap on a buggy UI could permanently wipe
a user's data — so it's locked down with explicit tests.
"""

import pytest
from pydantic import ValidationError

from app.schemas.auth import DeleteAccountRequest, DeleteAccountResponse


class TestDeleteAccountRequest:
    @pytest.mark.unit
    @pytest.mark.security
    def test_literal_delete_is_accepted(self):
        req = DeleteAccountRequest(confirm="DELETE", code="123456")
        assert req.confirm == "DELETE"

    @pytest.mark.unit
    @pytest.mark.security
    def test_the_reauthentication_code_is_required(self):
        # Phase G: a stolen access token alone must not be enough to erase an account
        with pytest.raises(ValidationError):
            DeleteAccountRequest(confirm="DELETE")
        with pytest.raises(ValidationError):
            DeleteAccountRequest(confirm="DELETE", code="12")

    @pytest.mark.unit
    @pytest.mark.security
    def test_lowercase_delete_is_rejected(self):
        # Case-sensitive on purpose — "delete" is far too easy to type by accident
        with pytest.raises(ValidationError):
            DeleteAccountRequest(confirm="delete")

    @pytest.mark.unit
    @pytest.mark.security
    def test_empty_confirm_is_rejected(self):
        with pytest.raises(ValidationError):
            DeleteAccountRequest(confirm="")

    @pytest.mark.unit
    @pytest.mark.security
    def test_arbitrary_text_is_rejected(self):
        with pytest.raises(ValidationError):
            DeleteAccountRequest(confirm="yes please")

    @pytest.mark.unit
    @pytest.mark.security
    def test_delete_with_whitespace_is_rejected(self):
        # Reinforces the exact-match guard — "DELETE " must not slip through
        with pytest.raises(ValidationError):
            DeleteAccountRequest(confirm="DELETE ")
        with pytest.raises(ValidationError):
            DeleteAccountRequest(confirm=" DELETE")


class TestDeleteAccountResponse:
    @pytest.mark.unit
    def test_response_shape(self):
        from datetime import datetime

        resp = DeleteAccountResponse(
            message="done",
            user_id="abc-123",
            scrubbed_at=datetime.utcnow(),
        )
        assert resp.message == "done"
        assert resp.user_id == "abc-123"
