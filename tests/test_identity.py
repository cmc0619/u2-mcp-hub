"""Tests for caller identity: who the server thinks is calling."""

from u2_mcp.identity import (
    LOCAL_CALLER,
    CallerIdentity,
    current_caller,
    set_identity_resolver,
    use_caller,
)


class TestCallerIdentity:
    """Who the server thinks is calling."""

    def test_without_authentication_the_caller_is_local(self) -> None:
        """In stdio mode there is no OAuth, so the caller is the local operator."""
        assert current_caller() == LOCAL_CALLER
        assert LOCAL_CALLER.is_authenticated is False

    def test_a_resolved_caller_is_used(self) -> None:
        """When a resolver reports an authenticated user, that user is the caller."""
        alice = CallerIdentity(subject="alice@example.com", email="alice@example.com", name="Alice")
        set_identity_resolver(lambda: alice)
        try:
            assert current_caller().subject == "alice@example.com"
        finally:
            set_identity_resolver(None)

    def test_caller_can_be_scoped_to_a_block(self) -> None:
        """A caller set for a block does not leak out of it."""
        bob = CallerIdentity(subject="bob@example.com", email="bob@example.com", name="Bob")

        with use_caller(bob):
            assert current_caller().subject == "bob@example.com"

        assert current_caller() == LOCAL_CALLER

    def test_identity_key_distinguishes_users(self) -> None:
        """Two different people produce two different keys."""
        alice = CallerIdentity(subject="alice@example.com")
        bob = CallerIdentity(subject="bob@example.com")

        assert alice.identity_key != bob.identity_key

    def test_display_name_prefers_something_a_human_recognises(self) -> None:
        """The audit trail should read as a person, not an opaque subject id."""
        caller = CallerIdentity(subject="auth0|653f", email="alice@example.com", name="Alice")

        assert caller.display_name == "Alice"
