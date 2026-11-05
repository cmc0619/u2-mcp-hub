"""Adversarial tests against the hardening work itself.

Every fix is new code, and new code is new attack surface. These tests attack the
remediations rather than the original defects: they ask what happens when the new
machinery fails, and insist that failing does not quietly grant more than it
should.
"""

import pytest

from u2_mcp.identity import (
    CallerIdentity,
    IdentityError,
    current_caller,
    set_identity_resolver,
)


@pytest.fixture(autouse=True)
def clear_resolver() -> None:
    """Make sure no test leaves an identity resolver installed."""
    yield
    set_identity_resolver(None)


class TestIdentityFailsClosed:
    """When the server cannot say who is calling, it must not guess."""

    def test_a_failing_resolver_does_not_become_a_local_operator(self) -> None:
        """A token lookup that throws must not silently downgrade to unauthenticated.

        Falling back to the local operator would let a caller launder their
        identity out of the audit trail by making resolution fail.
        """

        def broken_resolver() -> CallerIdentity | None:
            raise RuntimeError("token store unavailable")

        set_identity_resolver(broken_resolver)

        with pytest.raises(IdentityError):
            current_caller()

    def test_an_unresolvable_token_is_refused(self) -> None:
        """A resolver that recognises nobody must refuse, not fall back."""
        set_identity_resolver(lambda: None)

        with pytest.raises(IdentityError):
            current_caller()

    def test_no_resolver_still_means_local_stdio_use(self) -> None:
        """With no resolver installed at all, stdio mode still works unauthenticated."""
        set_identity_resolver(None)

        assert current_caller().subject == "local"
