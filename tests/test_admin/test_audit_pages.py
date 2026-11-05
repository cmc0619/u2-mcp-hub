"""Audit (filters, CSV), and admins landing on Connections."""

import csv
import io
from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from u2_mcp.admin.context import AdminContext
from u2_mcp.admin.services import AuditFilters, audit_csv
from u2_mcp.passwords import hash_password
from u2_mcp.setup_code import finish_setup

from .helpers import PASSWORD, admin_client, sign_in


def _shared(ctx: AdminContext) -> int:
    return ctx.store.add_connection(
        name="Prod",
        host="h",
        port=1,
        service="uvcs",
        account="A",
        shared_user="svc",
        shared_password="pw",
    ).id


class TestServices:
    def test_csv_has_a_header_and_defuses_formulas(self, ctx: AdminContext) -> None:
        ctx.store.add_audit(kind="admin", action="=HYPERLINK(1)", outcome="ok", actor_label="@evil")

        rows = list(csv.reader(io.StringIO(audit_csv(ctx, AuditFilters()))))

        assert rows[0] == [
            "at",
            "actor",
            "kind",
            "connection",
            "action",
            "outcome",
            "duration_ms",
            "params",
        ]
        assert rows[1][1] == "'@evil" and rows[1][4] == "'=HYPERLINK(1)"

    def test_dates_bound_the_range(self) -> None:
        filters = AuditFilters.from_query(
            {"from": "2026-10-01", "to": "2026-10-01", "kind": "nonsense", "user": "x"}
        )

        assert filters.until is not None and filters.since is not None
        assert filters.until - filters.since == 86400
        assert filters.kind is None and filters.user_id is None


@pytest.fixture
def client(ctx: AdminContext) -> Iterator[TestClient]:
    finish_setup(ctx.store)
    ctx.store.add_local_user("ann", password_hash=hash_password(PASSWORD), is_admin=True)
    with admin_client(ctx) as test_client:
        sign_in(test_client)
        yield test_client


class TestPages:
    def test_admins_land_on_connections(self, client: TestClient) -> None:
        response = client.get("/admin/", follow_redirects=False)
        assert response.headers["location"] == "/admin/connections"

    def test_there_is_no_dashboard(self, client: TestClient) -> None:
        assert client.get("/admin/dashboard").status_code == 404
        assert "/admin/dashboard" not in client.get("/admin/connections").text

    def test_audit_filters_and_csv(self, client: TestClient) -> None:
        page = client.get("/admin/audit?kind=auth").text
        assert "admin.sign_in" in page

        export = client.get("/admin/audit.csv?kind=auth")

        assert export.headers["content-type"].startswith("text/csv")
        assert "attachment" in export.headers["content-disposition"]
        assert "admin.sign_in" in export.text
