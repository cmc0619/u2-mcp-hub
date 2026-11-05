"""Transaction management tools for u2-mcp."""

import logging
from typing import Any

from ..guard import guarded
from ..server import get_connection_manager, mcp
from ..store import get_store

logger = logging.getLogger(__name__)


@mcp.tool()
@guarded()
def begin_transaction(connection: str | None = None) -> dict[str, Any]:
    """Begin a database transaction.

    Starts a new transaction. All subsequent write operations (write_record,
    delete_record) will be part of this transaction until commit_transaction
    or rollback_transaction is called.

    Args:
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing:
        - status: success or error
        - in_transaction: True if transaction is now active
        - started_at: Timestamp when transaction started

    Note:
        Only one transaction can be active at a time. Transactions are refused
        on a U2 login that several people share. With a personal login, your
        own assistant sessions share one transaction.
        Attempting to start a new transaction while one is active will fail.
    """
    manager = get_connection_manager()

    if manager.config.read_only:
        return {
            "error": "Transactions not available in read-only mode",
            "in_transaction": False,
        }

    # A transaction belongs to the database session, not to the caller. On a login
    # several people share, another person's ordinary writes would land inside it
    # and vanish if it were rolled back. Only one person on a stdio pipe is safe.
    if manager.credentials.is_shared and get_store() is not None:
        return {
            "error": (
                "Transactions need a personal U2 login: this connection's login is "
                "shared, so other people's writes would join your transaction. Ask an "
                "admin to switch this connection to personal U2 logins."
            ),
            "in_transaction": False,
        }

    if manager.in_transaction:
        return {
            "error": "Transaction already in progress",
            "in_transaction": True,
        }

    try:
        manager.begin_transaction()
        return {
            "status": "success",
            "message": "Transaction started",
            "in_transaction": True,
            "started_at": manager._transaction.started_at.isoformat()
            if manager._transaction.started_at
            else None,
        }
    except Exception as e:
        logger.error(f"Error starting transaction: {e}")
        return {"error": str(e), "in_transaction": manager.in_transaction}


@mcp.tool()
@guarded()
def commit_transaction(connection: str | None = None) -> dict[str, Any]:
    """Commit the current transaction.

    Saves all changes made since begin_transaction was called.
    The transaction is closed after commit.

    Args:
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing:
        - status: success or error
        - in_transaction: False after successful commit
        - message: Confirmation message

    Note:
        If no transaction is active, returns an error.
    """
    manager = get_connection_manager()

    if not manager.in_transaction:
        return {
            "error": "No transaction in progress",
            "in_transaction": False,
        }

    try:
        manager.commit_transaction()
        return {
            "status": "success",
            "message": "Transaction committed successfully",
            "in_transaction": False,
        }
    except Exception as e:
        logger.error(f"Error committing transaction: {e}")
        return {
            "error": str(e),
            "in_transaction": manager.in_transaction,
            "message": "Transaction may still be active",
        }


@mcp.tool()
@guarded()
def rollback_transaction(connection: str | None = None) -> dict[str, Any]:
    """Rollback the current transaction.

    Discards all changes made since begin_transaction was called.
    The transaction is closed after rollback.

    Args:
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing:
        - status: success or error
        - in_transaction: False after successful rollback
        - message: Confirmation message

    Note:
        If no transaction is active, returns an error.
    """
    manager = get_connection_manager()

    if not manager.in_transaction:
        return {
            "error": "No transaction in progress",
            "in_transaction": False,
        }

    try:
        manager.rollback_transaction()
        return {
            "status": "success",
            "message": "Transaction rolled back successfully",
            "in_transaction": False,
        }
    except Exception as e:
        logger.error(f"Error rolling back transaction: {e}")
        return {
            "error": str(e),
            "in_transaction": manager.in_transaction,
            "message": "Transaction may still be active",
        }


@mcp.tool()
@guarded()
def get_transaction_status(connection: str | None = None) -> dict[str, Any]:
    """Get the current transaction status.

    Returns information about whether a transaction is active
    and when it was started. This is inspection available through baseline
    connection access, including read-only connections; it does not change state.

    Args:
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing:
        - in_transaction: True if transaction is active
        - started_at: Timestamp when transaction started (if active)
        - read_only_mode: Whether server is in read-only mode
    """
    manager = get_connection_manager()

    return {
        "in_transaction": manager.in_transaction,
        "started_at": manager._transaction.started_at.isoformat()
        if manager._transaction.started_at
        else None,
        "read_only_mode": manager.config.read_only,
    }
