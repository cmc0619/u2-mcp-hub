"""File operation tools for u2-mcp."""

import logging
import re
from typing import Any

from ..connection import ConnectionManager, FileNotFoundError
from ..guard import guarded
from ..server import get_connection_manager, mcp
from ..utils.dynarray import build_record, format_record_for_display, parse_record
from ..utils.export import records_to_csv, records_to_json
from ..utils.record_lock import is_missing, write_guard

logger = logging.getLogger(__name__)


def file_names(manager: ConnectionManager, pattern: str = "*") -> list[str]:
    """The account's files: VOC entries whose type (field 1) begins with F.

    Read from a select list rather than cut from a LISTFILES printout, whose
    column headings and wrapped names came back as if they were files.

    Args:
        manager: The connection manager to run the selection on
        pattern: File name pattern; * is any run of characters

    Returns:
        The file names, sorted
    """
    criteria = 'WITH F1 LIKE "F..."'
    if pattern != "*":
        criteria = f'WITH @ID LIKE "{pattern.replace("*", "...")}" AND {criteria}'
    names, _ = manager.select_ids(f"SSELECT VOC {criteria}")
    return names


# One FILE.STAT line: a label, then "=" (UniVerse) or ":", then the value.
_STAT_LINE = re.compile(r"^\s*([^=:]+?)\s*[=:]\s*(.+?)\s*$")


def _stat_value(text: str) -> int | str:
    return int(text) if text.isdigit() else text


def _parse_file_stat(output: str) -> dict[str, Any]:
    """Parse FILE.STAT output into structured info.

    Each statistic is matched by its whole label, so "Average number of records
    per group" is not taken for the record count.

    Args:
        output: Raw FILE.STAT command output

    Returns:
        Dictionary with file statistics
    """
    info: dict[str, Any] = {
        "type": None,
        "modulo": None,
        "separation": None,
        "record_count": None,
    }

    for line in output.split("\n"):
        match = _STAT_LINE.match(line)
        if not match:
            continue
        label, value = match.group(1).lower(), _stat_value(match.group(2))
        if label == "file type":
            info["type"] = value
        elif "(modulo)" in label or label == "modulo":
            info["modulo"] = value
        elif label == "separation":
            info["separation"] = value
        elif label in ("number of records", "record count"):
            info["record_count"] = value

    return info


@mcp.tool()
@guarded()
def list_files(pattern: str = "*", connection: str | None = None) -> dict[str, Any]:
    """List available files in the current Universe account.

    Args:
        pattern: File name pattern to match (supports * wildcard).
                 Default "*" lists all files.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing list of matching file names and count.
    """
    manager = get_connection_manager()

    try:
        files = file_names(manager, pattern)

        return {
            "files": files,
            "count": len(files),
            "pattern": pattern,
        }
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return {"error": str(e), "pattern": pattern}


@mcp.tool()
@guarded()
def read_record(file_name: str, record_id: str, connection: str | None = None) -> dict[str, Any]:
    """Read a single record from a Universe file.

    The record is returned with fields parsed into structured JSON,
    preserving multivalue and subvalue structure.

    Args:
        file_name: Name of the Universe file
        record_id: Record ID (key) to read
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing record id, fields (by number), and optionally
        the raw record data. Returns error if record not found.
    """
    manager = get_connection_manager()

    try:
        file_handle = manager.open_file(file_name)
        raw_data = file_handle.read(record_id)

        if raw_data is None or str(raw_data) == "":
            return {
                "error": "Record not found",
                "file": file_name,
                "id": record_id,
            }

        fields = parse_record(str(raw_data))
        return format_record_for_display(record_id, fields)

    except FileNotFoundError as e:
        return {"error": str(e), "file": file_name, "id": record_id}
    except Exception as e:
        logger.error(f"Error reading record: {e}")
        return {"error": str(e), "file": file_name, "id": record_id}


@mcp.tool()
@guarded()
def read_records(
    file_name: str, record_ids: list[str], connection: str | None = None
) -> dict[str, Any]:
    """Read multiple records from a Universe file efficiently.

    Args:
        file_name: Name of the Universe file
        record_ids: List of record IDs to read
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing file name, list of records, count, and any errors.
        Each record includes id and fields. Records not found are listed in errors.
    """
    manager = get_connection_manager()
    max_records = manager.config.max_records

    # Enforce limit
    if len(record_ids) > max_records:
        return {
            "error": f"Requested {len(record_ids)} records, maximum is {max_records}",
            "file": file_name,
        }

    try:
        file_handle = manager.open_file(file_name)
        records: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        for rid in record_ids:
            try:
                raw_data = file_handle.read(rid)
                if raw_data is not None and str(raw_data) != "":
                    fields = parse_record(str(raw_data))
                    records.append(format_record_for_display(rid, fields))
                else:
                    errors.append({"id": rid, "error": "Not found"})
            except Exception as e:
                errors.append({"id": rid, "error": str(e)})

        result: dict[str, Any] = {
            "file": file_name,
            "records": records,
            "count": len(records),
        }
        if errors:
            result["errors"] = errors

        return result

    except FileNotFoundError as e:
        return {"error": str(e), "file": file_name}
    except Exception as e:
        logger.error(f"Error reading records: {e}")
        return {"error": str(e), "file": file_name}


@mcp.tool()
@guarded()
def write_record(
    file_name: str,
    record_id: str,
    fields: dict[str, Any],
    confirm: bool = False,
    connection: str | None = None,
) -> dict[str, Any]:
    """Write or update a record in a Universe file.

    Args:
        file_name: Target file name
        record_id: Record ID to create or update
        fields: Field values as JSON object. Keys are field numbers as strings,
                values can be strings (single value), lists (multivalues),
                or nested lists (subvalues).
        confirm: Must be True to execute the write. This is a safety measure.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Status of the write operation. Requires confirm=True to execute.
        Disabled in read-only mode.

    Example fields:
        {"1": "John Doe", "2": ["555-1234", "555-5678"], "3": "CA"}
    """
    manager = get_connection_manager()

    # Safety checks
    if manager.config.read_only:
        return {"error": "Write operations disabled in read-only mode"}

    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "Set confirm=True to execute write operation",
            "file": file_name,
            "id": record_id,
            "fields_to_write": len(fields),
        }

    try:
        raw_data = build_record(fields)
        # Takes turns with update_value, whose locked read-change-write a plain
        # write on the same session would otherwise land in the middle of.
        with write_guard(manager):
            file_handle = manager.open_file(file_name)
            file_handle.write(record_id, raw_data)

        return {
            "status": "success",
            "file": file_name,
            "id": record_id,
            "fields_written": len(fields),
        }

    except FileNotFoundError as e:
        return {"error": str(e), "file": file_name, "id": record_id}
    except Exception as e:
        logger.error(f"Error writing record: {e}")
        return {"error": str(e), "file": file_name, "id": record_id}


@mcp.tool()
@guarded()
def delete_record(
    file_name: str,
    record_id: str,
    confirm: bool = False,
    connection: str | None = None,
) -> dict[str, Any]:
    """Delete a record from a Universe file.

    Args:
        file_name: Target file name
        record_id: Record ID to delete
        confirm: Must be True to execute the delete. This is a safety measure.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Status of the delete operation. Requires confirm=True to execute.
        Disabled in read-only mode.
    """
    manager = get_connection_manager()

    # Safety checks
    if manager.config.read_only:
        return {"error": "Delete operations disabled in read-only mode"}

    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "Set confirm=True to execute delete operation",
            "file": file_name,
            "id": record_id,
        }

    try:
        with write_guard(manager):
            file_handle = manager.open_file(file_name)
            file_handle.delete(record_id)

        return {
            "status": "deleted",
            "file": file_name,
            "id": record_id,
        }

    except FileNotFoundError as e:
        return {"error": str(e), "file": file_name, "id": record_id}
    except Exception as e:
        logger.error(f"Error deleting record: {e}")
        return {"error": str(e), "file": file_name, "id": record_id}


@mcp.tool()
@guarded()
def get_file_info(file_name: str, connection: str | None = None) -> dict[str, Any]:
    """Get information about a Universe file.

    Returns file statistics including type, modulo, separation, and record count.

    Args:
        file_name: Name of the Universe file
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing file statistics and metadata, or an error with the
        database diagnostic when FILE.STAT fails or returns no recognized statistics.
    """
    manager = get_connection_manager()

    try:
        output, return_code = manager.run_command(f"FILE.STAT {file_name}")
        info = _parse_file_stat(output)
        if return_code < 0 or all(value is None for value in info.values()):
            diagnostic = output.strip() or "FILE.STAT returned no recognized statistics"
            logger.error("Error getting file info for %s: %s", file_name, diagnostic)
            return {"error": diagnostic, "file": file_name}
        info["file"] = file_name
        info["raw_output"] = output

        return info

    except Exception as e:
        logger.error(f"Error getting file info: {e}")
        return {"error": str(e), "file": file_name}


# =============================================================================
# Phase 3: Export Tools
# =============================================================================


@mcp.tool()
@guarded()
def export_to_json(
    file_name: str,
    record_ids: list[str],
    expand_mv: bool = False,
    connection: str | None = None,
) -> dict[str, Any]:
    """Export records from a Universe file to JSON format.

    Reads the specified records and returns them as a JSON string.
    Useful for data analysis and integration with other tools.

    Args:
        file_name: Name of the Universe file
        record_ids: List of record IDs to export
        expand_mv: If True, expand multivalues into separate objects.
                   If False (default), preserve multivalue arrays.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing:
        - status: success, partial (some records left out) or error
        - format: "json"
        - record_count: Number of records exported
        - is_complete: False when any requested record was left out
        - missing_ids: Requested records that do not exist
        - failed_ids: Requested records that could not be read, with the reason
        - data: JSON string of the exported records
    """
    manager = get_connection_manager()
    max_records = manager.config.max_records

    if len(record_ids) > max_records:
        return {
            "error": f"Requested {len(record_ids)} records, maximum is {max_records}",
            "file": file_name,
        }

    try:
        file_handle = manager.open_file(file_name)
        records, skipped = _read_for_export(file_handle, record_ids)

        json_output = records_to_json(records, expand_mv=expand_mv, pretty=True)

        return {
            **skipped,
            "file": file_name,
            "format": "json",
            "record_count": len(records),
            "expand_mv": expand_mv,
            "data": json_output,
        }

    except FileNotFoundError as e:
        return {"error": str(e), "file": file_name}
    except Exception as e:
        logger.error(f"Error exporting to JSON: {e}")
        return {"error": str(e), "file": file_name}


@mcp.tool()
@guarded()
def export_to_csv(
    file_name: str,
    record_ids: list[str],
    expand_mv: bool = False,
    mv_delimiter: str = "|",
    connection: str | None = None,
) -> dict[str, Any]:
    """Export records from a Universe file to CSV format.

    Reads the specified records and returns them as a CSV string.
    Useful for spreadsheet import and data analysis.

    Args:
        file_name: Name of the Universe file
        record_ids: List of record IDs to export
        expand_mv: If True, expand multivalues into separate rows.
                   If False (default), join multivalues with delimiter.
        mv_delimiter: Delimiter for multivalues when expand_mv=False.
                      Default is "|".
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        Dictionary containing:
        - status: success, partial (some records left out) or error
        - format: "csv"
        - record_count: Number of records exported
        - is_complete: False when any requested record was left out
        - missing_ids: Requested records that do not exist
        - failed_ids: Requested records that could not be read, with the reason
        - row_count: Number of rows in CSV (may differ if expand_mv=True)
        - data: CSV string of the exported records
    """
    manager = get_connection_manager()
    max_records = manager.config.max_records

    if len(record_ids) > max_records:
        return {
            "error": f"Requested {len(record_ids)} records, maximum is {max_records}",
            "file": file_name,
        }

    try:
        file_handle = manager.open_file(file_name)
        records, skipped = _read_for_export(file_handle, record_ids)

        csv_output = records_to_csv(
            records,
            expand_mv=expand_mv,
            mv_delimiter=mv_delimiter,
            include_header=True,
        )

        # Count rows (excluding header)
        row_count = csv_output.count("\n") - 1 if csv_output else 0

        return {
            **skipped,
            "file": file_name,
            "format": "csv",
            "record_count": len(records),
            "row_count": row_count,
            "expand_mv": expand_mv,
            "mv_delimiter": mv_delimiter if not expand_mv else None,
            "data": csv_output,
        }

    except FileNotFoundError as e:
        return {"error": str(e), "file": file_name}
    except Exception as e:
        logger.error(f"Error exporting to CSV: {e}")
        return {"error": str(e), "file": file_name}


def _read_for_export(
    file_handle: Any, record_ids: list[str]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read records for an export, accounting for every one that is left out.

    An export that quietly drops records reads as a complete one, so each id is
    either exported, missing (not in the file) or failed (with the reason).

    Returns:
        The records, and the status fields that say what was left out
    """
    records: list[dict[str, Any]] = []
    missing: list[str] = []
    failed: dict[str, str] = {}
    for rid in record_ids:
        try:
            raw_data = file_handle.read(rid)
        except Exception as error:  # noqa: BLE001 - reported per record
            if is_missing(error):
                missing.append(rid)
            else:
                failed[rid] = str(error)
            continue
        if raw_data is None:
            missing.append(rid)
            continue
        records.append(format_record_for_display(rid, parse_record(str(raw_data))))
    complete = not missing and not failed
    return records, {
        "status": "success" if complete else "partial",
        "is_complete": complete,
        "missing_ids": missing,
        "failed_ids": failed,
    }
