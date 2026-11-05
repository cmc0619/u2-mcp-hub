"""Changing one value of one field, without disturbing the ones beside it.

Separate from `write_record`, and the separation is the point rather than
tidiness.

`write_record` takes a whole record and stores it. That puts responsibility for
the record's *shape* on whoever assembled the fields — and in a MultiValue file
the shape is load-bearing. An inventory record holds parallel fields: position n
of the branch list, the on-hand list and the committed list all describe the same
branch. A field may legitimately be shorter than its siblings, because bins are
recorded for some branches and not others.

Assemble that record carelessly and a field comes back a different length. The
record is still well formed. Nothing errors. What has changed is which branch a
quantity belongs to, and no constraint, index or later read will notice — the
first anybody hears of it is a customer being promised stock that is somewhere
else.

So this tool names the field and the value instead of taking the record, which
keeps the shape the server's problem where it can be enforced once. It refuses a
position that does not exist rather than creating one, refuses an index past
the end of a field rather than padding to reach it, and refuses a value carrying
a mark, which would split it into new positions. Padding is the specific
mistake: reaching an index by filling the gap invents positions, and here a
position is a claim about a branch that nobody made.
"""

from typing import Any

from ..guard import guarded
from ..server import get_connection_manager, mcp
from ..utils.record_lock import (
    LOCK_EXCLUSIVE,
    is_locked,
    is_missing,
    record_lock_released,
    write_guard,
)


@mcp.tool()
@guarded()
def update_value(
    file_name: str,
    record_id: str,
    position: int,
    index: int,
    value: str,
    confirm: bool = False,
    connection: str | None = None,
) -> dict[str, Any]:
    """Change one value of one field in a record, leaving other positions alone.

    Prefer this over write_record for any change to an existing record. It cannot
    move a value onto a different position, which is the way a MultiValue record
    is most easily corrupted without anything reporting it.

    Args:
        file_name: Target file name
        record_id: The record to change
        position: Which field, counting from one
        index: Which value within that field, counting from zero
        value: What to put there; it may not contain a mark (chr(251) to chr(255))
        confirm: Must be True to execute the write. This is a safety measure.
        connection: Which connection to use (see list_connections). May be left
            out when you can use only one.

    Returns:
        The record before and after. Disabled in read-only mode.
    """
    manager = get_connection_manager()

    if manager.config.read_only:
        return {"error": "Write operations disabled in read-only mode"}

    if not confirm:
        return {
            "status": "confirmation_required",
            "message": "Set confirm=True to execute this change",
            "file": file_name,
            "id": record_id,
            "position": position,
            "index": index,
        }

    if any(mark in value for mark in _MARKS):
        return {
            "error": "The value contains a mark (chr(251) to chr(255)), which would add "
            "positions to the record; change one value at a time",
            "file": file_name,
            "id": record_id,
        }

    try:
        with write_guard(manager):
            file_handle = manager.open_file(file_name)
            with record_lock_released(file_handle, record_id):
                raw = file_handle.read(record_id, lock_flag=LOCK_EXCLUSIVE)
                before = "" if raw is None else str(raw)
                after, problem = _replace_value(before, position, index, value)
                if problem:
                    return {"error": problem, "file": file_name, "id": record_id}
                file_handle.write(record_id, after)
    except Exception as error:  # noqa: BLE001 - reported to the caller
        if is_locked(error):
            message = f"{record_id} is locked by another user; try again later"
        elif is_missing(error):
            message = f"{record_id} does not exist in {file_name}"
        else:
            message = str(error)
        return {"error": message, "file": file_name, "id": record_id}

    return {"file": file_name, "id": record_id, "before": before, "after": after}


# The separators this tool splits on.
_AM = chr(254)
_VM = chr(253)
# Every U2 mark, text mark through record mark. A value holding none of them
# replaces exactly one position, so the record keeps its shape.
_MARKS = tuple(chr(code) for code in range(251, 256))


def _replace_value(raw: str, position: int, index: int, value: str) -> tuple[str, str | None]:
    """Return the record with one value replaced, or why it cannot be.

    Refuses a field or value that is not there rather than padding to reach it:
    padding invents positions, and a position is a claim about a branch.

    Args:
        raw: The record as stored
        position: Which field, counting from one
        index: Which value within that field, counting from zero
        value: What to put there

    Returns:
        The changed record and None, or the unchanged record and the reason
    """
    fields = [field.split(_VM) for field in raw.split(_AM)] if raw else []
    if not 1 <= position <= len(fields):
        return raw, f"Field {position} does not exist; the record has {len(fields)} fields"
    values = fields[position - 1]
    if not 0 <= index < len(values):
        return raw, (
            f"Field {position} has {len(values)} values, so index {index} does not exist "
            "(indexes count from zero)"
        )
    values[index] = value
    return _AM.join(_VM.join(field) for field in fields), None
