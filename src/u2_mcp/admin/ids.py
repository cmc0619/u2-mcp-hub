"""Row ids from URLs and forms: anything SQLite cannot hold is simply not found."""

from starlette.convertors import IntegerConvertor, register_url_convertor

MAX_ID = 2**63 - 1
# 18 digits always fit SQLite's 64-bit integers; a longer id matches no route.
MAX_ID_DIGITS = 18


class IdConvertor(IntegerConvertor):
    """A path id of at most 18 digits (`{id:id}`)."""

    regex = f"[0-9]{{1,{MAX_ID_DIGITS}}}"


register_url_convertor("id", IdConvertor())


def parse_id(value: object) -> int | None:
    """A submitted id as an int, or None when malformed or beyond SQLite's range."""
    text = str(value or "")
    if not (text.isascii() and text.isdecimal()) or len(text) > MAX_ID_DIGITS + 1:
        return None
    number = int(text)
    return number if number <= MAX_ID else None
