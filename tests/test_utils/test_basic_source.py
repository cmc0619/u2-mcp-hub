"""The rules the BASIC tools stand on, tested without a database."""

import pytest

from u2_mcp.utils.basic_source import (
    AM,
    MAX_OUTPUT_CHARS,
    PATTERN_RE,
    cap_output,
    catalog_command,
    compile_command,
    name_problem,
    numbered_lines,
    object_file_name,
    parse_compile_output,
    program_file_problem,
    record_hash,
    record_to_lines,
    source_hash,
    source_problem,
    source_to_record,
    split_object_ids,
)

ALLOWED = ["*BP", "BP.*"]

UV_OK = "Compiling: Source = 'BP/HELLO', Object = 'BP.O/HELLO'\n*\nCompilation Complete."
UV_WARN = (
    "Compiling: Source = 'BP/HELLO', Object = 'BP.O/HELLO'\n*\n"
    "WARNING: Variable 'X' never assigned a value.\nCompilation Complete."
)
UV_BAD = (
    "Compiling: Source = 'BP/BAD', Object = 'BP.O/BAD'\n*\n"
    '0003   PRINT "A" "\n                  ^\n'
    "End of Line unexpected, Was expecting: Array Name, Variable, Literal Number\n\n"
    "1 Errors detected, No Object Code Produced."
)
UD_OK = "Compiling Unibasic: BP/HELLO in mode 'u'.\ncompilation finished"
UD_BAD = (
    "Compiling Unibasic: BP/BAD in mode 'u'.\nmain program: syntax error at or before\n"
    'line 3 : PRINT "A" "\n                   ^\ncompilation failed'
)


class TestNames:
    @pytest.mark.parametrize("name", ["BP", "HELLO", "ORD.POST", "A-1", "x_y", "9LIVES"])
    def test_ordinary_names_pass(self, name: str) -> None:
        assert name_problem("program", name) is None

    @pytest.mark.parametrize(
        "name",
        ["", "*GLOBAL", "-OPT", "$X", "!X", "_HELLO", "A B", 'A"B', "A;B", "A'B", "X" * 65],
    )
    def test_names_with_meaning_or_quotes_are_refused(self, name: str) -> None:
        assert name_problem("program", name) == (
            "program must be 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit"
        )

    def test_patterns_allow_wildcards_only(self) -> None:
        assert PATTERN_RE.fullmatch("ORD*")
        assert not PATTERN_RE.fullmatch('BP" X')


class TestProgramFiles:
    @pytest.mark.parametrize("name", ["BP", "bp", "XBP", "SUBS.BP", "BP.UTIL"])
    def test_program_files_pass(self, name: str) -> None:
        assert program_file_problem(name, ALLOWED) is None

    def test_a_data_file_is_refused_and_the_setting_is_named(self) -> None:
        assert program_file_problem("CUSTOMERS", ALLOWED) == (
            "CUSTOMERS is not a BASIC program file on this server. Program files are "
            "those matching U2_BASIC_FILES: *BP, BP.*"
        )

    def test_object_files_are_never_source(self) -> None:
        assert program_file_problem("BP.O", ALLOWED) == "BP.O holds object code, not source"

    def test_a_bad_file_name_is_reported_as_a_name(self) -> None:
        assert program_file_problem("BP X", ALLOWED) == name_problem("file_name", "BP X")


class TestSourceAndRecord:
    @pytest.mark.parametrize(
        "raw", ["", "CRT 'HI'", "A" + AM + "B", "A" + AM + "", AM + AM + "END", "café" + AM + "€"]
    )
    def test_reading_then_writing_back_stores_the_identical_record(self, raw: str) -> None:
        source = "\n".join(record_to_lines(raw))
        assert source_to_record(source) == raw
        assert source_hash(source) == record_hash(raw)

    def test_windows_and_old_mac_line_ends_become_lines(self) -> None:
        assert source_to_record("A\r\nB\rC") == AM.join(["A", "B", "C"])

    def test_a_trailing_newline_is_an_empty_last_line(self) -> None:
        assert source_to_record("A\n") == "A" + AM

    def test_an_empty_record_has_no_lines(self) -> None:
        assert record_to_lines("") == []

    def test_the_hash_is_sha256_of_the_stored_record(self) -> None:
        assert record_hash("A") == (
            "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd"
        )

    @pytest.mark.parametrize("code", [251, 252, 253, 254, 255])
    def test_mark_characters_are_refused_with_their_line(self, code: int) -> None:
        assert source_problem("OK\nBAD" + chr(code)) == (
            "source line 2 contains a U2 mark character (chr 251-255), "
            "which would change the record's shape"
        )

    def test_accented_letters_below_the_marks_are_not_marks(self) -> None:
        # é is chr(233) and ø chr(248). û ü ý þ ÿ ARE chr(251)-chr(255): the marks.
        assert source_problem("CRT 'café ø'") is None

    def test_oversized_source_is_refused(self) -> None:
        assert source_problem("X" * 1_000_001) == "source is longer than 1000000 characters"

    def test_numbered_lines_start_where_asked(self) -> None:
        assert numbered_lines(["A", "B"], 9) == "    9  A\n   10  B"

    def test_output_is_capped(self) -> None:
        text, cut = cap_output("X" * (MAX_OUTPUT_CHARS + 5))
        assert (len(text), cut) == (MAX_OUTPUT_CHARS, True)
        assert cap_output("short") == ("short", False)


class TestCommands:
    @pytest.mark.parametrize("service", ["uvcs", "udcs"])
    def test_the_commands_name_the_mode_explicitly(self, service: str) -> None:
        assert compile_command(service, "BP", "HELLO") == "BASIC BP HELLO"
        assert catalog_command(service, "BP", "HELLO") == "CATALOG BP HELLO LOCAL"

    @pytest.mark.parametrize("bad", ['HI" GLOBAL', "*HI", "HI X"])
    def test_builders_refuse_names_that_were_not_checked(self, bad: str) -> None:
        with pytest.raises(ValueError):
            compile_command("uvcs", "BP", bad)
        with pytest.raises(ValueError):
            catalog_command("udcs", bad, "HELLO")

    def test_universe_object_code_lives_in_a_dot_o_file(self) -> None:
        assert object_file_name("BP") == "BP.O"

    def test_unidata_object_records_are_hidden_and_mark_their_program(self) -> None:
        names, objects = split_object_ids("udcs", ["A", "_A", "B"])
        assert (names, objects) == (["A", "B"], {"A"})

    def test_universe_listing_is_left_whole(self) -> None:
        assert split_object_ids("uvcs", ["A", "_A"]) == (["A", "_A"], None)


class TestCompilerOutput:
    def test_universe_success(self) -> None:
        assert parse_compile_output("uvcs", UV_OK) == {
            "status": "compiled",
            "errors": [],
            "warnings": [],
        }

    def test_universe_warning_still_compiles(self) -> None:
        parsed = parse_compile_output("uvcs", UV_WARN)
        assert parsed["status"] == "compiled"
        assert parsed["warnings"] == ["WARNING: Variable 'X' never assigned a value."]

    def test_universe_error_has_its_line_and_message(self) -> None:
        parsed = parse_compile_output("uvcs", UV_BAD)
        assert parsed["status"] == "failed"
        assert parsed["errors"] == [
            {
                "line": 3,
                "message": "End of Line unexpected, Was expecting: Array Name, Variable, "
                "Literal Number",
            }
        ]

    def test_unidata_success(self) -> None:
        assert parse_compile_output("udcs", UD_OK)["status"] == "compiled"

    def test_unidata_error_has_its_line_and_message(self) -> None:
        parsed = parse_compile_output("udcs", UD_BAD)
        assert parsed["status"] == "failed"
        assert parsed["errors"] == [
            {"line": 3, "message": "main program: syntax error at or before"}
        ]

    @pytest.mark.parametrize("service", ["uvcs", "udcs"])
    def test_output_with_no_known_marker_is_unknown_never_success(self, service: str) -> None:
        assert parse_compile_output(service, "Command executed: BASIC BP X")["status"] == (
            "unknown"
        )

    def test_errors_are_capped(self) -> None:
        many = "\n".join(f"{n:04d}   X\nbad thing" for n in range(1, 300))
        assert len(parse_compile_output("uvcs", many)["errors"]) == 200


class TestKeywordNames:
    @pytest.mark.parametrize(
        "name",
        ["DIRECT", "GLOBAL", "FORCE", "LOCAL", "NEWVERSION", "COMPLETE", "local", "Global"],
    )
    def test_command_keywords_are_refused_as_program_names(self, name: str) -> None:
        assert name_problem("program", name) == (
            f"program cannot be named {name}: it is a CATALOG/BASIC keyword"
        )

    def test_a_keyword_cannot_reach_a_command(self) -> None:
        with pytest.raises(ValueError, match="keyword"):
            catalog_command("uvcs", "BP", "LOCAL")

    def test_longer_names_that_contain_a_keyword_pass(self) -> None:
        assert name_problem("program", "LOCAL.TAX") is None
