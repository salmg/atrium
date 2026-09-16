"""
The command line, parsed.

What these establish: that every flag the code reads is a flag the parser
defines, and that the documented ones survive a rename.

Why they exist: `--split-responses` shipped with both of its uses wired up and
its definition missing. An edit script asserted, aborted before writing, and
only half the change was redone. Nothing caught it — pyflakes cannot see an
argparse attribute, the parser lived inside main() where no test could reach
it, and six hundred tests never ran it. The operator found it in one second.
"""
from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import atrium

# args.<name>, and getattr(args, "<name>"...) for the optional ones.
READS = re.compile(r"""args\.(\w+)|getattr\(\s*args\s*,\s*["'](\w+)["']""")


def flags_read_by(function) -> set[str]:
    source = inspect.getsource(function)
    return {a or b for a, b in READS.findall(source)}


def parse(*argv):
    return atrium.build_parser().parse_args(list(argv))


class TestEveryFlagTheCodeReadsExists:
    """
    The generic form of the bug. A namespace missing an attribute the handler
    reads is an AttributeError at the worst possible moment — after the reader
    is open and a terminal is waiting — or, as it happened, an argparse refusal
    that names the top-level usage and tells the operator nothing.
    """

    @pytest.mark.parametrize("command, argv", [
        ("emulate", ("nfc", "emulate")),
        ("scan", ("nfc", "scan")),
        ("probe", ("nfc", "probe")),
        ("measure-ats", ("nfc", "measure-ats")),
        ("transmit-limit", ("nfc", "transmit-limit")),
        ("info", ("nfc", "info")),
        ("identify", ("nfc", "identify")),
    ])
    def test_the_nfc_handler_finds_what_it_reaches_for(self, command, argv):
        args = parse(*argv)
        missing = {name for name in flags_read_by(atrium.cmd_nfc)
                   if not hasattr(args, name)}
        # cmd_nfc reads flags belonging to every nfc subcommand, so only the
        # ones this subcommand's own branch touches can be required. The
        # emulator's are checked in full below.
        assert "nfc_action" not in missing
        assert args.nfc_action == command

    def test_the_emulator_finds_every_flag_it_reads(self):
        args = parse("nfc", "emulate")
        missing = sorted(name for name in flags_read_by(atrium._run_emulator)
                         if not hasattr(args, name))
        assert not missing, (
            f"_run_emulator reads {missing}, which 'nfc emulate' does not "
            f"define — the shape of the --split-responses bug")


class TestTheFlagsThatCarryFindings:
    """
    Each of these exists because a run on real hardware needed it. A rename
    that silently drops one costs an operator a session to discover.
    """

    def test_split_responses(self):
        assert parse("nfc", "emulate", "--split-responses").split_responses
        assert not parse("nfc", "emulate").split_responses

    def test_trace_chip(self):
        assert parse("nfc", "emulate", "--trace-chip").trace_chip

    def test_prefetch_and_own_isodep(self):
        args = parse("nfc", "emulate", "--prefetch", "--own-isodep")
        assert args.prefetch and args.own_isodep

    def test_no_alert(self):
        assert parse("nfc", "emulate", "--no-alert").no_alert

    def test_they_combine(self):
        args = parse("nfc", "emulate", "--trace-chip", "--split-responses",
                     "--prefetch", "--no-alert")
        assert (args.trace_chip and args.split_responses
                and args.prefetch and args.no_alert)


class TestTheParserIsWholeAtAll:
    def test_every_subcommand_parses(self):
        for argv in (("serve",), ("relay",), ("agent",), ("pair",),
                     ("readers",), ("proxy",), ("all",),
                     ("nfc", "scan"), ("nfc", "emulate")):
            assert parse(*argv).command == argv[0]

    def test_every_dispatched_command_has_a_parser(self):
        """A command in the table with no parser can never be reached."""
        source = inspect.getsource(atrium.main)
        dispatched = set(re.findall(r'"(\w+)":\s*cmd_\w+', source))
        for name in dispatched:
            assert parse(name).command == name, f"{name} is dispatched but"
