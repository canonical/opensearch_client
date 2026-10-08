# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the command-line entry point name."""

import contextlib
import io
import sys
from importlib.metadata import entry_points

from opensearch_client.cli.main import main


def test_console_script_is_named_os_cli() -> None:
    scripts = {
        script.name: script.value
        for script in entry_points(group="console_scripts")
        if script.value.startswith("opensearch_client.")
    }

    assert scripts == {"os-cli": "opensearch_client.cli.main:main"}


def test_help_shows_os_cli_as_the_program_name() -> None:
    saved_argv = sys.argv
    sys.argv = ["ignored", "--help"]
    stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout):
            try:
                main()
            except SystemExit:
                pass
    finally:
        sys.argv = saved_argv

    assert stdout.getvalue().startswith("usage: os-cli ")
