# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for osclient.cli.index."""

import contextlib
import io
import json
from argparse import ArgumentParser
from typing import Any

from osclient.cli import index
from osclient.client import OpensearchClient
from osclient.result import OpensearchResult, Success


def test_load_documents_parses_each_format() -> None:
    docs = [{"a": 1}, {"a": 2}]
    assert index._load_documents('[{"a": 1}, {"a": 2}]', "json") == docs
    assert index._load_documents('{"a": 1}\n{"a": 2}\n', "jsonl") == docs
    assert index._load_documents("- a: 1\n- a: 2\n", "yaml") == docs
    # A single object is wrapped into a one-document list.
    assert index._load_documents('{"a": 1}', "json") == [{"a": 1}]


def test_load_documents_exits_on_bad_or_non_object_input() -> None:
    for text, fmt in [("{not json", "json"), ("[1, 2]", "json")]:
        try:
            index._load_documents(text, fmt)
            assert False, "expected SystemExit"
        except SystemExit as exit_error:
            assert exit_error.code == 2


class _RecordingTransport:
    """Records each request and answers every one with an empty success."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str = "application/json",
        timeout: int = 30,
    ) -> OpensearchResult[Any]:
        decoded = None if body is None else json.loads(body)
        self.calls.append((method, path, decoded))
        return Success({})


def _run_cli(argv: list[str], transport: _RecordingTransport) -> None:
    """Parse argv as an ``osclient index`` command and run it, discarding stdout."""
    parser = ArgumentParser()
    index.add_subparser(parser.add_subparsers(dest="subcommand"))
    args = parser.parse_args(["index", *argv])
    with contextlib.redirect_stdout(io.StringIO()):
        index.run(args, OpensearchClient(transport))


def test_rollover_is_a_dry_run_unless_applied_and_passes_settings_through() -> None:
    settings = {"index.number_of_shards": 1}
    cases: list[tuple[list[str], tuple[str, str, Any]]] = [
        (["rollover", "w"], ("POST", "w/_rollover?dry_run=true", None)),
        (["rollover", "w", "--apply"], ("POST", "w/_rollover?dry_run=false", None)),
        (
            ["rollover", "w", "--apply", "--settings", json.dumps(settings)],
            ("POST", "w/_rollover?dry_run=false", {"settings": settings}),
        ),
    ]
    for argv, expected in cases:
        transport = _RecordingTransport()
        _run_cli(argv, transport)
        assert transport.calls == [expected], argv


def test_rollover_rejects_settings_that_are_not_a_json_object() -> None:
    transport = _RecordingTransport()
    try:
        _run_cli(["rollover", "w", "--apply", "--settings", "[1]"], transport)
        assert False, "expected SystemExit"
    except SystemExit as exit_error:
        assert exit_error.code == 2
    assert transport.calls == []
