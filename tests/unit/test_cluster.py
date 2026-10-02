# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for osclient.cli.cluster."""

import contextlib
import io
import json
from argparse import ArgumentParser
from typing import Any

import yaml

from osclient.cli import cluster
from osclient.client import OpensearchClient
from osclient.result import Failure, OpensearchResult, Success


class RecordingTransport:
    """Records each request and answers every one with the same payload."""

    def __init__(self, payload: Any) -> None:
        self.payload = payload
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
        return Success(self.payload)


class NotFoundTransport:
    """Records each request and answers every one with a 404."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str = "application/json",
        timeout: int = 30,
    ) -> OpensearchResult[Any]:
        self.calls.append((method, path))
        return Failure("no such template", status=404)


def _run_cli(argv: list[str], transport: Any) -> str:
    """Parse argv as an ``osclient cluster`` command, run it, return stdout."""
    parser = ArgumentParser()
    cluster.add_subparser(parser.add_subparsers(dest="subcommand"))
    args = parser.parse_args(["cluster", *argv])
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        cluster.run(args, OpensearchClient(transport))
    return stdout.getvalue()


def test_template_commands_send_the_expected_request() -> None:
    body = {"index_patterns": ["x-*"]}
    source = json.dumps(body)
    cases: list[tuple[list[str], tuple[str, str, Any]]] = [
        (["template"], ("GET", "_index_template", None)),
        (["template", "t"], ("GET", "_index_template/t", None)),
        (["template", "t", "--legacy"], ("GET", "_template/t", None)),
        (["set", "template", "t", source], ("PUT", "_index_template/t", body)),
        (
            ["delete", "template", "t", "--apply"],
            ("DELETE", "_index_template/t", None),
        ),
        (
            ["simulate", "template", "t", source],
            ("POST", "_index_template/_simulate/t", body),
        ),
        (
            ["simulate", "index", "x-1"],
            ("POST", "_index_template/_simulate_index/x-1", None),
        ),
        (["component-template"], ("GET", "_component_template", None)),
        (["component-template", "c"], ("GET", "_component_template/c", None)),
        (
            ["set", "component-template", "c", source],
            ("PUT", "_component_template/c", body),
        ),
        (
            ["delete", "component-template", "c", "--apply"],
            ("DELETE", "_component_template/c", None),
        ),
    ]
    for argv, expected in cases:
        transport = RecordingTransport({})
        _run_cli(argv, transport)
        assert transport.calls == [expected], argv


def test_delete_template_dry_run_reports_patterns_without_deleting() -> None:
    template = {"name": "t", "index_template": {"index_patterns": ["a-*", "b-*"]}}
    transport = RecordingTransport({"index_templates": [template]})
    output = _run_cli(["delete", "template", "t"], transport)
    assert [method for method, _, _ in transport.calls] == ["GET"]
    assert yaml.safe_load(output) == {
        "template": "t",
        "dry_run": True,
        "index_patterns": ["a-*", "b-*"],
    }


def test_delete_component_template_dry_run_names_its_users_without_deleting() -> None:
    users = [
        {"name": "uses-it", "index_template": {"composed_of": ["c", "other"]}},
        {"name": "does-not", "index_template": {"composed_of": ["other"]}},
    ]
    transport = RecordingTransport({"index_templates": users})
    output = _run_cli(["delete", "component-template", "c"], transport)
    assert [method for method, _, _ in transport.calls] == ["GET", "GET"]
    assert yaml.safe_load(output) == {
        "component_template": "c",
        "dry_run": True,
        "used_by": ["uses-it"],
    }


def test_delete_dry_run_of_a_missing_template_fails() -> None:
    cases = [
        (["delete", "template", "gone"], [("GET", "_index_template/gone")]),
        (
            ["delete", "component-template", "gone"],
            [("GET", "_component_template/gone")],
        ),
    ]
    for argv, expected_calls in cases:
        transport = NotFoundTransport()
        try:
            _run_cli(argv, transport)
            assert False, "expected SystemExit"
        except SystemExit as exit_error:
            assert exit_error.code == 1
        assert transport.calls == expected_calls, argv


def test_delete_refuses_a_name_that_could_match_several_templates() -> None:
    for target in ("template", "component-template"):
        for name in ("t-*", "a,b"):
            transport = RecordingTransport({})
            try:
                _run_cli(["delete", target, name, "--apply"], transport)
                assert False, "expected SystemExit"
            except SystemExit as exit_error:
                assert exit_error.code == 2
            assert transport.calls == [], (target, name)
