# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for opensearch_client.cli.index."""

from opensearch_client.cli import index


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
