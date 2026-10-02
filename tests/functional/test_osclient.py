# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Functional tests for osclient against a live OpenSearch cluster.

These require a running OpenSearch reachable via the ``OPENSEARCH_*`` environment
variables (``OPENSEARCH_URL``, ``OPENSEARCH_USER``, ``OPENSEARCH_PASSWORD``); when
any is unset the whole module is skipped, so a plain ``tox`` run without a cluster
stays green. ``tests/functional/run.sh`` starts an ephemeral Docker cluster, sets
the variables, runs these tests, and tears everything down.
"""

import contextlib
import os
import uuid
from collections.abc import Generator
from typing import Iterator

import pytest

from osclient import OpensearchClient, triage
from osclient import client as bulk_module
from osclient.config import client_from_env

if not (
    os.environ.get("OPENSEARCH_URL")
    and os.environ.get("OPENSEARCH_USER")
    and os.environ.get("OPENSEARCH_PASSWORD")
):
    pytest.skip(
        "OPENSEARCH_URL, OPENSEARCH_USER, and OPENSEARCH_PASSWORD must be set; "
        "no OpenSearch cluster available",
        allow_module_level=True,
    )


def _build_client() -> OpensearchClient:
    """Build the client, asserting it is configured (the skip guard ran above).

    The non-optional return type narrows ``_client`` to ``OpensearchClient`` for
    every test function, unlike a module-level assert which narrows only here.
    """
    client = client_from_env()
    assert client is not None, "OPENSEARCH_* is set but client_from_env returned None"
    return client


_client = _build_client()


@contextlib.contextmanager
def _temporary_indices(*names: str) -> Iterator[None]:
    """Delete the named indices on exit, whether the test passes or fails."""
    try:
        yield
    finally:
        for name in names:
            _client.request("DELETE", name)


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _block_writes(index: str, blocked: bool) -> None:
    """Block or unblock writes to the index, as a full disk would."""
    settings = {"index.blocks.write": blocked}
    assert _client.request("PUT", f"{index}/_settings", settings).ok


class _SleepRecorder:
    """Stands in for ``sleep``: records each delay, and can unblock writes midway."""

    def __init__(self, index: str, unblock_on_call: int | None = None) -> None:
        self.index = index
        self.unblock_on_call = unblock_on_call
        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)
        if len(self.delays) == self.unblock_on_call:
            _block_writes(self.index, False)


@contextlib.contextmanager
def _sleep_replaced(recorder: _SleepRecorder) -> Generator[None]:
    """Make ``bulk`` call the recorder instead of really waiting."""
    original = bulk_module.sleep
    setattr(bulk_module, "sleep", recorder)
    try:
        yield
    finally:
        setattr(bulk_module, "sleep", original)


def test_index_and_read_back() -> None:
    index = _unique("osclient-func")
    with _temporary_indices(index):
        assert _client.create_index(
            {"mappings": {"properties": {"name": {"type": "keyword"}}}}, index=index
        ).ok
        for i, name in enumerate(["a", "b", "c"]):
            assert _client.index_document(
                {"name": name, "n": i}, index=index, refresh=True
            ).ok

        search = _client.search({"query": {"match_all": {}}}, index=index)
        assert search
        assert len(search.data) == 3

        count = _client.count({"match_all": {}}, index=index)
        assert count
        assert count.data == 3

        rows = _client.sql(f"SELECT name FROM {index} ORDER BY n")
        assert rows
        assert [row["name"] for row in rows.data] == ["a", "b", "c"]


def test_triage_workflow_eliminates_a_layer() -> None:
    source = _unique("osclient-func-src")
    dest = _unique("osclient-func-triage")
    with _temporary_indices(source, dest):
        assert _client.create_index(
            {
                "mappings": {
                    "properties": {
                        "rule": {"properties": {"level": {"type": "integer"}}}
                    }
                }
            },
            index=source,
        ).ok
        for level in [1, 1, 1, 10, 10]:
            assert _client.index_document(
                {"rule": {"level": level}}, index=source, refresh=True
            ).ok

        # init copies the source into a fresh triage index, all untriaged.
        summary = triage.init(_client, source, dest, poll_seconds=0.5)
        assert summary["total"] == 5
        assert summary["tagged_untriaged"] == 5
        assert triage.status(_client, dest)["untriaged"] == 5

        # eliminate tags the low-severity docs (SQL predicate pushed down to DSL).
        # layer=None exercises the auto-increment branch; on a fresh index it is 1.
        result = triage.eliminate(
            _client,
            dest,
            "rule.level < 3",
            None,
            "low severity",
            apply=True,
        )
        assert result["updated"] == 3
        assert result["layer"] == 1

        after = triage.status(_client, dest)
        assert after["untriaged"] == 2
        assert after["eliminated_by_layer"] == {1: 3}

        # restore undoes layer 1: the 3 docs return to untriaged, and each records
        # the undone elimination on triage.history.
        undo = triage.restore(_client, dest, 1, None, apply=True)
        assert undo["restored"] == 3
        restored = triage.status(_client, dest)
        assert restored["untriaged"] == 5
        assert restored["eliminated_by_layer"] == {}

        rows = _client.search({"size": 10, "query": {"match_all": {}}}, index=dest)
        assert rows
        with_history = [doc for doc in rows.data if doc["triage"].get("history")]
        assert len(with_history) == 3  # only the restored docs carry history
        entry = with_history[0]["triage"]["history"][0]
        assert entry["layer"] == 1
        assert entry["query"] == "rule.level < 3"


def test_index_lifecycle_helpers() -> None:
    index = _unique("osclient-func-lifecycle")
    with _temporary_indices(index):
        assert _client.create_index({}, index=index).ok
        assert _client.index_exists(index).data is True
        assert _client.index_document({"n": 1}, index=index).ok
        assert _client.refresh(index=index).ok
        listed = _client.list_indices("osclient-func-lifecycle-*")
        assert listed and index in listed.data
        assert _client.delete_index(index).ok
        assert _client.index_exists(index).data is False


def test_bulk_indexes_documents_across_batches() -> None:
    index = _unique("osclient-func-bulk")
    with _temporary_indices(index):
        docs = [{"name": f"host-{i}", "n": i} for i in range(50)]
        # A small byte cap forces the 50 documents across several batches.
        result = _client.bulk(docs, index=index, max_bytes=300)
        assert result, result.reason
        assert result.data["indexed"] == 50
        assert result.data["failed"] == 0
        assert result.data["batches"] > 1

        assert _client.request("POST", f"{index}/_refresh").ok
        count = _client.count({"match_all": {}}, index=index)
        assert count
        assert count.data == 50
        rows = _client.sql(f"SELECT name FROM {index} WHERE n = 7")
        assert rows
        assert [row["name"] for row in rows.data] == ["host-7"]


def test_bulk_reports_rejected_documents_and_retries_only_transient_ones() -> None:
    index = _unique("osclient-func-bulk-reject")
    with _temporary_indices(index):
        assert _client.create_index(
            {"mappings": {"properties": {"n": {"type": "integer"}}}}, index=index
        ).ok
        # The middle document's value cannot coerce to the integer mapping, so the
        # cluster rejects that one item while indexing the others: a per-item error
        # inside an otherwise-200 bulk response.
        result = _client.bulk(
            [{"n": 1}, {"n": "not-an-int"}, {"n": 3}], index=index, max_retries=0
        )
        assert not result
        assert "1 of 3" in result.reason
        assert result.data["indexed"] == 2
        assert result.data["failed"] == 1
        failures = result.data["failures"]
        assert len(failures) == 1
        assert failures[0]["document"] == {"n": "not-an-int"}
        assert failures[0]["status"] >= 400
        assert failures[0]["error"] is not None

        # A rejected document is a permanent failure: even with retries allowed it
        # is sent once and bulk never waits.
        recorder = _SleepRecorder(index)
        with _sleep_replaced(recorder):
            permanent = _client.bulk([{"n": "not-an-int"}], index=index, max_retries=3)
        assert not permanent
        assert permanent.data["batches"] == 1
        assert recorder.delays == []

        # A write-blocked index fails every item with a 403 cluster_block_exception.
        # The status alone looks permanent, but the error type marks it transient
        # (the block can be lifted), so bulk retries, doubling the delay up to a
        # minute. The block is lifted before the last retry, which then succeeds.
        _block_writes(index, True)
        recorder = _SleepRecorder(index, unblock_on_call=8)
        with _sleep_replaced(recorder):
            recovered = _client.bulk([{"n": 4}], index=index, max_retries=8)
        assert recovered, recovered.reason
        assert recovered.data["batches"] == 9  # the first send and eight retries
        assert recorder.delays == [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0]

        # Two documents from the first call, and the retried one written once.
        assert _client.refresh(index=index).ok
        count = _client.count({"match_all": {}}, index=index)
        assert count
        assert count.data == 3
