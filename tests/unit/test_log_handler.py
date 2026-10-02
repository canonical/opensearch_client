# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for opensearch_client.log_handler.OpensearchHandler.

The handler talks to a ``FakeClient`` that answers the three client calls it
makes. Requests, batching, retries and their delays belong to OpensearchClient and
are tested in test_client.py, and delivery to a real cluster is covered by the
functional tests. These tests cover what the handler adds on top.
"""

import contextlib
import logging
import socket
import sys
import threading
import time
from collections.abc import Generator, Iterable
from typing import Any, cast

from opensearch_client import log_handler
from opensearch_client.client import OpensearchClient
from opensearch_client.log_handler import OpensearchHandler
from opensearch_client.result import Failure, OpensearchResult, Success

# How long the tests wait on another thread before deciding it is stuck. Only
# reached when the code under test is broken.
_WAIT_SECONDS = 5

# How long to watch for activity that should not happen.
_QUIET_SECONDS = 0.3


class FakeClient:
    """Stands in for ``OpensearchClient``: answers the calls the handler makes.

    Attributes:
        calls (list[str]): the name of every call, in order.
        documents (list[dict[str, Any]]): the documents of every ``bulk`` call that
            succeeded, in order.
        index_present (bool): whether the index exists.
        failure (dict[str, Any] | None): how every document of a ``bulk`` call
            fails, as the failure summary describes it (``status`` plus ``error``
            or ``reason``), or None to accept them.
        bulk_received (threading.Event): set once a ``bulk`` call has been answered.
    """

    def __init__(
        self,
        *,
        index_present: bool = True,
        failure: dict[str, Any] | None = None,
        bulk_error: Exception | None = None,
        chatter: bool = False,
    ) -> None:
        """Create the fake.

        Args:
            index_present (bool): whether the index is already there.
            failure (dict[str, Any] | None): how documents fail, or None to accept
                them.
            bulk_error (Exception | None): raised by every ``bulk`` call.
            chatter (bool): log a warning on the root logger during every ``bulk``
                call, as the libraries under a real client do.
        """
        self.index_present = index_present
        self.failure = failure
        self.bulk_error = bulk_error
        self.chatter = chatter
        self.calls: list[str] = []
        self.documents: list[dict[str, Any]] = []
        self.bulk_received = threading.Event()

    def index_exists(self, index: str) -> OpensearchResult[bool]:
        self.calls.append("index_exists")
        return Success(self.index_present)

    def create_index(
        self, body: dict[str, Any], index: str | None = None
    ) -> OpensearchResult[dict[str, Any]]:
        self.calls.append("create_index")
        self.index_present = True
        return Success({})

    def bulk(
        self,
        documents: Iterable[dict[str, Any]],
        index: str | None = None,
        *,
        max_retries: int = 3,
    ) -> OpensearchResult[dict[str, Any]]:
        self.calls.append("bulk")
        if self.chatter:
            logging.warning("client chatter")
        if self.bulk_error is not None:
            raise self.bulk_error
        sent = list(documents)
        if self.failure is None:
            self.documents.extend(sent)
            summary = {"indexed": len(sent), "failed": 0, "batches": 1, "failures": []}
            self.bulk_received.set()
            return Success(summary)
        failures = [{**self.failure, "document": document} for document in sent]
        summary = {
            "indexed": 0,
            "failed": len(sent),
            "batches": 1,
            "failures": failures,
        }
        self.bulk_received.set()
        return Failure(f"{len(sent)} documents failed to index", data=summary)

    def recover(self) -> None:
        """Start accepting documents."""
        self.failure = None


class BlockingClient(FakeClient):
    """A FakeClient that holds the first ``bulk`` call open until released."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.send_started = threading.Event()
        self.release_send = threading.Event()
        self.is_first_send = True

    def bulk(
        self,
        documents: Iterable[dict[str, Any]],
        index: str | None = None,
        *,
        max_retries: int = 3,
    ) -> OpensearchResult[dict[str, Any]]:
        if self.is_first_send:
            self.is_first_send = False
            self.send_started.set()
            # Outlasts the test's own wait, so a broken handler cannot hang it.
            if not self.release_send.wait(_WAIT_SECONDS * 2):
                raise RuntimeError("the send was never released")
        return super().bulk(documents, index, max_retries=max_retries)


class ThreadSpy:
    """Stands in for Thread: records the handler's attributes at start, runs nothing."""

    attributes_at_start: set[str] = set()

    def __init__(self, target: Any, name: str, daemon: bool) -> None:
        self.target = target

    def start(self) -> None:
        ThreadSpy.attributes_at_start = set(vars(self.target.__self__))

    def is_alive(self) -> bool:
        return False

    def join(self, timeout: float | None = None) -> None:
        pass


class ErrorRecordingHandler(OpensearchHandler):
    """Keeps the records passed to handleError instead of printing a traceback."""

    def __init__(self, client: OpensearchClient, index: str, **kwargs: Any) -> None:
        super().__init__(client, index, **kwargs)
        self.errored_records: list[logging.LogRecord] = []

    def handleError(self, record: logging.LogRecord) -> None:
        self.errored_records.append(record)


def _as_client(client: FakeClient) -> OpensearchClient:
    """Give the handler the fake where it expects an ``OpensearchClient``."""
    return cast(OpensearchClient, client)


def _build_handler(client: FakeClient, **kwargs: Any) -> OpensearchHandler:
    # An hour, so the timer never fires during a test unless the test sets it.
    kwargs.setdefault("flush_interval", 3600.0)
    return OpensearchHandler(_as_client(client), "logs", **kwargs)


@contextlib.contextmanager
def _close_after(handler: OpensearchHandler) -> Generator[OpensearchHandler]:
    """Yield the handler, then close it so its flush thread stops."""
    try:
        yield handler
    finally:
        handler.close()


def _make_record(
    message: str, extra: dict[str, Any] | None = None
) -> logging.LogRecord:
    """A record as a logger makes it, with ``extra=`` attributes if given."""
    logger = logging.getLogger("test")
    return logger.makeRecord(
        "test", logging.INFO, __file__, 1, message, (), None, None, extra
    )


def _emit_all_then_signal(
    handler: OpensearchHandler,
    records: list[logging.LogRecord],
    emitted: threading.Event,
) -> None:
    for record in records:
        handler.emit(record)
    emitted.set()


def test_emit_queues_ecs_documents_and_contains_bad_records() -> None:
    """An exception record becomes an ECS document; a bad one is reported."""
    client = FakeClient()
    handler = ErrorRecordingHandler(_as_client(client), "logs", flush_interval=3600.0)
    try:
        raise ValueError("bad value")
    except ValueError:
        exc_info = sys.exc_info()
    good = logging.LogRecord(
        "test", logging.ERROR, __file__, 1, "got %s and %d", ("text", 3), exc_info
    )
    bad = logging.LogRecord(
        "test", logging.INFO, __file__, 1, "%d", ("not a number",), None
    )

    with _close_after(handler):
        handler.emit(bad)
        handler.emit(good)
        handler.flush()

        assert handler.errored_records == [bad]
        assert handler.dropped == 0
        assert len(client.documents) == 1
        document = client.documents[0]
        assert document["message"] == "got text and 3"
        assert document["log"]["level"] == "error"
        assert document["log"]["logger"] == "test"
        assert document["event"]["severity"] == logging.ERROR
        # With no service_name, the name comes from the running program.
        assert document["service"]["name"]
        assert document["event"]["dataset"] == document["service"]["name"]
        assert document["error"]["type"] == "ValueError"
        assert document["error"]["message"] == "bad value"
        assert "ValueError: bad value" in document["error"]["stack_trace"]
        assert "args" not in document
        assert "exc_info" not in document


def test_documents_carry_identity_labels_and_merged_extra_fields() -> None:
    """Shared identity, extras and extra_fields (which win) are in every document."""
    client = FakeClient()
    extra_fields = {
        "service": {"version": "1.2"},
        "labels": {"env": "test"},
        "event": {"dataset": "custom-dataset"},
        "log": {"level": "OVERRIDE"},
    }
    handler = _build_handler(client, service_name="superset", extra_fields=extra_fields)
    extra = {"collector": "superset", "batch.size": 3, "skipped": None}
    first = _make_record("one", extra)
    first.created = 1_700_000_000.123456
    second = _make_record("two")
    second.stack_info = "Stack (most recent call last):\n  File x, line 1"

    with _close_after(handler):
        handler.emit(first)
        handler.emit(second)
        handler.flush()

        first_document, second_document = client.documents
        assert first_document["@timestamp"] == "2023-11-14T22:13:20.123Z"
        assert first_document["ecs"] == {"version": "9.0"}
        assert first_document["host"] == {"name": socket.gethostname()}
        assert first_document["agent"]["type"] == "opensearch_client"
        # extra_fields are merged into service, not a replacement for it.
        service = first_document["service"]
        assert service["name"] == "superset"
        assert service["version"] == "1.2"
        assert service["ephemeral_id"] == second_document["service"]["ephemeral_id"]
        # extra_fields replace a default (event.dataset) and a field taken from
        # the record (log.level), and leave their siblings alone.
        assert first_document["event"] == {
            "dataset": "custom-dataset",
            "severity": logging.INFO,
        }
        assert first_document["log"]["level"] == "OVERRIDE"
        assert first_document["log"]["logger"] == "test"
        assert first_document["labels"] == {
            "env": "test",
            "collector": "superset",
            "batch_size": "3",
        }
        assert first_document["python"] == {"msg": "one", "pathname": __file__}
        assert "error" not in first_document
        # stack_info alone is reported as a stack trace, with no exception type.
        assert second_document["error"] == {"stack_trace": second.stack_info}
        # Nothing from the first record carries over into the second.
        assert second_document["labels"] == {"env": "test"}


def test_flush_thread_starts_after_the_handler_is_fully_set_up() -> None:
    """A thread started early could use state that does not exist yet."""
    original = log_handler.Thread
    setattr(log_handler, "Thread", ThreadSpy)
    try:
        handler = _build_handler(FakeClient())
    finally:
        setattr(log_handler, "Thread", original)

    assert ThreadSpy.attributes_at_start == set(vars(handler))
    handler.close()


def test_stalled_send_does_not_block_emit_and_the_queue_stays_bounded() -> None:
    """While a send hangs, emit returns, the oldest waiting record is dropped."""
    client = BlockingClient()
    with _close_after(
        _build_handler(client, flush_threshold=1, buffer_limit=2)
    ) as handler:
        handler.emit(_make_record("a"))
        assert client.send_started.wait(_WAIT_SECONDS), "the send never started"

        emitted = threading.Event()
        records = [_make_record("b"), _make_record("c"), _make_record("d")]
        emitter = threading.Thread(
            target=_emit_all_then_signal, args=(handler, records, emitted)
        )
        emitter.start()
        emit_returned = emitted.wait(_WAIT_SECONDS)
        client.release_send.set()
        emitter.join()
        handler.flush()

        assert emit_returned, "emit blocked while a send was in progress"
        assert [document["message"] for document in client.documents] == [
            "a",
            "c",
            "d",
        ]
        assert handler.dropped == 1


def test_queued_records_are_sent_without_an_explicit_flush() -> None:
    """A full buffer and an elapsed interval each send the queue on their own."""
    full_buffer = {"flush_threshold": 2, "flush_interval": 3600.0}
    interval_elapsed = {"flush_threshold": 1000, "flush_interval": 0.05}

    for settings, record_count in ((full_buffer, 2), (interval_elapsed, 1)):
        client = FakeClient()
        with _close_after(_build_handler(client, **settings)) as handler:
            for number in range(record_count):
                handler.emit(_make_record(str(number)))

            assert client.bulk_received.wait(_WAIT_SECONDS), f"not sent: {settings}"
            assert len(client.documents) == record_count


def test_send_path_records_are_ignored_and_a_locked_flush_does_not_stall() -> None:
    """Chatter from the send is never shipped, and logging.shutdown cannot stall."""
    client = FakeClient(chatter=True)
    with _close_after(_build_handler(client)) as handler:
        root = logging.getLogger()
        previous_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.INFO)
        try:
            handler.emit(_make_record("hello"))
            handler.flush()
            handler.flush()  # would send the chatter, had it been queued
            messages = [document["message"] for document in client.documents]
            assert messages == ["hello"]

            handler.emit(_make_record("goodbye"))
            started = time.monotonic()
            handler.acquire()  # logging.shutdown flushes with this lock held
            try:
                handler.flush()
            finally:
                handler.release()
            elapsed = time.monotonic() - started
        finally:
            root.removeHandler(handler)
            root.setLevel(previous_level)

        assert elapsed < _WAIT_SECONDS, "flush stalled while the handler lock was held"


def test_index_is_checked_on_first_flush_and_again_only_when_it_goes_missing() -> None:
    """Building the handler makes no calls; the first flush checks the index."""
    index_missing = (False, ["index_exists", "create_index", "bulk", "bulk"])
    index_present = (True, ["index_exists", "bulk", "bulk"])

    for index_exists, expected_calls in (index_missing, index_present):
        client = FakeClient(index_present=index_exists)
        with _close_after(_build_handler(client)) as handler:
            assert client.calls == []

            handler.emit(_make_record("one"))
            handler.flush()
            handler.emit(_make_record("two"))
            handler.flush()

            assert client.calls == expected_calls

            # The index is deleted: the next send fails, and the one after
            # that creates the index again before sending.
            client.index_present = False
            client.failure = {
                "status": 404,
                "error": {"type": "index_not_found_exception"},
            }
            client.calls.clear()
            handler.emit(_make_record("three"))
            handler.flush()
            client.recover()
            handler.flush()

            assert client.calls == ["bulk", "index_exists", "create_index", "bulk"]
            assert [document["message"] for document in client.documents] == [
                "one",
                "two",
                "three",
            ]


def test_failed_sends_are_kept_and_resent_until_the_handler_closes() -> None:
    """Failed sends are kept and resent until close, without a tight retry loop.

    Records are lost only if the buffer limit is passed (see the next test) or
    when the handler closes while the cluster is still down.
    """
    down = {"status": None, "reason": "down"}
    client = FakeClient(failure=down)
    with _close_after(_build_handler(client, flush_threshold=2)) as handler:
        handler.emit(_make_record("a"))
        handler.flush()

        assert client.calls.count("bulk") == 1
        assert handler.dropped == 0

        client.bulk_received.clear()
        handler.emit(_make_record("b"))  # fills the buffer, but the handler backs off
        assert not client.bulk_received.wait(_QUIET_SECONDS), "retrying in a loop"

        client.recover()
        handler.flush()
        assert [document["message"] for document in client.documents] == ["a", "b"]
        assert handler.dropped == 0

        client.failure = down
        handler.emit(_make_record("c"))
        handler.close()
        assert handler.dropped == 1  # closing gives up on what could not be sent


def test_records_kept_after_a_failed_send_respect_buffer_limit_oldest_first() -> None:
    """Kept records go back in front, and the oldest are dropped past buffer_limit."""
    client = BlockingClient(failure={"status": None, "reason": "down"})
    with _close_after(
        _build_handler(client, flush_threshold=3, buffer_limit=3)
    ) as handler:
        for name in ("a", "b", "c"):
            handler.emit(
                _make_record(name)
            )  # the third fills the buffer; its send blocks
        assert client.send_started.wait(_WAIT_SECONDS), "the send never started"
        handler.emit(_make_record("d"))
        handler.emit(_make_record("e"))

        client.release_send.set()  # the blocked send now fails
        handler.flush()
        assert handler.dropped == 2

        client.recover()
        handler.flush()
        assert [document["message"] for document in client.documents] == [
            "c",
            "d",
            "e",
        ]
        assert handler.dropped == 2


def test_temporary_failures_are_kept_and_rejected_documents_are_dropped() -> None:
    """Only a failure that can clear up later is worth sending again."""
    cases = (
        (503, "unavailable_shards_exception", True),
        (429, "es_rejected_execution_exception", True),
        (403, "cluster_block_exception", True),
        (400, "mapper_parsing_exception", False),
    )

    for status, error_type, is_kept in cases:
        failure = {"status": status, "error": {"type": error_type}}
        client = FakeClient(failure=failure)
        with _close_after(_build_handler(client)) as handler:
            handler.emit(_make_record("one"))
            handler.flush()
            client.recover()
            handler.flush()

            expected = (1, 0) if is_kept else (0, 1)  # (delivered, dropped)
            assert (len(client.documents), handler.dropped) == expected, (
                f"{status} {error_type}"
            )


def test_a_send_that_raises_is_contained() -> None:
    """Records are counted as dropped; the thread lives on; close does not raise."""
    client = FakeClient(bulk_error=RuntimeError("boom"))
    handler = _build_handler(client)

    with _close_after(handler):
        handler.emit(_make_record("one"))
        handler.flush()
        assert handler.dropped == 1

        handler.emit(_make_record("two"))
        handler.flush()
        assert handler.dropped == 2  # the flush thread survived the first failure

        handler.emit(_make_record("three"))
    # Leaving the block closed the handler. Its final send raised, and that must
    # not have escaped.

    assert handler.dropped == 3
    assert not handler._flush_thread.is_alive()


def test_close_sends_the_remaining_records_and_stops_the_flush_thread() -> None:
    """Closing flushes what is queued; a later flush returns at once."""
    client = FakeClient()
    handler = _build_handler(client)
    handler.emit(_make_record("last"))

    handler.close()

    assert [document["message"] for document in client.documents] == ["last"]
    assert not handler._flush_thread.is_alive()

    started = time.monotonic()
    handler.flush()  # logging.shutdown flushes handlers that were already closed
    assert time.monotonic() - started < _WAIT_SECONDS
