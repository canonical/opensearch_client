# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch client library.

The public surface:

    from osclient import OpensearchClient, OpensearchResult, client_from_env

and, to ship log records to an index, ``OpensearchHandler``.
"""

from osclient.client import DEFAULT_INDEX, OpensearchClient
from osclient.config import client_from_env
from osclient.log_handler import OpensearchHandler
from osclient.result import Failure, OpensearchResult, Success
from osclient.transport import (
    DirectTransport,
    FailoverTransport,
    ProbeTransport,
    ProxyTransport,
)

__all__ = [
    "OpensearchClient",
    "OpensearchHandler",
    "OpensearchResult",
    "Success",
    "Failure",
    "DEFAULT_INDEX",
    "client_from_env",
    "DirectTransport",
    "ProxyTransport",
    "FailoverTransport",
    "ProbeTransport",
]
