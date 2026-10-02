# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""``opensearch_client cluster``: cluster-level inspection."""

import sys
from argparse import Namespace, _SubParsersAction
from typing import Any

from opensearch_client.cli.diagnostics import diagnose
from opensearch_client.cli.io import (
    add_format_argument,
    emit,
    parse_json_object,
    render,
    resolve_source,
)
from opensearch_client.client import OpensearchClient

NAME = "cluster"


def add_subparser(subparsers: _SubParsersAction) -> None:
    """Register ``cluster`` and its inspection verbs."""
    parser = subparsers.add_parser(NAME, help="cluster-level inspection")
    operations = parser.add_subparsers(dest="operation", required=True)

    versions = operations.add_parser(
        "versions", help="show OpenSearch and installed-plugin versions"
    )
    add_format_argument(versions)

    pipeline = operations.add_parser(
        "pipeline", help="show ingest pipelines (all, or one named)"
    )
    pipeline.add_argument(
        "name", nargs="?", metavar="NAME", help="pipeline to show (default: all)"
    )
    add_format_argument(pipeline)

    set_parser = operations.add_parser(
        "set", help="set a cluster-level resource (e.g. an ingest pipeline)"
    )
    set_targets = set_parser.add_subparsers(dest="set_target", required=True)
    set_pipeline = set_targets.add_parser(
        "pipeline",
        help="create or replace a named ingest pipeline",
        epilog="SOURCE is the pipeline definition as JSON: '@PATH' reads a file, "
        "'-' reads stdin, or give the text literally.",
    )
    set_pipeline.add_argument("name", metavar="NAME", help="the pipeline name")
    set_pipeline.add_argument(
        "source",
        metavar="SOURCE",
        help="the pipeline definition as JSON ('@PATH', '-', or literal)",
    )
    add_format_argument(set_pipeline)


def get_versions(client: OpensearchClient) -> dict[str, Any]:
    """Collect OpenSearch and installed-plugin versions.

    SQL and PPL are both provided by the single ``opensearch-sql`` plugin, so its
    version covers both. Each lookup is independent: if one fails its error is
    recorded and the other is still returned.
    """
    versions: dict[str, Any] = {}
    opensearch = client.opensearch_version()
    versions["opensearch"] = (
        opensearch.data if opensearch.ok else {"error": opensearch.reason}
    )
    plugins = client.plugin_versions()
    versions["plugins"] = plugins.data if plugins.ok else {"error": plugins.reason}
    return versions


def run(args: Namespace, client: OpensearchClient) -> None:
    """Run the chosen operation against the client."""
    if args.operation == "versions":
        print(render(get_versions(client), args.format))
    elif args.operation == "pipeline":
        emit(diagnose(client.get_pipeline(args.name)), "Pipeline", args.format)
    elif args.operation == "set" and args.set_target == "pipeline":
        body = parse_json_object(resolve_source(args.source), "pipeline definition")
        if body is None:
            sys.exit(2)
        result = client.put_pipeline(args.name, body)
        emit(diagnose(result), "Set pipeline", args.format)
