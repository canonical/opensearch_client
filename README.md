# opensearch_client

OpenSearch client library

## Install

Install the package as you would any non-PyPi Python package. For example:

```
python3 -m pip install -e .
```

or

```
pipx install git+https://github.com/canonical/opensearch_client.git
```

Runtime dependencies: `requests`, `PyYAML`.

## Overview

`osclient` provides:

- a Python library for querying an OpenSearch cluster (directly, or through a
  dashboard console proxy as a fallback), where every call returns an
  `OpensearchResult` (`ok` / `data` / `reason`) rather than raising; and
- a single `osclient` command-line tool with `query` (read-only SQL, PPL, and
  term queries) and `triage` (layered threat-hunt) subcommands.

## Documentation

- [Library](docs/library.md): the client API and connection helpers.
- [CLI](docs/cli.md): the `osclient query` and `osclient triage` subcommands.
- [SQL `_explain`](docs/sql-explain.md): the `_explain` output the triage
  predicate translation parses.

## Roadmap

The client currently covers single-document indexing, search, SQL and PPL,
counts, mappings, versions, index creation, reindex, update-by-query, and task
polling, over a direct or dashboard-proxy transport with server-certificate
verification. The following capabilities are planned but not yet implemented:

### Bulk indexing

A method for writing many documents in one round trip via the `_bulk` API:

- serialize documents to newline-delimited JSON and split them into batches
  bounded by a configurable byte limit;
- retry transient transport errors and 5xx responses, and halve the batch size
  on a `413` (request entity too large) before retrying;
- inspect the per-item results and report which documents failed and why, rather
  than treating a `200` on the bulk request as success.

### Mutual TLS

Client-certificate authentication in the transports: a certificate and private
key supplied alongside the existing verify / CA-bundle options, for clusters
that require clients to present a certificate.

### Ingest pipelines

An optional pipeline name on the indexing operations (single and bulk), so
documents are routed through a named ingest pipeline as they are written.

### Index lifecycle helpers

First-class methods for the common index-management operations currently reached
only through `request`:

- test whether an index exists;
- refresh an index to make recent writes searchable;
- delete an index;
- resolve an index pattern to its most recently created concrete index.

### Index template management

Get and set index templates.

### ISM management

Get and set index state management (ISM) policies.
