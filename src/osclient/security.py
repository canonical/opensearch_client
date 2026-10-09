# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage Security plugin accounts: roles, internal users and role mappings.

SKELETON: every function and method below is a declaration with no behaviour yet.

This module calls the Security REST API through
:meth:`~osclient.client.OpensearchClient.request`; the client has no methods of its
own for it, and the API paths live here. Two parts:

- The classes model the JSON of that API. Their field names are the JSON keys, and
  the JSON shape is the one ``export_indexer_config.py`` in secops-tools writes (a
  role, user or mapping is an object keyed by its name). ``to_dict`` builds a
  request body; ``from_dict`` parses a response.
- The functions work with those classes and return
  :class:`~osclient.result.OpensearchResult`; an expected failure is a value, not
  an exception.

Rules the functions follow:

- Creation is create-only. A role, user or mapping that already exists is never
  overwritten: ``create_*`` returns a failure instead. Replacing means deleting
  and creating again.
- A password is write-only. It is accepted when a user is created, is never
  returned by the API, and is kept out of ``repr`` and ``to_dict`` unless set.
  Nothing here generates a password.
- Server-set fields (``reserved``, ``hidden``, ``static``, and a user's ``hash``)
  are read from responses and never sent.
- Secrets are never printed or logged. Output built from a raw API response goes
  through :func:`redact_secrets` first, and a request body is never logged: this
  repository's own log handler indexes what the collectors log, so a logged
  password would end up in the SIEM index.

The Security API is served by the indexer's REST port (9200 by default), the
endpoint the secops-tools scripts use, so OPENSEARCH_URL should point there.
Whether it can also be reached through a Dashboards console proxy (the
OPENSEARCH_DASHBOARD_URL route) has not been verified.
"""

from dataclasses import dataclass, field
from typing import Any

from osclient.client import OpensearchClient
from osclient.result import OpensearchResult


@dataclass(frozen=True)
class IndexPermission:
    """One entry of a role's ``index_permissions``.

    Attributes:
        index_patterns: the indexes the permissions apply to; wildcards allowed.
        allowed_actions: individual actions or action groups, e.g. ``index``.
        dls: a document-level security query, or empty for none.
        fls: field-level security; a ``~`` prefix excludes a field. Empty for none.
        masked_fields: fields to anonymize. Empty for none.
    """

    index_patterns: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    dls: str = ""
    fls: tuple[str, ...] = ()
    masked_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Build this entry as the API's JSON object.

        Returns:
            The entry with every field, as lists and strings.
        """
        raise NotImplementedError

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IndexPermission":
        """Parse an ``index_permissions`` entry from the API's JSON.

        Args:
            data: the entry; the optional keys may be missing.

        Returns:
            The parsed entry.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class TenantPermission:
    """One entry of a role's ``tenant_permissions`` (Dashboards tenants).

    Attributes:
        tenant_patterns: the tenants the permissions apply to; wildcards allowed.
        allowed_actions: ``kibana_all_read`` and/or ``kibana_all_write``.
    """

    tenant_patterns: tuple[str, ...]
    allowed_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Build this entry as the API's JSON object.

        Returns:
            The entry, as lists.
        """
        raise NotImplementedError

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TenantPermission":
        """Parse a ``tenant_permissions`` entry from the API's JSON.

        Args:
            data: the entry.

        Returns:
            The parsed entry.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class Role:
    """A Security plugin role: a named set of cluster, index and tenant permissions.

    Attributes:
        name: the role name. In JSON it is the key, not a field.
        cluster_permissions: cluster-level actions or action groups.
        index_permissions: index-level permissions.
        tenant_permissions: Dashboards tenant permissions.
        description: free text.
        reserved: set by the server; a reserved role cannot be changed.
        hidden: set by the server; a hidden role is not listed.
        static: set by the server for built-in roles.
    """

    name: str
    cluster_permissions: tuple[str, ...] = ()
    index_permissions: tuple[IndexPermission, ...] = ()
    tenant_permissions: tuple[TenantPermission, ...] = ()
    description: str = ""
    reserved: bool = False
    hidden: bool = False
    static: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Build the request body for the roles API.

        Returns:
            The permissions and description. The name and the server-set flags are
            left out.
        """
        raise NotImplementedError

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> "Role":
        """Parse a role from the API's JSON.

        Args:
            name: the role name (the key of the object in the response).
            data: the role object.

        Returns:
            The parsed role, with the server-set flags filled in.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class RoleMapping:
    """Which users, backend roles and hosts receive a role.

    Attributes:
        role: the role being mapped. In JSON it is the key, not a field.
        users: user names; wildcards allowed.
        backend_roles: a user with any of these receives the role.
        and_backend_roles: a user must have all of these to receive the role.
        hosts: host names or addresses; wildcards allowed.
        description: free text.
        reserved: set by the server; a reserved mapping cannot be changed.
        hidden: set by the server.
        static: set by the server for built-in mappings.
    """

    role: str
    users: tuple[str, ...] = ()
    backend_roles: tuple[str, ...] = ()
    and_backend_roles: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    description: str = ""
    reserved: bool = False
    hidden: bool = False
    static: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Build the request body for the role mappings API.

        Returns:
            The users, backend roles, and hosts. The role name and the server-set
            flags are left out.
        """
        raise NotImplementedError

    @classmethod
    def from_dict(cls, role: str, data: dict[str, Any]) -> "RoleMapping":
        """Parse a role mapping from the API's JSON.

        Args:
            role: the role name (the key of the object in the response).
            data: the mapping object.

        Returns:
            The parsed mapping.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class User:
    """An internal user of the Security plugin.

    Attributes:
        name: the user name. In JSON it is the key, not a field.
        password: the plain-text password. Write-only: it is accepted when a user
            is created, never returned by the API, and hidden from ``repr``.
        backend_roles: backend roles used by role mappings.
        opendistro_security_roles: roles mapped directly to the user; each must
            already exist.
        attributes: custom name-value pairs.
        description: free text.
        reserved: set by the server; a reserved user cannot be changed.
        hidden: set by the server.
        static: set by the server for built-in users.
    """

    name: str
    password: str = field(default="", repr=False)
    backend_roles: tuple[str, ...] = ()
    opendistro_security_roles: tuple[str, ...] = ()
    attributes: dict[str, str] = field(default_factory=dict)
    description: str = ""
    reserved: bool = False
    hidden: bool = False
    static: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Build the request body for the internal users API.

        Returns:
            The roles, attributes and description, plus the password when one is
            set. The name and the server-set flags are left out.
        """
        raise NotImplementedError

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> "User":
        """Parse a user from the API's JSON.

        Args:
            name: the user name (the key of the object in the response).
            data: the user object. Its password hash, if present, is dropped.

        Returns:
            The parsed user, without a password.
        """
        raise NotImplementedError


_ROLES_PATH = "_plugins/_security/api/roles"
_USERS_PATH = "_plugins/_security/api/internalusers"
_ROLE_MAPPINGS_PATH = "_plugins/_security/api/rolesmapping"

REDACTED = "<redacted>"

# Keys whose values must never be printed or logged, wherever they appear in a
# response:
# - password: write-only; the API never returns it, but a request body carries it.
# - hash: the stored password hash. The API normally returns it empty, but the
#   secops-tools scripts strip it on import, which suggests exports can contain it,
#   and a hash can be attacked offline.
# Not redacted, but worth a decision: a user's ``attributes`` are free-form
# name-value pairs and could hold anything.
SENSITIVE_KEYS = frozenset({"password", "hash"})


# -- output -------------------------------------------------------------------


def redact_secrets(data: Any) -> Any:
    """Return a copy of an API response with every secret value replaced.

    Every value under a key in ``SENSITIVE_KEYS`` becomes ``REDACTED``, at any
    depth in nested dicts and lists. The input is not changed.

    Args:
        data: a decoded API response: a dict, a list, or a scalar.

    Returns:
        The same structure with the sensitive values replaced.
    """
    raise NotImplementedError


# -- build ------------------------------------------------------------------


def build_logging_writer_role(name: str, index_patterns: tuple[str, ...]) -> Role:
    """Build the least-privileged role for an account that only ships logs.

    The role lets an account check that its index exists and write documents to
    it (cluster ``indices:data/write/bulk``; on ``index_patterns``,
    ``indices:admin/get`` and the ``index`` action group), and nothing else. The
    exact permission list still has to be verified against a real cluster.

    Args:
        name: the role name.
        index_patterns: the indexes the account may write to.

    Returns:
        The role.
    """
    raise NotImplementedError


# -- existence ----------------------------------------------------------------


def role_exists(client: OpensearchClient, name: str) -> OpensearchResult[bool]:
    """Report whether a role exists.

    Args:
        client: the client used to reach the cluster.
        name: the role name.

    Returns:
        True or False; a failure other than "not found" (such as an
        authorization error) is returned as a failure, not as False.
    """
    raise NotImplementedError


def user_exists(client: OpensearchClient, name: str) -> OpensearchResult[bool]:
    """Report whether an internal user exists.

    Args:
        client: the client used to reach the cluster.
        name: the user name.

    Returns:
        True or False; any other failure is returned as a failure.
    """
    raise NotImplementedError


def role_mapping_exists(client: OpensearchClient, role: str) -> OpensearchResult[bool]:
    """Report whether a role has a mapping.

    Args:
        client: the client used to reach the cluster.
        role: the role name.

    Returns:
        True or False; any other failure is returned as a failure.
    """
    raise NotImplementedError


def check_service_account(
    client: OpensearchClient, user: str, role: str, index: str
) -> OpensearchResult[dict[str, bool]]:
    """Report which parts of a service account already exist.

    Args:
        client: the client used to reach the cluster.
        user: the user name.
        role: the role name; its mapping is checked too.
        index: the index the account writes to.

    Returns:
        A mapping with the keys ``user``, ``role``, ``role_mapping`` and
        ``index``, each True or False.
    """
    raise NotImplementedError


# -- read ---------------------------------------------------------------------


def get_role(client: OpensearchClient, name: str) -> OpensearchResult[Role]:
    """Get one role.

    Args:
        client: the client used to reach the cluster.
        name: the role name.

    Returns:
        The role, or a failure (status 404 when it does not exist).
    """
    raise NotImplementedError


def get_user(client: OpensearchClient, name: str) -> OpensearchResult[User]:
    """Get one internal user, without a password.

    Args:
        client: the client used to reach the cluster.
        name: the user name.

    Returns:
        The user, or a failure (status 404 when it does not exist).
    """
    raise NotImplementedError


def get_role_mapping(
    client: OpensearchClient, role: str
) -> OpensearchResult[RoleMapping]:
    """Get the mapping of one role.

    Args:
        client: the client used to reach the cluster.
        role: the role name.

    Returns:
        The mapping, or a failure (status 404 when the role has none).
    """
    raise NotImplementedError


def list_roles(client: OpensearchClient) -> OpensearchResult[list[Role]]:
    """List every role the API returns, sorted by name.

    Args:
        client: the client used to reach the cluster.

    Returns:
        The roles.
    """
    raise NotImplementedError


def list_users(client: OpensearchClient) -> OpensearchResult[list[User]]:
    """List every internal user the API returns, sorted by name, without passwords.

    Args:
        client: the client used to reach the cluster.

    Returns:
        The users.
    """
    raise NotImplementedError


def list_role_mappings(
    client: OpensearchClient,
) -> OpensearchResult[list[RoleMapping]]:
    """List every role mapping the API returns, sorted by role name.

    Args:
        client: the client used to reach the cluster.

    Returns:
        The mappings.
    """
    raise NotImplementedError


# -- create (create-only) -----------------------------------------------------


def create_role(
    client: OpensearchClient, role: Role
) -> OpensearchResult[dict[str, Any]]:
    """Create a role; never overwrite one.

    Args:
        client: the client used to reach the cluster.
        role: the role to create.

    Returns:
        The API's acknowledgement, or a failure. A role that already exists is a
        failure (status 409) and is left unchanged.
    """
    raise NotImplementedError


def create_user(
    client: OpensearchClient, user: User
) -> OpensearchResult[dict[str, Any]]:
    """Create an internal user; never overwrite one.

    Args:
        client: the client used to reach the cluster.
        user: the user to create, with its password set.

    Returns:
        The API's acknowledgement, or a failure. A user that already exists is a
        failure (status 409) and keeps its password.
    """
    raise NotImplementedError


def create_role_mapping(
    client: OpensearchClient, mapping: RoleMapping
) -> OpensearchResult[dict[str, Any]]:
    """Create a role mapping; never replace one.

    Args:
        client: the client used to reach the cluster.
        mapping: the mapping to create.

    Returns:
        The API's acknowledgement, or a failure. A role that already has a mapping
        is a failure (status 409) and keeps it.
    """
    raise NotImplementedError


def create_service_account(
    client: OpensearchClient, user: User, role: Role
) -> OpensearchResult[dict[str, Any]]:
    """Create a role, a user, and the mapping that gives the user the role.

    The steps run in that order, so access is granted last and a failure part-way
    leaves no working account. Each step is create-only.

    Args:
        client: the client used to reach the cluster.
        user: the account's user, with its password set.
        role: the account's role.

    Returns:
        A summary naming the user, role and mapping created. On a failure, a failure
        whose data lists the steps that had already succeeded (nothing is undone).
    """
    raise NotImplementedError


# -- delete -------------------------------------------------------------------


def delete_role(
    client: OpensearchClient, name: str
) -> OpensearchResult[dict[str, Any]]:
    """Delete a role.

    Args:
        client: the client used to reach the cluster.
        name: the role name.

    Returns:
        The API's acknowledgement, or a failure.
    """
    raise NotImplementedError


def delete_user(
    client: OpensearchClient, name: str
) -> OpensearchResult[dict[str, Any]]:
    """Delete an internal user.

    Args:
        client: the client used to reach the cluster.
        name: the user name.

    Returns:
        The API's acknowledgement, or a failure.
    """
    raise NotImplementedError


def delete_role_mapping(
    client: OpensearchClient, role: str
) -> OpensearchResult[dict[str, Any]]:
    """Delete the mapping of a role.

    Args:
        client: the client used to reach the cluster.
        role: the role name.

    Returns:
        The API's acknowledgement, or a failure.
    """
    raise NotImplementedError
