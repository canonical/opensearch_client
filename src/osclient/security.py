# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage Security plugin accounts: roles, internal users and role mappings.

SKELETON: every function below is a declaration with no behaviour yet.

This module calls the Security REST API through
:meth:`~osclient.client.OpensearchClient.request`; the client has no methods of its
own for it, and the API paths live here. Two parts:

- The classes model the request bodies of that API. Their field names are the JSON
  keys (a role, user or mapping is an object keyed by its name). ``to_dict``
  builds a request body. Responses are not parsed into these classes: the ``get_*``
  and ``list_*`` functions return the response JSON.
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
  appear in responses and are never sent; the classes do not model them.
- Secrets are never printed or logged. Output built from a raw API response goes
  through :func:`redact_secrets` first, and a request body is never logged: logs
  may be shipped to the cluster, and a logged password would then be stored in an
  index.

The Security API is served by the cluster's REST port (9200 by default), so
OPENSEARCH_URL should point there. Whether it can also be reached through a
Dashboards console proxy (the OPENSEARCH_DASHBOARD_URL route) has not been
verified.
"""

from dataclasses import dataclass, field
from typing import Any

from osclient.client import OpensearchClient
from osclient.result import OpensearchResult


@dataclass(frozen=True)
class IndexPermission:
    """One entry of a role's ``index_permissions``.

    Example:
        The JSON object (``dls`` is only written when set)::

            {
              "index_patterns": ["example-index-*"],
              "dls": "<a query, as a JSON string>",
              "fls": ["~example_field"],
              "masked_fields": ["example_field"],
              "allowed_actions": ["read"]
            }

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
            The entry as lists and strings. ``dls`` is left out when empty.
        """
        body: dict[str, Any] = {"index_patterns": list(self.index_patterns)}
        if self.dls:
            body["dls"] = self.dls
        body["fls"] = list(self.fls)
        body["masked_fields"] = list(self.masked_fields)
        body["allowed_actions"] = list(self.allowed_actions)
        return body


@dataclass(frozen=True)
class TenantPermission:
    """One entry of a role's ``tenant_permissions`` (Dashboards tenants).

    Example:
        The JSON object::

            {
              "tenant_patterns": ["human_resources"],
              "allowed_actions": ["kibana_all_read"]
            }

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
        return {
            "tenant_patterns": list(self.tenant_patterns),
            "allowed_actions": list(self.allowed_actions),
        }


@dataclass(frozen=True)
class Role:
    """A Security plugin role: a named set of cluster, index and tenant permissions.

    Example:
        A role as the API returns it, an object keyed by the role name (the request
        body is the inner object)::

            {
              "example-role": {
                "cluster_permissions": ["cluster_monitor"],
                "index_permissions": [
                  {
                    "index_patterns": ["example-index-*"],
                    "fls": [],
                    "masked_fields": [],
                    "allowed_actions": ["read"]
                  }
                ],
                "tenant_permissions": [
                  {
                    "tenant_patterns": ["example-tenant"],
                    "allowed_actions": ["kibana_all_read"]
                  }
                ],
                "description": "Example role"
              }
            }

        A response may also carry ``reserved``, ``hidden`` and ``static``, which
        are set by the server and not modelled here.

    Attributes:
        name: the role name. In JSON it is the key, not a field.
        cluster_permissions: cluster-level actions or action groups.
        index_permissions: index-level permissions.
        tenant_permissions: Dashboards tenant permissions.
        description: free text.
    """

    name: str
    cluster_permissions: tuple[str, ...] = ()
    index_permissions: tuple[IndexPermission, ...] = ()
    tenant_permissions: tuple[TenantPermission, ...] = ()
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Build the request body for the roles API.

        Returns:
            The three permission lists (empty ones included), and the description
            when set. The name is left out: it goes in the URL.
        """
        body: dict[str, Any] = {
            "cluster_permissions": list(self.cluster_permissions),
            "index_permissions": [entry.to_dict() for entry in self.index_permissions],
            "tenant_permissions": [
                entry.to_dict() for entry in self.tenant_permissions
            ],
        }
        if self.description:
            body["description"] = self.description
        return body


@dataclass(frozen=True)
class RoleMapping:
    """Which users, backend roles and hosts receive a role.

    Example:
        A mapping as the API returns it, an object keyed by the role name (the
        request body is the inner object)::

            {
              "example-role": {
                "users": ["example-user"],
                "backend_roles": ["example-backend-role"],
                "and_backend_roles": [],
                "hosts": ["example-host"]
              }
            }

        A response may also carry ``description``, ``reserved``, ``hidden`` and
        ``static``. They are not modelled: the API may not accept a description on
        a mapping (unverified), and the rest are set by the server.

    Attributes:
        role: the role being mapped. In JSON it is the key, not a field.
        users: user names; wildcards allowed.
        backend_roles: a user with any of these receives the role.
        and_backend_roles: a user must have all of these to receive the role.
        hosts: host names or addresses; wildcards allowed.
    """

    role: str
    users: tuple[str, ...] = ()
    backend_roles: tuple[str, ...] = ()
    and_backend_roles: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Build the request body for the role mappings API.

        Returns:
            ``users``, ``backend_roles`` and ``hosts`` (empty ones included), and
            ``and_backend_roles`` when set. The role name is left out: it goes in
            the URL.
        """
        body: dict[str, Any] = {
            "users": list(self.users),
            "backend_roles": list(self.backend_roles),
            "hosts": list(self.hosts),
        }
        if self.and_backend_roles:
            body["and_backend_roles"] = list(self.and_backend_roles)
        return body


@dataclass(frozen=True)
class User:
    """An internal user of the Security plugin.

    Example:
        A user as the API returns it, an object keyed by the user name (the request
        body is the inner object). The request body also carries a ``password``,
        which the API never returns::

            {
              "example-user": {
                "backend_roles": ["example-backend-role"],
                "attributes": {"example-key": "example-value"},
                "opendistro_security_roles": ["example-role"],
                "description": "Example user"
              }
            }

        A response may also carry ``hash``, ``reserved``, ``hidden`` and
        ``static``, which are set by the server and not modelled here.

    Attributes:
        name: the user name. In JSON it is the key, not a field.
        password: the plain-text password. Write-only: it is accepted when a user
            is created, never returned by the API, and hidden from ``repr``.
        backend_roles: backend roles used by role mappings.
        opendistro_security_roles: roles mapped directly to the user; each must
            already exist.
        attributes: custom name-value pairs.
        description: free text.
    """

    name: str
    password: str = field(default="", repr=False)
    backend_roles: tuple[str, ...] = ()
    opendistro_security_roles: tuple[str, ...] = ()
    attributes: dict[str, str] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Build the request body for the internal users API.

        Never print or log the result: it holds the password.

        Returns:
            ``backend_roles``, ``attributes`` and ``opendistro_security_roles``
            (empty ones included), the description when set, and the password when
            set. The name is left out: it goes in the URL.
        """
        body: dict[str, Any] = {
            "backend_roles": list(self.backend_roles),
            "attributes": dict(self.attributes),
            "opendistro_security_roles": list(self.opendistro_security_roles),
        }
        if self.description:
            body["description"] = self.description
        if self.password:
            body["password"] = self.password
        return body


_ROLES_PATH = "_plugins/_security/api/roles"
_USERS_PATH = "_plugins/_security/api/internalusers"
_ROLE_MAPPINGS_PATH = "_plugins/_security/api/rolesmapping"

REDACTED = "<redacted>"

# Keys whose values must never be printed or logged, wherever they appear in a
# response:
# - password: write-only; the API never returns it, but a request body carries it.
# - hash: the stored password hash. The API normally returns it empty, but a
#   response could contain one, and a hash can be attacked offline.
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


def get_role(client: OpensearchClient, name: str) -> OpensearchResult[dict[str, Any]]:
    """Get one role.

    Args:
        client: the client used to reach the cluster.
        name: the role name.

    Returns:
        The response JSON, an object keyed by the role name, as the API returns it;
        or a failure (status 404 when it does not exist).
    """
    raise NotImplementedError


def get_user(client: OpensearchClient, name: str) -> OpensearchResult[dict[str, Any]]:
    """Get one internal user.

    Args:
        client: the client used to reach the cluster.
        name: the user name.

    Returns:
        The response JSON, an object keyed by the user name, as the API returns it;
        or a failure (status 404 when it does not exist). It is not redacted: pass
        it through :func:`redact_secrets` before printing.
    """
    raise NotImplementedError


def get_role_mapping(
    client: OpensearchClient, role: str
) -> OpensearchResult[dict[str, Any]]:
    """Get the mapping of one role.

    Args:
        client: the client used to reach the cluster.
        role: the role name.

    Returns:
        The response JSON, an object keyed by the role name, as the API returns it;
        or a failure (status 404 when the role has none).
    """
    raise NotImplementedError


def list_roles(client: OpensearchClient) -> OpensearchResult[dict[str, Any]]:
    """List every role the API returns.

    Args:
        client: the client used to reach the cluster.

    Returns:
        The response JSON, an object keyed by role name, as the API returns it.
    """
    raise NotImplementedError


def list_users(client: OpensearchClient) -> OpensearchResult[dict[str, Any]]:
    """List every internal user the API returns.

    Args:
        client: the client used to reach the cluster.

    Returns:
        The response JSON, an object keyed by user name, as the API returns it. It
        is not redacted: pass it through :func:`redact_secrets` before printing.
    """
    raise NotImplementedError


def list_role_mappings(client: OpensearchClient) -> OpensearchResult[dict[str, Any]]:
    """List every role mapping the API returns.

    Args:
        client: the client used to reach the cluster.

    Returns:
        The response JSON, an object keyed by role name, as the API returns it.
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
