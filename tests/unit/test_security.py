# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the request-body classes in osclient.security."""

from helpers import RecordingTransport, ScriptedTransport

from osclient import security
from osclient.client import OpensearchClient
from osclient.result import Failure, Success
from osclient.security import (
    IndexPermission,
    Role,
    RoleMapping,
    TenantPermission,
    User,
)


def test_a_minimal_role_mapping_and_user_are_rebuilt_exactly() -> None:
    role = Role(
        name="example-role",
        cluster_permissions=("cluster_monitor",),
        index_permissions=(
            IndexPermission(
                index_patterns=("example-index-*",), allowed_actions=("read",)
            ),
        ),
    )
    assert role.to_dict() == {
        "cluster_permissions": ["cluster_monitor"],
        "index_permissions": [
            {
                "index_patterns": ["example-index-*"],
                "fls": [],
                "masked_fields": [],
                "allowed_actions": ["read"],
            }
        ],
        "tenant_permissions": [],
    }

    mapping = RoleMapping(role="example-role", users=("example-user",))
    assert mapping.to_dict() == {
        "users": ["example-user"],
        "backend_roles": [],
        "hosts": [],
    }

    user = User(name="example-user", description="Example user")
    assert user.to_dict() == {
        "backend_roles": [],
        "attributes": {},
        "opendistro_security_roles": [],
        "description": "Example user",
    }


def test_a_role_with_every_field_is_rebuilt_exactly() -> None:
    role = Role(
        name="example-role",
        cluster_permissions=("cluster_monitor",),
        index_permissions=(
            IndexPermission(
                index_patterns=("example-index-*",),
                allowed_actions=("read",),
                dls='{"term": {"owner": "example"}}',
                fls=("~example_field",),
                masked_fields=("other_field",),
            ),
        ),
        tenant_permissions=(
            TenantPermission(("example-tenant",), ("kibana_all_read",)),
        ),
        description="Example role",
    )

    assert role.to_dict() == {
        "cluster_permissions": ["cluster_monitor"],
        "index_permissions": [
            {
                "index_patterns": ["example-index-*"],
                "dls": '{"term": {"owner": "example"}}',
                "fls": ["~example_field"],
                "masked_fields": ["other_field"],
                "allowed_actions": ["read"],
            }
        ],
        "tenant_permissions": [
            {
                "tenant_patterns": ["example-tenant"],
                "allowed_actions": ["kibana_all_read"],
            }
        ],
        "description": "Example role",
    }


def test_a_password_is_write_only() -> None:
    user = User(name="example-user", password="a-secret-value")

    assert user.to_dict()["password"] == "a-secret-value"
    assert "password" not in User(name="example-user").to_dict()
    assert "a-secret-value" not in repr(user)


def test_and_backend_roles_are_sent_only_when_set() -> None:
    mapping = RoleMapping(role="r", users=("u",), and_backend_roles=("a", "b"))

    assert mapping.to_dict()["and_backend_roles"] == ["a", "b"]
    assert "and_backend_roles" not in RoleMapping(role="r", users=("u",)).to_dict()


def test_get_and_list_send_one_get_and_return_the_response_unchanged() -> None:
    response = {"example": {"description": "as the API returned it"}}
    transport = RecordingTransport(response)
    client = OpensearchClient(transport)

    fetched = [
        security.get_role(client, "example-role"),
        security.get_user(client, "example-user"),
        security.get_role_mapping(client, "example-role"),
        security.list_roles(client),
        security.list_users(client),
        security.list_role_mappings(client),
    ]

    for result in fetched:
        assert result
        assert result.data == response
    assert transport.calls == [
        ("GET", "_plugins/_security/api/roles/example-role", None),
        ("GET", "_plugins/_security/api/internalusers/example-user", None),
        ("GET", "_plugins/_security/api/rolesmapping/example-role", None),
        ("GET", "_plugins/_security/api/roles", None),
        ("GET", "_plugins/_security/api/internalusers", None),
        ("GET", "_plugins/_security/api/rolesmapping", None),
    ]


def test_a_name_is_encoded_so_it_cannot_change_the_endpoint() -> None:
    transport = RecordingTransport()

    security.get_role(OpensearchClient(transport), "a/b?c d")

    assert transport.calls == [
        ("GET", "_plugins/_security/api/roles/a%2Fb%3Fc%20d", None)
    ]


def test_existence_checks_report_true_false_or_the_failure() -> None:
    checks = (
        (security.role_exists, "_plugins/_security/api/roles/example"),
        (security.user_exists, "_plugins/_security/api/internalusers/example"),
        (security.role_mapping_exists, "_plugins/_security/api/rolesmapping/example"),
    )
    forbidden = Failure("403 from GET", status=403)

    for exists, path in checks:
        found = ScriptedTransport([Success({"example": {}})])
        assert exists(OpensearchClient(found), "example") == Success(True)
        assert found.calls == [("GET", path, None)]

        missing = ScriptedTransport([Failure("404 from GET", status=404)])
        assert exists(OpensearchClient(missing), "example") == Success(False)

        denied = ScriptedTransport([forbidden])
        assert exists(OpensearchClient(denied), "example") == forbidden
