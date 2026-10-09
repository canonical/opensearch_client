# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the request-body classes in osclient.security."""

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
