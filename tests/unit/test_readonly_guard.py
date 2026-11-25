"""Unit tests for ReadOnlySafetyGuard (Task 45).

Verifies strict enforcement of Phase 1 harmless invariants against mutating tool
names and destructive payload patterns.
"""

from __future__ import annotations

import pytest

from verity.scanner.readonly_guard import (
    MutationProhibitedError,
    ReadOnlySafetyGuard,
    SafetyVerdict,
)


def test_guard_blocks_destructive_tool_names():
    """Verify tool names containing forbidden mutating verbs are blocked."""
    forbidden_names = [
        "delete_user",
        "drop_table",
        "truncate_orders",
        "update_customer",
        "alter_database",
        "write_file",
        "modify_record",
        "destroy_session",
        "kill_process",
        "purge_cache",
        "wipe_disk",
        "charge_card",
        "create_customer",
    ]

    for name in forbidden_names:
        res = ReadOnlySafetyGuard.check_call(name, {})
        assert res.verdict == SafetyVerdict.BLOCKED
        assert res.is_mutating is True
        assert res.matched_keyword is not None

        with pytest.raises(MutationProhibitedError) as exc_info:
            ReadOnlySafetyGuard.enforce(name, {})
        assert "MUTATION_PROHIBITED_IN_PHASE_1" in str(exc_info.value)


def test_guard_blocks_destructive_sql_in_arguments():
    """Verify destructive SQL statements in query arguments are blocked even with safe tool names."""
    malicious_payloads = [
        "DROP TABLE users;",
        "SELECT * FROM users; DROP TABLE orders;",
        "DELETE FROM customers WHERE id = 1",
        "TRUNCATE TABLE accounts",
        "UPDATE users SET is_admin = 1",
        "INSERT INTO users (name) VALUES ('evil')",
        "; DELETE FROM tokens",
    ]

    for payload in malicious_payloads:
        res = ReadOnlySafetyGuard.check_call("execute_query", {"query": payload})
        assert res.verdict == SafetyVerdict.BLOCKED
        assert res.is_mutating is True

        with pytest.raises(MutationProhibitedError):
            ReadOnlySafetyGuard.enforce("execute_query", {"query": payload})


def test_guard_blocks_destructive_shell_in_arguments():
    """Verify dangerous shell commands in arguments are blocked."""
    dangerous_commands = [
        "rm -rf /tmp/data",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sdb",
        "echo bad > /etc/passwd",
        "kill -9 1234",
    ]

    for cmd in dangerous_commands:
        res = ReadOnlySafetyGuard.check_call("run_command", {"command": cmd})
        assert res.verdict == SafetyVerdict.BLOCKED
        assert res.is_mutating is True


def test_guard_scans_nested_structures():
    """Verify guard inspects deeply nested dictionaries and arrays."""
    nested_args = {
        "options": {
            "filters": [
                {"field": "status", "val": "active"},
                {"field": "raw", "val": "DROP TABLE transactions"},
            ]
        }
    }
    res = ReadOnlySafetyGuard.check_call("search_records", nested_args)
    assert res.verdict == SafetyVerdict.BLOCKED
    assert res.is_mutating is True


def test_guard_allows_safe_read_operations():
    """Verify safe read-only operations pass with SafetyVerdict.PERMITTED."""
    safe_calls = [
        ("read_file", {"path": "/var/log/app.log"}),
        ("list_directory", {"path": "/home/user"}),
        ("execute_query", {"query": "SELECT id, name FROM customers WHERE active = 1"}),
        ("get_user_profile", {"user_id": "usr_991"}),
        ("browse_url", {"url": "https://service.internal/health"}),
        ("calculate_discount", {"formula": "total * 0.1"}),
        ("describe_schema", {"table": "orders"}),
    ]

    for tool_name, args in safe_calls:
        res = ReadOnlySafetyGuard.check_call(tool_name, args)
        assert res.verdict == SafetyVerdict.PERMITTED
        assert res.is_mutating is False

        # enforce should not raise
        enforced = ReadOnlySafetyGuard.enforce(tool_name, args)
        assert enforced.verdict == SafetyVerdict.PERMITTED


def test_guard_bypasses_check_outside_phase_1():
    """Verify mutating operations are permitted when phase is explicitly not PHASE_1."""
    res = ReadOnlySafetyGuard.check_call("delete_user", {"id": "1"}, phase="PHASE_2_MUTATION")
    assert res.verdict == SafetyVerdict.PERMITTED
    assert res.is_mutating is False


def test_destructive_verbs_blocked():
    """Verify M44 extended destructive verbs are blocked in Phase 1."""
    destructive_tools = [
        "run_sql",
        "execute_sql",
        "upsert_customer",
        "post_webhook",
        "put_record",
        "patch_item",
        "chmod_file",
        "kill_process",
        "http_put_item",
        "api_post_event",
        "bulk_patch_users",
    ]
    for tool_name in destructive_tools:
        res = ReadOnlySafetyGuard.check_call(tool_name, {})
        assert res.verdict == SafetyVerdict.BLOCKED, f"Expected {tool_name} to be BLOCKED"
        assert res.is_mutating is True


def test_readonly_tool_allowed():
    """Verify read-only tools and non-matching substrings like input_ remain permitted."""
    safe_tools = [
        ("list_customers", {"limit": 10}),
        ("get_input_schema", {}),
        ("describe_output_format", {}),
    ]
    for tool_name, args in safe_tools:
        res = ReadOnlySafetyGuard.check_call(tool_name, args)
        assert res.verdict == SafetyVerdict.PERMITTED, f"Expected {tool_name} to be PERMITTED"
        assert res.is_mutating is False
