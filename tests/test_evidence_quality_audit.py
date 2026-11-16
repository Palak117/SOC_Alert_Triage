"""
Tests for Evidence Quality Audit Validation in Forensic Alert Investigation.
Verifies missing-value detection, IPv4/IPv6 validation, and legitimate evidence preservation.
"""

import pytest
import numpy as np
import pandas as pd
from dashboard.views.alert_investigation import validate_evidence_field


def test_missing_value_none():
    """Verify None is classified as Missing Evidence Gap across all fields."""
    for field in ["Source IP", "Destination IP", "User Identity", "Action Taken", "Disposition", "Message Payload"]:
        assert validate_evidence_field(field, None) is False


def test_missing_value_nan():
    """Verify NaN / float('nan') is classified as Missing Evidence Gap."""
    for field in ["Source IP", "Destination IP", "User Identity", "Action Taken", "Disposition", "Message Payload"]:
        assert validate_evidence_field(field, float("nan")) is False
        assert validate_evidence_field(field, np.nan) is False


def test_missing_value_null_string():
    """Verify 'null', 'NULL', 'Null' strings are classified as Missing Evidence Gap."""
    for field in ["Source IP", "Destination IP", "User Identity", "Action Taken", "Disposition", "Message Payload"]:
        assert validate_evidence_field(field, "null") is False
        assert validate_evidence_field(field, "NULL") is False
        assert validate_evidence_field(field, "Null") is False


def test_missing_value_na_string():
    """Verify 'N/A', 'n/a', 'NA', 'na' strings are classified as Missing Evidence Gap."""
    for field in ["Source IP", "Destination IP", "User Identity", "Action Taken", "Disposition", "Message Payload"]:
        assert validate_evidence_field(field, "N/A") is False
        assert validate_evidence_field(field, "n/a") is False
        assert validate_evidence_field(field, "NA") is False
        assert validate_evidence_field(field, "na") is False


def test_missing_value_empty_string():
    """Verify empty string '' is classified as Missing Evidence Gap."""
    for field in ["Source IP", "Destination IP", "User Identity", "Action Taken", "Disposition", "Message Payload"]:
        assert validate_evidence_field(field, "") is False


def test_missing_value_whitespace():
    """Verify whitespace-only strings are classified as Missing Evidence Gap."""
    for field in ["Source IP", "Destination IP", "User Identity", "Action Taken", "Disposition", "Message Payload"]:
        assert validate_evidence_field(field, "   ") is False
        assert validate_evidence_field(field, "\t \n") is False


def test_missing_value_brackets():
    """Verify '[]' and '{}' empty structure strings are classified as Missing Evidence Gap."""
    for field in ["Source IP", "Destination IP", "User Identity", "Action Taken", "Disposition", "Message Payload"]:
        assert validate_evidence_field(field, "[]") is False
        assert validate_evidence_field(field, "{}") is False


def test_valid_ipv4_addresses():
    """Verify valid IPv4 addresses are correctly marked as Verified."""
    valid_ips = ["192.168.1.1", "10.0.0.1", "100.64.26.41", "8.8.8.8", "172.16.254.1"]
    for ip in valid_ips:
        assert validate_evidence_field("Source IP", ip) is True
        assert validate_evidence_field("Destination IP", ip) is True


def test_valid_ipv6_addresses():
    """Verify valid IPv6 addresses are correctly marked as Verified."""
    valid_ipv6s = [
        "::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1ff:fe23:4567:890a",
        "2607:f8b0:4005:805::200e"
    ]
    for ip in valid_ipv6s:
        assert validate_evidence_field("Source IP", ip) is True
        assert validate_evidence_field("Destination IP", ip) is True


def test_invalid_ipv4_addresses():
    """Verify invalid/out-of-range IPv4 addresses are rejected as Missing Evidence Gap."""
    invalid_ips = ["999.999.999.999", "256.1.1.1", "192.168.1", "192.168.1.1.1", "10.0.0.0/24"]
    for ip in invalid_ips:
        assert validate_evidence_field("Source IP", ip) is False
        assert validate_evidence_field("Destination IP", ip) is False


def test_invalid_ipv6_addresses():
    """Verify malformed IPv6 addresses are rejected as Missing Evidence Gap."""
    invalid_ipv6s = ["2001:xyz::1", "1200::AB00:1234::2552:7777:1313", "fe80:::1"]
    for ip in invalid_ipv6s:
        assert validate_evidence_field("Source IP", ip) is False
        assert validate_evidence_field("Destination IP", ip) is False


def test_arbitrary_invalid_ip_text():
    """Verify arbitrary strings like 'invalid_ip' or domain names are rejected for IP fields."""
    arbitrary_texts = ["invalid_ip", "localhost", "trustedadvisor.amazonaws.com", "not_an_ip", "12345"]
    for text in arbitrary_texts:
        assert validate_evidence_field("Source IP", text) is False
        assert validate_evidence_field("Destination IP", text) is False


def test_legitimate_populated_non_ip_fields():
    """Verify legitimate text values for non-IP fields are correctly preserved as Verified."""
    # User Identity
    assert validate_evidence_field("User Identity", "admin") is True
    assert validate_evidence_field("User Identity", "USER-0728") is True
    assert validate_evidence_field("User Identity", "svc_backup") is True

    # Action Taken
    assert validate_evidence_field("Action Taken", "blocked") is True
    assert validate_evidence_field("Action Taken", "Logon") is True
    assert validate_evidence_field("Action Taken", "Process Creation") is True

    # Disposition
    assert validate_evidence_field("Disposition", "detected") is True
    assert validate_evidence_field("Disposition", "Unprocessed") is True
    assert validate_evidence_field("Disposition", "Disrupted") is True

    # Message Payload
    assert validate_evidence_field("Message Payload", "Malicious process spawned from powershell.exe") is True
    assert validate_evidence_field("Message Payload", "Outbound beaconing detected to C2 server") is True
