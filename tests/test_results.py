#!/usr/bin/env python3
# -- coding: utf-8 --

from netexec_mcp.results import build_verdict, parse_markers


def verdict_for(output):
    records = parse_markers(output)
    return records, build_verdict(records, returncode=0)


def test_clock_skew_is_authentication_failure():
    records, (_, outcome_class, op_error, _) = verdict_for(
        "RDP 192.0.2.10 3389 SRV01 [-] Failed to get a TGT with the certificate: "
        "Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)"
    )

    assert records[0].error_class == "auth_error"
    assert records[0].terminal is False
    assert outcome_class == "auth_failed"
    assert op_error is None


def test_disconnected_rdp_execution_overrides_authentication_success():
    _, (verdict, outcome_class, op_error, op_error_note) = verdict_for(
        r"""RDP 192.0.2.10 3389 SRV01 [+] EXAMPLE\alice from ccache
RDP 192.0.2.10 3389 SRV01 [-] RDP session disconnected before command execution; -x/-X was not run"""
    )

    assert verdict["any_success"] is True
    assert outcome_class == "op_error"
    assert op_error == "rdp_operation_failed"
    assert "did not complete" in op_error_note


def test_reset_rdp_execution_is_an_operation_error():
    _, (_, outcome_class, op_error, _) = verdict_for(
        r"""RDP 192.0.2.10 3389 SRV01 [+] EXAMPLE\alice from ccache
RDP 192.0.2.10 3389 SRV01 [-] Connection was reset by the remote host"""
    )

    assert outcome_class == "op_error"
    assert op_error == "rdp_operation_failed"


def test_rdp_failure_does_not_bury_another_hosts_success():
    _, (_, outcome_class, op_error, _) = verdict_for(
        r"""RDP 192.0.2.10 3389 SRV01 [+] EXAMPLE\alice from ccache
RDP 192.0.2.10 3389 SRV01 [-] Connection was reset by the remote host
RDP 192.0.2.11 3389 SRV02 [+] EXAMPLE\alice from ccache"""
    )

    assert outcome_class == "success"
    assert op_error == "rdp_operation_failed"


def test_disconnected_rdp_screenshot_is_an_operation_error():
    _, (_, outcome_class, op_error, _) = verdict_for(
        r"""RDP 192.0.2.10 3389 SRV01 [+] EXAMPLE\alice from ccache
RDP 192.0.2.10 3389 SRV01 [-] RDP session disconnected before screenshot capture; --screenshot was not run"""
    )

    assert outcome_class == "op_error"
    assert op_error == "rdp_operation_failed"


def test_connection_reset_is_not_assumed_to_be_rdp_on_other_protocols():
    records, (_, outcome_class, op_error, _) = verdict_for(
        "SMB 192.0.2.10 445 SRV01 [-] Connection was reset by the remote host"
    )

    assert records[0].error_class is None
    assert outcome_class == "ok"
    assert op_error is None
