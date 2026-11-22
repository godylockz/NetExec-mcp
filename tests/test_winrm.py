#!/usr/bin/env python3
# -- coding: utf-8 --

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from netexec_mcp.modules import winrm


def test_winrm_run_passes_kerberos_cache_to_netexec():
    calls = []

    async def execute(config, protocol, targets, flags, **kwargs):
        calls.append((config, protocol, targets, flags, kwargs))
        return SimpleNamespace(to_dict=lambda: {"outcome_class": "success"})

    with patch.object(winrm, "execute", execute):
        result = asyncio.run(winrm._winrm_run(
            lambda: "config",
            ["-x", "whoami"],
            ["srv02.example.test"],
            offensive=True,
            domain="EXAMPLE.TEST",
            use_kcache=True,
            kdc_host="192.0.2.10",
            ccache="/tmp/alice.ccache",
        ))

    assert result == {"outcome_class": "success"}
    assert calls == [(
        "config",
        "winrm",
        ["srv02.example.test"],
        [
            "-d", "EXAMPLE.TEST", "--kdcHost", "192.0.2.10", "--use-kcache",
            "-x", "whoami",
        ],
        {
            "offensive": True,
            "dump": False,
            "ccache": "/tmp/alice.ccache",
        },
    )]
