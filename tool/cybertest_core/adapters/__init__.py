"""Dynamic provider adapters for explicit Cybertest validation plans."""

from .base import (
    AdapterExecutionResult,
    CapabilityProbeResult,
    DynamicAdapter,
    JsonCommandTransport,
    TransportDynamicAdapter,
)
from .browser_playwright import PlaywrightAdapter
from .cli_http import CLIHttpAdapter
from .http_replay_burp import BurpReplayAdapter
from .js_cdp import JSCDPAdapter
from .oast_callback import OASTCallbackAdapter
from .packet_capture import PacketCaptureAdapter


ADAPTER_TYPES = {
    "browser.interactive": PlaywrightAdapter,
    "http.replay": BurpReplayAdapter,
    "js.cdp": JSCDPAdapter,
    "http.capture": PacketCaptureAdapter,
    "oast.callback": OASTCallbackAdapter,
    "cli.http": CLIHttpAdapter,
}

__all__ = [
    "ADAPTER_TYPES",
    "AdapterExecutionResult",
    "BurpReplayAdapter",
    "CapabilityProbeResult",
    "CLIHttpAdapter",
    "DynamicAdapter",
    "JSCDPAdapter",
    "JsonCommandTransport",
    "OASTCallbackAdapter",
    "PacketCaptureAdapter",
    "PlaywrightAdapter",
    "TransportDynamicAdapter",
]
