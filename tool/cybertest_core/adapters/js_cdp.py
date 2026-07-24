"""JavaScript/CDP runtime provider adapter."""

from __future__ import annotations

from .base import TransportDynamicAdapter


class JSCDPAdapter(TransportDynamicAdapter):
    capability_id = "js.cdp"
    fallback_capability = "browser.interactive"
    allowed_operations = frozenset(
        {
            "observe_runtime",
            "observe_network",
            "source_map",
            "hook",
        }
    )
