"""Playwright/browser provider adapter."""

from __future__ import annotations

from .base import TransportDynamicAdapter


class PlaywrightAdapter(TransportDynamicAdapter):
    capability_id = "browser.interactive"
    fallback_capability = "cli.http"
    allowed_operations = frozenset(
        {
            "navigate",
            "form_interaction",
            "screenshot",
            "observe_network",
        }
    )
