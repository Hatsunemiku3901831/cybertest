"""Burp HTTP replay provider adapter."""

from __future__ import annotations

from .base import TransportDynamicAdapter


class BurpReplayAdapter(TransportDynamicAdapter):
    capability_id = "http.replay"
    fallback_capability = "cli.http"
    allowed_operations = frozenset(
        {
            "query_history",
            "replay",
            "authentication_matrix",
            "differential_compare",
        }
    )
