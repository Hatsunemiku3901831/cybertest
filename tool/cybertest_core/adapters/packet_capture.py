"""Packet-capture provider adapter."""

from __future__ import annotations

from .base import TransportDynamicAdapter


class PacketCaptureAdapter(TransportDynamicAdapter):
    capability_id = "http.capture"
    fallback_capability = "http.replay"
    allowed_operations = frozenset({"capture"})
