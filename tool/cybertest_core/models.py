"""Shared data models for Cybertest candidate processing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RawSignal:
    value: str
    source: str
    source_file: str
    record: dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    key: str
    name: str
    asset: str
    url_or_endpoint: str
    candidate_type: str
    evidence_sources: set[str] = field(default_factory=set)
    evidence_refs: set[str] = field(default_factory=set)
    related_params: set[str] = field(default_factory=set)
    score: int = 0
    score_reasons: list[str] = field(default_factory=list)
    downgrade_reasons: list[str] = field(default_factory=list)
    anonymous_hint: bool = False
    observed_without_auth: bool | None = None
    auth_experiment: dict[str, Any] | None = None
    unauth_reachable: bool = False
    core_business: bool = False
    possible_impact: str = ""
    next_action: str = ""
    needs_material: bool = False
    material_requirements: list[str] = field(default_factory=list)
    status: str = "discovered"
    queue: str = "P3"
    priority_score: int = 0
    evidence_confidence: str = "unknown"
    reachability_stage: str = "signal"
    impact_stage: str = "hypothesis"
    business_object: str = "unknown"
    business_capability: str = "unknown"
    operation_type: str = "read"
    trust_boundary: str = "unknown"
    category: str = "unknown"
    technologies: set[str] = field(default_factory=set)
    observed_signals: set[str] = field(default_factory=set)
    suspected_control_gaps: set[str] = field(default_factory=set)
    available_materials: set[str] = field(default_factory=set)
    available_capabilities: set[str] = field(default_factory=set)
    safe_validation_level: str = "readonly"
    matched_tactics: list[dict[str, Any]] = field(default_factory=list)
    route_status: str = "unrouted"
    route_decision_id: str = ""
    route_fallback: dict[str, Any] | None = None
    validation_contract: dict[str, Any] = field(default_factory=dict)
    negative_controls: list[str] = field(default_factory=list)
    evidence_invariants: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    rollback_plan: dict[str, Any] = field(default_factory=dict)
    root_cause_family: str = "unknown"
    affected_instance_key: str = ""
    reopen_conditions: list[str] = field(default_factory=list)
    missing_materials: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    recovery_first_action: str = ""
    resume_tactic_id: str = ""
    do_not_overclaim: str = ""

    def __post_init__(self) -> None:
        """Keep the v1 score alias compatible with v2 priority_score."""

        if self.priority_score == 0 and self.score:
            self.priority_score = self.score
        elif self.score == 0 and self.priority_score:
            self.score = self.priority_score
