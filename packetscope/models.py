from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Limits:
    max_input_bytes: int = 256 * 1024 * 1024
    max_packet_bytes: int = 16 * 1024 * 1024
    max_packets: int = 100_000
    max_pcapng_block_bytes: int = 64 * 1024 * 1024
    max_hypotheses: int = 500
    max_response_bytes: int = 32 * 1024 * 1024
    max_analysis_seconds: float = 2.0
    max_crc_candidates: int = 4000
    max_crc_ranges: int = 512
    max_flows: int = 100_000
    max_samples: int = 1_000
    max_job_payload_bytes: int = 64 * 1024 * 1024
    max_retained_jobs: int = 32

    def __post_init__(self) -> None:
        for name, value in (
            ("max_input_bytes", self.max_input_bytes),
            ("max_packet_bytes", self.max_packet_bytes),
            ("max_packets", self.max_packets),
            ("max_pcapng_block_bytes", self.max_pcapng_block_bytes),
            ("max_hypotheses", self.max_hypotheses),
            ("max_response_bytes", self.max_response_bytes),
            ("max_crc_candidates", self.max_crc_candidates),
            ("max_crc_ranges", self.max_crc_ranges),
            ("max_flows", self.max_flows),
            ("max_samples", self.max_samples),
            ("max_job_payload_bytes", self.max_job_payload_bytes),
            ("max_retained_jobs", self.max_retained_jobs),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_analysis_seconds <= 0:
            raise ValueError("max_analysis_seconds must be positive")


@dataclass(frozen=True)
class Packet:
    index: int
    payload: bytes
    source_offset: int = 0
    timestamp: float | None = None
    original_length: int | None = None
    link_type: int | None = None
    interface_id: int | None = None
    source_name: str | None = None


@dataclass(frozen=True)
class FieldHypothesis:
    """A byte-precise, explainable interpretation of a possible field."""

    field_type: str
    packet_id: int
    absolute_offset: int
    payload_relative_offset: int | None
    width_bits: int
    endian: str
    candidate_value: Any
    confidence: float
    evidence: list[dict[str, Any]] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    sample_count: int = 0
    status: str = "hypothesis"
    alternative_interpretations: list[str] = field(default_factory=list)
    coordinate_system: str = "raw_packet"

    def __post_init__(self) -> None:
        if self.absolute_offset < 0:
            raise ValueError("absolute_offset must be non-negative")
        if self.payload_relative_offset is not None and self.payload_relative_offset < 0:
            raise ValueError("payload_relative_offset must be non-negative")
        if self.width_bits <= 0 or self.width_bits % 8:
            raise ValueError("width_bits must be a positive multiple of eight")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.status.upper() == "CONFIRMED":
            raise ValueError("automatic field hypotheses cannot be confirmed")
        if not isinstance(self.coordinate_system, str) or self.coordinate_system not in {"raw_packet", "application_payload"}:
            raise ValueError("coordinate_system must be raw_packet or application_payload")

    def as_dict(self) -> dict[str, Any]:
        return {
            "field_type": self.field_type,
            "packet_id": self.packet_id,
            "absolute_offset": self.absolute_offset,
            "payload_relative_offset": self.payload_relative_offset,
            "width_bits": self.width_bits,
            "endian": self.endian,
            "candidate_value": self.candidate_value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "contradictions": self.contradictions,
            "sample_count": self.sample_count,
            "status": self.status,
            "alternative_interpretations": self.alternative_interpretations,
            "coordinate_system": self.coordinate_system,
        }


@dataclass
class ImportResult:
    format: str
    packets: list[Packet]
    warnings: list[str] = field(default_factory=list)
