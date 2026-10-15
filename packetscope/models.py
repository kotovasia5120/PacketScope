from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Limits:
    max_input_bytes: int = 256 * 1024 * 1024
    max_packet_bytes: int = 16 * 1024 * 1024
    max_packets: int = 100_000
    max_pcapng_block_bytes: int = 64 * 1024 * 1024
    max_hypotheses: int = 500
    max_response_bytes: int = 32 * 1024 * 1024


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


@dataclass
class ImportResult:
    format: str
    packets: list[Packet]
    warnings: list[str] = field(default_factory=list)
