"""Direction-aware grouping for decoded IP transport packets.

This module deliberately groups captured packets; it does not reassemble TCP
streams or infer application messages.  A :class:`Flow` therefore describes
the evidence present in the capture, including packet-level completeness and
limitations that an analysis consumer must keep visible.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

from packetscope.errors import InputLimitError
from packetscope.models import Limits, Packet
from packetscope.protocols import decode_packet


FORWARD = "forward"
REVERSE = "reverse"
BOTH = "both"


@dataclass(frozen=True, order=True)
class Endpoint:
    """Canonical IP endpoint used as one side of a flow."""

    ip_version: int
    address: str
    port: int

    def as_dict(self) -> dict[str, int | str]:
        return {"ip_version": self.ip_version, "address": self.address, "port": self.port}


@dataclass(frozen=True)
class FlowPacket:
    """Packet metadata retained in a normalized flow."""

    packet_id: int
    source_offset: int
    timestamp: float | None
    direction: str
    source: Endpoint
    destination: Endpoint
    payload_offset: int
    payload_length: int
    sequence: int | None = None
    acknowledgement: int | None = None
    flags: int | None = None
    complete: bool = True
    retransmission: bool = False
    out_of_order: bool = False
    limitations: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def direction_label(self) -> str:
        return self.direction

    def as_dict(self) -> dict:
        return {
            "packet_id": self.packet_id,
            "source_offset": self.source_offset,
            "timestamp": self.timestamp,
            "direction": self.direction,
            "direction_label": self.direction_label,
            "source": self.source.as_dict(),
            "destination": self.destination.as_dict(),
            "payload_offset": self.payload_offset,
            "payload_length": self.payload_length,
            "sequence": self.sequence,
            "acknowledgement": self.acknowledgement,
            "flags": self.flags,
            "complete": self.complete,
            "retransmission": self.retransmission,
            "out_of_order": self.out_of_order,
            "limitations": list(self.limitations),
            "notes": list(self.notes),
        }


@dataclass
class Flow:
    """A bidirectional, endpoint-normalized collection of captured packets."""

    flow_id: str
    ip_version: int
    transport: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    packets: list[FlowPacket] = field(default_factory=list)
    selected_direction: str = BOTH
    complete: bool = True
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    direction_counts: dict[str, int] = field(default_factory=lambda: {FORWARD: 0, REVERSE: 0})
    retransmission_count: int = 0
    out_of_order_count: int = 0
    limitations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def protocol(self) -> str:
        """Compatibility/readability alias for the transport name."""

        return self.transport

    @property
    def packet_ids(self) -> tuple[int, ...]:
        return tuple(packet.packet_id for packet in self.packets)

    @property
    def endpoints(self) -> tuple[Endpoint, Endpoint]:
        return self.endpoint_a, self.endpoint_b

    @property
    def completeness(self) -> dict[str, object]:
        return {
            "packet_metadata": "complete" if self.complete else "partial",
            "stream_reassembly": "not_performed",
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
        }

    def as_dict(self) -> dict:
        """Return deterministic JSON-safe flow metadata."""

        return {
            "flow_id": self.flow_id,
            "ip_version": self.ip_version,
            "transport": self.transport,
            "protocol": self.transport,
            "endpoints": [self.endpoint_a.as_dict(), self.endpoint_b.as_dict()],
            "endpoint_a": self.endpoint_a.as_dict(),
            "endpoint_b": self.endpoint_b.as_dict(),
            "packet_count": self.packet_count,
            "packets": [packet.as_dict() for packet in self.packets],
            "selected_direction": self.selected_direction,
            "direction_counts": {FORWARD: self.direction_counts.get(FORWARD, 0), REVERSE: self.direction_counts.get(REVERSE, 0)},
            "complete": self.complete,
            "completeness": self.completeness,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "retransmission_count": self.retransmission_count,
            "out_of_order_count": self.out_of_order_count,
            "limitations": sorted(set(self.limitations)),
            "notes": list(dict.fromkeys(self.notes)),
        }


def normalize_direction(value: str | None) -> str:
    """Normalize public direction aliases to ``both``, ``forward``, or ``reverse``."""

    normalized = (value or BOTH).strip().lower().replace("-", "_")
    aliases = {
        "": BOTH,
        "all": BOTH,
        "both": BOTH,
        "forward": FORWARD,
        "a_to_b": FORWARD,
        "a2b": FORWARD,
        "reverse": REVERSE,
        "b_to_a": REVERSE,
        "b2a": REVERSE,
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise ValueError("direction must be one of both, forward, or reverse") from exc


def group_flows(
    packets: Iterable[Packet],
    *,
    selected_direction: str | None = None,
    limits: Limits | None = None,
) -> list[Flow]:
    """Group IPv4/IPv6 TCP/UDP packets into deterministic bidirectional flows.

    Packets that the standard-library decoder cannot identify as a complete IP
    transport packet are omitted.  The returned order is by first captured
    packet ID, then canonical flow ID; packets within each flow use packet ID,
    source offset, and their stable input position as tie breakers.
    """

    limits = limits or Limits()
    direction = normalize_direction(selected_direction)
    grouped: dict[tuple, list[tuple[tuple[int, int, int], Packet, dict, Endpoint, Endpoint, str]]] = {}
    for position, packet in enumerate(packets):
        if position >= limits.max_packets:
            raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
        if len(packet.payload) > limits.max_packet_bytes:
            raise InputLimitError(f"packet exceeds limit {limits.max_packet_bytes}")
        decoded = decode_packet(packet)
        network, transport = _network_transport(decoded)
        if network is None or transport is None:
            continue
        if transport.get("status") != "ok" or transport.get("protocol") not in {"tcp", "udp"}:
            continue
        try:
            version = int(network["version"])
            source = _endpoint(version, str(network["source"]), int(transport["source_port"]))
            destination = _endpoint(version, str(network["destination"]), int(transport["destination_port"]))
        except (KeyError, TypeError, ValueError):
            continue
        endpoint_a, endpoint_b = sorted((source, destination), key=_endpoint_sort_key)
        packet_direction = FORWARD if source == endpoint_a else REVERSE
        if direction != BOTH and packet_direction != direction:
            continue
        key = (version, str(transport["protocol"]), endpoint_a, endpoint_b)
        order = (int(packet.index), int(packet.source_offset), position)
        grouped.setdefault(key, []).append((order, packet, transport, source, destination, packet_direction))

    if len(grouped) > limits.max_flows:
        raise InputLimitError(f"flow count exceeds limit {limits.max_flows}")
    result = []
    for key, records in grouped.items():
        records.sort(key=lambda item: item[0])
        result.append(_make_flow(key, records, direction))
    result.sort(key=lambda flow: (flow.packets[0].packet_id if flow.packets else -1, flow.flow_id))
    return result


def select_flow_packets(
    packets: Iterable[Packet],
    *,
    selected_direction: str | None = None,
    flow_id: str | None = None,
    limits: Limits | None = None,
) -> list[Packet]:
    """Select captured packets by normalized flow and/or direction.

    With no selection this returns the input packet sequence as a bounded list.
    Direction selection intentionally returns only decodable flow packets so an
    analysis cannot accidentally mix unclassified bytes into one direction.
    """

    packet_list = list(packets)
    limits = limits or Limits()
    if len(packet_list) > limits.max_packets:
        raise InputLimitError(f"packet count exceeds limit {limits.max_packets}")
    direction = normalize_direction(selected_direction)
    if flow_id is None and direction == BOTH:
        for packet in packet_list:
            if len(packet.payload) > limits.max_packet_bytes:
                raise InputLimitError(f"packet exceeds limit {limits.max_packet_bytes}")
        return packet_list
    flows = group_flows(packet_list, selected_direction=direction, limits=limits)
    selected_ids = {
        item.packet_id
        for flow in flows
        if flow_id is None or flow.flow_id == flow_id
        for item in flow.packets
    }
    return [packet for packet in packet_list if packet.index in selected_ids]


def flows_as_dict(flows: Iterable[Flow]) -> list[dict]:
    """Serialize flows in their supplied deterministic order."""

    return [flow.as_dict() for flow in flows]


# A descriptive alias for callers that prefer the operation's verb.
normalize_flows = group_flows


def _endpoint(version: int, address: str, port: int) -> Endpoint:
    parsed = ipaddress.ip_address(address)
    if parsed.version != version or not 0 <= port <= 65535:
        raise ValueError("invalid endpoint")
    return Endpoint(version, parsed.compressed, port)


def _endpoint_sort_key(endpoint: Endpoint) -> tuple[int, bytes, int]:
    return endpoint.ip_version, ipaddress.ip_address(endpoint.address).packed, endpoint.port


def _network_transport(decoded: dict) -> tuple[dict | None, dict | None]:
    network = decoded.get("network") if isinstance(decoded.get("network"), dict) else decoded
    if not isinstance(network, dict) or network.get("version") not in (4, 6):
        return None, None
    transport = network.get("transport")
    return network, transport if isinstance(transport, dict) else None


def _make_flow(key: tuple, records: list[tuple], selected_direction: str) -> Flow:
    version, transport_name, endpoint_a, endpoint_b = key
    flow_id = _flow_id(version, transport_name, endpoint_a, endpoint_b)
    flow = Flow(flow_id, version, transport_name, endpoint_a, endpoint_b, selected_direction=selected_direction)
    state = {FORWARD: {"expected": None, "ranges": []}, REVERSE: {"expected": None, "ranges": []}}
    timestamps: list[float] = []
    for _order, packet, transport, source, destination, direction in records:
        packet_notes: list[str] = []
        limitations: list[str] = []
        payload_offset = int(transport.get("payload_offset", 0))
        payload_length = max(0, int(transport.get("payload_length", 0)))
        complete = not bool(transport.get("truncated")) and not (
            packet.original_length is not None and packet.original_length > len(packet.payload)
        )
        if transport.get("truncated"):
            limitations.append("captured transport payload is truncated")
            packet_notes.append("packet is incomplete according to the decoder")
        if packet.original_length is not None and packet.original_length > len(packet.payload):
            limitations.append("capture record is shorter than its original length")
        sequence = int(transport["sequence"]) if "sequence" in transport else None
        acknowledgement = int(transport["acknowledgement"]) if "acknowledgement" in transport else None
        flags = int(transport["flags"]) if "flags" in transport else None
        retransmission = False
        out_of_order = False
        if transport_name == "tcp" and sequence is not None:
            span = payload_length
            if flags is not None and flags & 0x002:
                span += 1
            if flags is not None and flags & 0x001:
                span += 1
            if span:
                start = sequence
                end = sequence + span
                direction_state = state[direction]
                retransmission = any(start < old_end and old_start < end for old_start, old_end in direction_state["ranges"])
                expected = direction_state["expected"]
                out_of_order = expected is not None and start < expected
                direction_state["ranges"].append((start, end))
                direction_state["expected"] = max(expected if expected is not None else end, end)
                if retransmission:
                    packet_notes.append("possible TCP retransmission or overlapping segment")
                if out_of_order:
                    packet_notes.append("TCP segment is earlier than the next expected sequence")
        flow_packet = FlowPacket(
            packet.index,
            packet.source_offset,
            packet.timestamp,
            direction,
            source,
            destination,
            payload_offset,
            payload_length,
            sequence,
            acknowledgement,
            flags,
            complete,
            retransmission,
            out_of_order,
            tuple(sorted(set(limitations))),
            tuple(packet_notes),
        )
        flow.packets.append(flow_packet)
        flow.direction_counts[direction] += 1
        flow.complete = flow.complete and complete
        if packet.timestamp is not None:
            timestamps.append(float(packet.timestamp))
        if retransmission:
            flow.retransmission_count += 1
        if out_of_order:
            flow.out_of_order_count += 1
        flow.limitations.extend(limitations)
    if timestamps:
        flow.first_timestamp = min(timestamps)
        flow.last_timestamp = max(timestamps)
    if transport_name == "tcp":
        flow.limitations.append("TCP stream reassembly is not performed; segments remain packet-scoped")
    if any(packet.timestamp is None for packet in flow.packets):
        flow.limitations.append("one or more packets have no capture timestamp")
    if flow.retransmission_count:
        flow.notes.append("retransmission/overlap detection is sequence-based and remains a hypothesis")
    if flow.out_of_order_count:
        flow.notes.append("out-of-order notes are based on captured packet order, not reassembled stream state")
    return flow


def _flow_id(version: int, transport: str, endpoint_a: Endpoint, endpoint_b: Endpoint) -> str:
    return f"ipv{version}/{transport}/{endpoint_a.address}:{endpoint_a.port}<->{endpoint_b.address}:{endpoint_b.port}"
