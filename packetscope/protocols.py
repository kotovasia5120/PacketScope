"""Bounded decoders for common link and network headers.

The decoder never reassembles fragments and never assumes an unknown link type
is Ethernet.  All offsets are relative to the imported packet's raw bytes and
all returned values are JSON-safe metadata.
"""

from __future__ import annotations

import struct

from packetscope.models import Packet


def decode_packet(packet: Packet) -> dict:
    if packet.link_type not in (1, 101):
        return {
            "status": "unsupported_link_type",
            "link_type": packet.link_type,
            "payload_offset": 0,
            "payload_length": len(packet.payload),
        }
    if packet.link_type == 101:
        return _decode_ip(packet.payload, 0)
    if len(packet.payload) < 14:
        return {"status": "truncated_ethernet", "header_length": len(packet.payload)}
    destination = packet.payload[0:6].hex()
    source = packet.payload[6:12].hex()
    ether_type = struct.unpack_from("!H", packet.payload, 12)[0]
    offset = 14
    vlan_tags = 0
    while ether_type in (0x8100, 0x88A8, 0x9100):
        if len(packet.payload) < offset + 4:
            return {
                "status": "truncated_ethernet_vlan",
                "source": source,
                "destination": destination,
                "vlan_tags": vlan_tags,
            }
        ether_type = struct.unpack_from("!H", packet.payload, offset + 2)[0]
        offset += 4
        vlan_tags += 1
    result = {
        "status": "ok",
        "link": "ethernet",
        "source": source,
        "destination": destination,
        "ether_type": f"0x{ether_type:04x}",
        "header_length": offset,
        "vlan_tags": vlan_tags,
    }
    if ether_type == 0x0800:
        result["network"] = _decode_ip(packet.payload, offset)
    elif ether_type == 0x86DD:
        result["network"] = _decode_ipv6(packet.payload, offset)
    else:
        result["network"] = {
            "status": "unsupported_ethertype",
            "payload_offset": offset,
            "payload_length": max(0, len(packet.payload) - offset),
        }
    return result


def _decode_ip(data: bytes, offset: int) -> dict:
    if len(data) < offset + 1:
        return {"status": "truncated_ip", "payload_offset": offset}
    version = data[offset] >> 4
    if version == 4:
        return _decode_ipv4(data, offset)
    if version == 6:
        return _decode_ipv6(data, offset)
    return {"status": "unknown_ip_version", "version": version, "payload_offset": offset}


def _decode_ipv4(data: bytes, offset: int) -> dict:
    if len(data) < offset + 20:
        return {"status": "truncated_ipv4", "payload_offset": offset}
    first, tos, total_length, identification, flags_fragment, ttl, protocol, checksum = struct.unpack_from(
        "!BBHHHBBH", data, offset
    )
    version = first >> 4
    header_length = (first & 0x0F) * 4
    if version != 4 or header_length < 20:
        return {"status": "invalid_ipv4_header", "payload_offset": offset}
    if len(data) < offset + header_length:
        return {"status": "truncated_ipv4_options", "payload_offset": offset}
    if total_length < header_length:
        return {"status": "invalid_ipv4_length", "payload_offset": offset}
    captured_end = min(len(data), offset + total_length)
    fragmented = bool(flags_fragment & 0x2000 or flags_fragment & 0x1FFF)
    result = {
        "status": "fragmented" if fragmented else "ok",
        "version": 4,
        "source": ".".join(str(value) for value in data[offset + 12 : offset + 16]),
        "destination": ".".join(str(value) for value in data[offset + 16 : offset + 20]),
        "protocol": protocol,
        "header_length": header_length,
        "total_length": total_length,
        "captured_length": max(0, captured_end - offset),
        "fragment_offset": (flags_fragment & 0x1FFF) * 8,
        "more_fragments": bool(flags_fragment & 0x2000),
        "payload_offset": offset + header_length,
        "payload_length": max(0, captured_end - offset - header_length),
        "truncated": captured_end < offset + total_length,
    }
    if not fragmented and not result["truncated"]:
        result["transport"] = _decode_transport(data, offset + header_length, protocol, captured_end)
    return result


def _decode_ipv6(data: bytes, offset: int) -> dict:
    if len(data) < offset + 40:
        return {"status": "truncated_ipv6", "payload_offset": offset}
    first_word, payload_length, next_header, hop_limit = struct.unpack_from("!IHBB", data, offset)
    if first_word >> 28 != 6:
        return {"status": "invalid_ipv6_header", "payload_offset": offset}
    source = ":".join(f"{value:04x}" for value in struct.unpack_from("!8H", data, offset + 8))
    destination = ":".join(f"{value:04x}" for value in struct.unpack_from("!8H", data, offset + 24))
    payload_offset = offset + 40
    end = min(len(data), payload_offset + payload_length)
    result = {
        "status": "ok",
        "version": 6,
        "source": source,
        "destination": destination,
        "next_header": next_header,
        "hop_limit": hop_limit,
        "header_length": 40,
        "payload_offset": payload_offset,
        "payload_length": max(0, end - payload_offset),
        "truncated": end < payload_offset + payload_length,
    }
    if next_header == 44:
        result["status"] = "fragmented"
        return result
    if not result["truncated"]:
        result["transport"] = _decode_transport(data, payload_offset, next_header, end)
    return result


def _decode_transport(data: bytes, offset: int, protocol: int, end: int) -> dict:
    if protocol == 6:
        if end - offset < 20:
            return {"status": "truncated_tcp", "payload_offset": offset}
        source, destination, sequence, acknowledgement, flags_word, window, checksum, urgent = struct.unpack_from(
            "!HHIIHHHH", data, offset
        )
        header_length = ((flags_word >> 12) & 0xF) * 4
        if header_length < 20 or end - offset < header_length:
            return {"status": "invalid_tcp_header", "payload_offset": offset}
        return {
            "status": "ok",
            "protocol": "tcp",
            "source_port": source,
            "destination_port": destination,
            "sequence": sequence,
            "acknowledgement": acknowledgement,
            "flags": flags_word & 0x1FF,
            "header_length": header_length,
            "payload_offset": offset + header_length,
            "payload_length": end - offset - header_length,
        }
    if protocol == 17:
        if end - offset < 8:
            return {"status": "truncated_udp", "payload_offset": offset}
        source, destination, length, checksum = struct.unpack_from("!HHHH", data, offset)
        if length < 8:
            return {"status": "invalid_udp_length", "payload_offset": offset}
        return {
            "status": "ok",
            "protocol": "udp",
            "source_port": source,
            "destination_port": destination,
            "length": length,
            "payload_offset": offset + 8,
            "payload_length": max(0, min(length, end - offset) - 8),
            "truncated": end - offset < length,
        }
    return {
        "status": "unsupported_transport",
        "protocol": protocol,
        "payload_offset": offset,
        "payload_length": max(0, end - offset),
    }
