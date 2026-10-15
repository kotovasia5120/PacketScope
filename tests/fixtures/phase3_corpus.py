"""Deterministic synthetic corpora for protocol-analysis regression tests."""
from __future__ import annotations

import random
from packetscope.analysis.crc import CRCParams, STANDARD_CRC, compute_crc

TRUTH_A = {"magic": {"offset": 0, "width": 2}, "message_type": {"offset": 2, "width": 1}, "sequence_counter": {"offset": 3, "width": 2, "endian": "big"}, "length": {"offset": 5, "width": 2, "endian": "big"}, "crc": {"width": 2, "algorithm": "CRC-16/CCITT-FALSE", "from_end": 2}}
TRUTH_B = {"magic": {"offset": 0, "width": 1}, "flags": {"offset": 1, "width": 1}, "sequence_counter": {"offset": 2, "width": 4, "endian": "little", "wraps": True}, "crc": {"width": 4, "algorithm": "CRC-32/ISO-HDLC", "from_end": 4, "endian": "little"}}


def corpus_a() -> list[bytes]:
    params = STANDARD_CRC[1]
    payloads = (b"A", b"payload", b"longer-payload")
    packets = []
    for sequence, payload in enumerate(payloads):
        body = b"\xa5\x5a" + b"\x02" + sequence.to_bytes(2, "big") + b"\x00\x00" + payload
        body = body[:5] + (len(body) + 2).to_bytes(2, "big") + body[7:]
        packets.append(body + compute_crc(body, params).to_bytes(2, "big"))
    return packets


def corpus_b() -> list[bytes]:
    params = STANDARD_CRC[3]
    sequences = (0xFFFFFFFE, 0xFFFFFFFF, 0, 1)
    packets = []
    for index, sequence in enumerate(sequences):
        body = b"\xc3" + bytes((1 << (index % 2),)) + sequence.to_bytes(4, "little") + b"\x03xyz"
        packets.append(body + compute_crc(body, params).to_bytes(4, "little"))
    return packets


def corpus_c() -> list[bytes]:
    return [b"\xde\xad\x01alpha", b"\xde\xad\x01beXta", b"\xde\xad\x01gamma", b"\xde\xad\x01ga"]


def corpus_d() -> list[bytes]:
    rng = random.Random(90210)
    packets = [bytes(rng.randrange(256) for _ in range(20)) for _ in range(5)]
    return [packet[:-1] + bytes((packet[-1] ^ 0xFF,)) for packet in packets]
