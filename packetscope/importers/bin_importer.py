from packetscope.errors import InputLimitError
from packetscope.models import ImportResult, Limits, Packet


def parse_bin(data: bytes, name: str, limits: Limits) -> ImportResult:
    if len(data) > limits.max_packet_bytes:
        raise InputLimitError(f"binary packet exceeds limit {limits.max_packet_bytes}")
    return ImportResult("bin", [Packet(0, data, source_name=name)])
