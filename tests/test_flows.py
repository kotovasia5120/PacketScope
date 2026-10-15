import struct
import unittest

from packetscope.analysis import analyze_packets
from packetscope.errors import InputLimitError
from packetscope.flows import group_flows, select_flow_packets
from packetscope.models import Limits, Packet


def ethernet(payload: bytes, ether_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ether_type) + payload


def ipv4_transport(transport: bytes, protocol: int, source: bytes, destination: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, protocol, 0, source, destination)
    return header + transport


def ipv6_transport(transport: bytes, next_header: int, source: bytes, destination: bytes) -> bytes:
    header = struct.pack("!IHBB", 6 << 28, len(transport), next_header, 32) + source + destination
    return header + transport


def udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def tcp(source_port: int, destination_port: int, sequence: int, payload: bytes, flags: int = 0x18) -> bytes:
    return struct.pack("!HHIIHHHH", source_port, destination_port, sequence, 0, 0x5000 | flags, 4096, 0, 0) + payload


class FlowGroupingTests(unittest.TestCase):
    def test_ipv4_udp_reverse_packets_share_flow_and_keep_identity(self):
        left = bytes((192, 0, 2, 10))
        right = bytes((192, 0, 2, 20))
        packets = [
            Packet(10, ethernet(ipv4_transport(udp(4000, 5000, b"left-1"), 17, left, right), 0x0800), 100, 1.0, link_type=1),
            Packet(11, ethernet(ipv4_transport(udp(5000, 4000, b"right-1"), 17, right, left), 0x0800), 200, 2.0, link_type=1),
            Packet(12, ethernet(ipv4_transport(udp(4000, 5000, b"left-2"), 17, left, right), 0x0800), 300, 3.0, link_type=1),
        ]
        flows = group_flows(packets)
        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow.direction_counts, {"forward": 2, "reverse": 1})
        self.assertEqual([item.packet_id for item in flow.packets], [10, 11, 12])
        self.assertEqual([item.direction for item in flow.packets], ["forward", "reverse", "forward"])
        self.assertEqual([item.source_offset for item in flow.packets], [100, 200, 300])
        self.assertEqual(flow.first_timestamp, 1.0)
        self.assertEqual(flow.last_timestamp, 3.0)
        self.assertTrue(flow.complete)

        forward = group_flows(packets, selected_direction="forward")[0]
        self.assertEqual([item.packet_id for item in forward.packets], [10, 12])
        self.assertEqual(forward.direction_counts, {"forward": 2, "reverse": 0})

    def test_ipv6_udp_and_ipv4_tcp_are_separate_and_stably_ordered(self):
        v6a = bytes.fromhex("20010db8000000000000000000000002")
        v6b = bytes.fromhex("20010db8000000000000000000000001")
        v4a = bytes((192, 0, 2, 30))
        v4b = bytes((192, 0, 2, 40))
        packets = [
            Packet(3, ethernet(ipv6_transport(udp(6000, 7000, b"v6-reverse"), 17, v6a, v6b), 0x86DD), 30, 3.0, link_type=1),
            Packet(1, ethernet(ipv4_transport(tcp(8000, 9000, 100, b"v4-forward"), 6, v4a, v4b), 0x0800), 10, 1.0, link_type=1),
            Packet(2, ethernet(ipv4_transport(tcp(9000, 8000, 500, b"v4-reverse"), 6, v4b, v4a), 0x0800), 20, 2.0, link_type=1),
            Packet(4, ethernet(ipv6_transport(udp(7000, 6000, b"v6-forward"), 17, v6b, v6a), 0x86DD), 40, 4.0, link_type=1),
        ]
        flows = group_flows(packets)
        self.assertEqual([flow.transport for flow in flows], ["tcp", "udp"])
        self.assertEqual([item.packet_id for item in flows[0].packets], [1, 2])
        self.assertEqual(flows[1].direction_counts, {"forward": 1, "reverse": 1})
        self.assertEqual(flows[1].endpoint_a.address, "2001:db8::1")
        self.assertEqual(flows[1].endpoint_b.address, "2001:db8::2")
        self.assertEqual(group_flows(list(reversed(packets)))[0].as_dict(), flows[0].as_dict())

    def test_tcp_notes_are_packet_scoped_and_direction_specific(self):
        left = bytes((192, 0, 2, 50))
        right = bytes((192, 0, 2, 60))
        packets = [
            Packet(0, ethernet(ipv4_transport(tcp(1000, 2000, 100, b"abcd"), 6, left, right), 0x0800), 50, 1.0, link_type=1),
            Packet(1, ethernet(ipv4_transport(tcp(1000, 2000, 110, b"efgh"), 6, left, right), 0x0800), 70, 2.0, link_type=1),
            Packet(2, ethernet(ipv4_transport(tcp(1000, 2000, 105, b"ij"), 6, left, right), 0x0800), 90, 3.0, link_type=1),
            Packet(3, ethernet(ipv4_transport(tcp(2000, 1000, 900, b"reply"), 6, right, left), 0x0800), 110, 4.0, link_type=1),
            Packet(4, ethernet(ipv4_transport(tcp(1000, 2000, 100, b"abcd"), 6, left, right), 0x0800), 130, 5.0, link_type=1),
        ]
        flow = group_flows(packets)[0]
        self.assertEqual(flow.direction_counts, {"forward": 4, "reverse": 1})
        self.assertEqual(flow.retransmission_count, 1)
        self.assertGreaterEqual(flow.out_of_order_count, 1)
        self.assertTrue(any("reassembly is not performed" in item for item in flow.limitations))
        self.assertTrue(any(item.retransmission for item in flow.packets))
        self.assertTrue(any(item.out_of_order for item in flow.packets))

    def test_selection_and_analysis_do_not_mix_directions(self):
        left = bytes((192, 0, 2, 70))
        right = bytes((192, 0, 2, 80))
        packets = [
            Packet(0, ethernet(ipv4_transport(udp(3000, 4000, b"AAA"), 17, left, right), 0x0800), link_type=1),
            Packet(1, ethernet(ipv4_transport(udp(4000, 3000, b"BBB"), 17, right, left), 0x0800), link_type=1),
        ]
        self.assertEqual([packet.index for packet in select_flow_packets(packets, selected_direction="reverse")], [1])
        result = analyze_packets(packets, selected_direction="forward")
        self.assertEqual(result["observations"]["analysis_packet_count"], 1)
        self.assertEqual([packet["packet_id"] for packet in result["flows"][0]["packets"]], [0, 1])
        self.assertEqual(result["flow_selection"]["direction"], "forward")

    def test_grouping_limits_and_invalid_direction_are_explicit(self):
        source = bytes((192, 0, 2, 90))
        destination = bytes((192, 0, 2, 91))
        packet = Packet(0, ethernet(ipv4_transport(udp(1, 2, b"x"), 17, source, destination), 0x0800), link_type=1)
        with self.assertRaises(InputLimitError):
            group_flows([packet, packet], limits=Limits(max_packets=1))
        with self.assertRaises(ValueError):
            group_flows([packet], selected_direction="sideways")


if __name__ == "__main__":
    unittest.main()
