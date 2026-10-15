import json
import unittest
from pathlib import Path

from packetscope.analysis import analyze_packets
from packetscope.flows import group_flows
from packetscope.importers import import_bytes
from packetscope.models import Limits
from tests.fixtures.phase6_multiflow import pcap_bytes


class Phase6MultiFlowTests(unittest.TestCase):
    def test_deterministic_capture_matches_manifest_and_reports_limits(self):
        manifest = json.loads(Path(__file__).with_name("fixtures").joinpath("phase6_multiflow_ground_truth.json").read_text())
        imported = import_bytes("phase6_multiflow.pcap", pcap_bytes(), "pcap", Limits())
        flows = group_flows(imported.packets)
        by_id = {flow.flow_id: flow for flow in flows}
        self.assertEqual(set(by_id), set(manifest["flow_ids"]))
        for flow_id, packet_ids in manifest["membership"].items():
            self.assertEqual([packet.packet_id for packet in by_id[flow_id].packets], packet_ids)
        for flow in flows:
            for packet in flow.packets:
                self.assertEqual(packet.direction, manifest["directions"][str(packet.packet_id)])
        tcp = by_id["ipv4/tcp/192.0.2.30:8000<->192.0.2.40:9000"]
        self.assertGreaterEqual(tcp.retransmission_count, 1)
        self.assertGreaterEqual(tcp.out_of_order_count, 1)
        self.assertTrue(any("reassembly is not performed" in item for item in tcp.limitations))

        result = analyze_packets(imported.packets)
        self.assertEqual(result["observations"]["packet_count"], 10)
        self.assertEqual(result["observations"]["analysis_packet_count"], 10)
        self.assertTrue(any("application payload unavailable" in warning for warning in result["warnings"]))
        crc = [item for item in result["hypotheses"] if item.get("algorithm") == manifest["application_crc"]["algorithm"]]
        self.assertTrue(crc)
        self.assertTrue(all(set(item.get("packet_ids", [])) <= set(range(10)) for item in crc for item in item.get("evidence", [])))

    def test_selected_flow_and_direction_have_exact_packet_scope(self):
        imported = import_bytes("phase6_multiflow.pcap", pcap_bytes(), "pcap", Limits())
        flow_id = "ipv4/udp/192.0.2.10:4000<->192.0.2.20:5000"
        result = analyze_packets(imported.packets, flow_id=flow_id, selected_direction="forward")
        self.assertEqual(result["flow_selection"], {"flow_id": flow_id, "direction": "forward", "applied": True})
        self.assertEqual([packet["index"] for packet in result["packets"]], [0])
        self.assertEqual(result["observations"]["analysis_packet_count"], 1)
        self.assertEqual(result["hypotheses"], [])


if __name__ == "__main__":
    unittest.main()
