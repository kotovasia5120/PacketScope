import unittest
from packetscope.analysis.crc import (
    CRCParams, SearchBudget, compute_crc, discover_checksums, standard_vectors,
)

class CrcTests(unittest.TestCase):
    def test_standard_check_vectors(self):
        self.assertEqual(standard_vectors(), {
            "CRC-8": 0xF4, "CRC-16/CCITT-FALSE": 0x29B1,
            "CRC-16/MODBUS": 0x4B37, "CRC-32/ISO-HDLC": 0xCBF43926,
        })

    def test_discovery_reports_location_order_and_range(self):
        p = CRCParams(8, 7, 0, False, False, 0)
        payloads = [b"abc", b"abd", b"xyz"]
        samples = [x + bytes([compute_crc(x, p)]) for x in payloads]
        result = discover_checksums(samples)
        found = [h for h in result.hypotheses if h.algorithm == "CRC-8"]
        self.assertTrue(found)
        self.assertEqual(found[0].evidence.location, 3)
        self.assertEqual(found[0].evidence.byte_order, "big")
        self.assertEqual(found[0].evidence.covered_range, (0, 4))

    def test_search_budget_is_explicit(self):
        result = discover_checksums([b"abcdef", b"abcdeg", b"abcdeh"], budget=SearchBudget(max_candidates=1))
        self.assertEqual(result.status, "SEARCH_LIMIT_REACHED")
        result = discover_checksums([b"abcdef", b"abcdeg", b"abcdeh"], budget=SearchBudget(time_limit_seconds=0))
        self.assertEqual(result.status, "TIME_LIMIT_EXCEEDED")

    def test_insufficient_samples_are_not_a_match(self):
        result = discover_checksums([b"abcdef", b"abcdeg"])
        self.assertEqual(result.status, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result.hypotheses, ())

if __name__ == "__main__": unittest.main()
