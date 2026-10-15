import tempfile
import unittest
from pathlib import Path

from packetscope.analysis import analyze_packets
from packetscope.models import Limits, Packet
from packetscope.profiles import (
    BUILTIN_PROFILES,
    dump_profile,
    limits_for_profile,
    migrate_profile,
    resolve_profile,
    validate_profile,
)


class ProfileTests(unittest.TestCase):
    def test_builtin_profiles_are_explicit_and_fingerprinted(self):
        self.assertEqual(set(BUILTIN_PROFILES), {"default", "fast", "deep"})
        self.assertNotEqual(BUILTIN_PROFILES["fast"].fingerprint, BUILTIN_PROFILES["deep"].fingerprint)
        self.assertLess(BUILTIN_PROFILES["fast"].maximum_samples, BUILTIN_PROFILES["deep"].maximum_samples)
        self.assertEqual(BUILTIN_PROFILES["fast"].as_dict()["ranking_options"]["confidence_label"], "heuristic")

    def test_profile_json_round_trip_migration_and_validation(self):
        old = migrate_profile({"profile_id": "old"})
        profile = validate_profile(old)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            dump_profile(profile, path)
            loaded = resolve_profile(str(path))
        self.assertEqual(loaded.as_dict(), profile.as_dict())
        with self.assertRaises(ValueError):
            validate_profile({"schema_version": 99})

    def test_profile_changes_budgets_and_report_has_reproducibility_identity(self):
        profile = resolve_profile("fast")
        limits = limits_for_profile(Limits(), profile)
        result = analyze_packets([Packet(i, bytes([0xAA, i, 0x03])) for i in range(3)], limits=limits,
                                 profile=profile, input_sha256="a" * 64)
        self.assertEqual(result["reproducibility"]["input_sha256"], "a" * 64)
        self.assertEqual(result["reproducibility"]["profile_fingerprint"], profile.fingerprint)
        self.assertEqual(result["reproducibility"]["profile"]["profile_id"], "fast")
        self.assertEqual(result["analysis"]["crc_candidates_tested"], result["reproducibility"]["candidates_evaluated"])


if __name__ == "__main__":
    unittest.main()
