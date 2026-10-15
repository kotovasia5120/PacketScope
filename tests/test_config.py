import os
import unittest
from unittest import mock

from packetscope import __version__
from packetscope.config import DeploymentConfig, deployment_from_env, resolve_deployment_mode
from packetscope.models import Limits
from packetscope.profiles import PACKETSCOPE_VERSION
from packetscope.web import PacketScopeHandler


class ConfigurationTests(unittest.TestCase):
    def test_local_is_the_default_and_upload_budget_matches_retention_budget(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_deployment_mode(), "local")
            self.assertEqual(deployment_from_env().mode, "local")
        limits = Limits()
        self.assertEqual(limits.max_input_bytes, limits.max_job_payload_bytes)
        self.assertTrue(DeploymentConfig("local").local_only)

    def test_public_mode_is_explicit_and_version_metadata_agrees(self):
        self.assertEqual(resolve_deployment_mode("public_demo"), "public-demo")
        config = DeploymentConfig("public-demo")
        self.assertFalse(config.local_only)
        self.assertIn("transmitted", config.privacy_notice)
        self.assertEqual(__version__, PACKETSCOPE_VERSION)
        self.assertEqual(PacketScopeHandler.server_version, "PacketScope/" + __version__)

    def test_invalid_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_deployment_mode("private-cloud")


if __name__ == "__main__":
    unittest.main()
