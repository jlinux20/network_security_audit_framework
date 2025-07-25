import unittest
import os
import json
from network_audit import Config

class TestConfig(unittest.TestCase):
    def setUp(self):
        self.test_config_file = "test_audit_config.json"
        if os.path.exists(self.test_config_file):
            os.remove(self.test_config_file)

    def tearDown(self):
        if os.path.exists(self.test_config_file):
            os.remove(self.test_config_file)

    def test_create_default_config(self):
        config = Config(self.test_config_file)
        self.assertTrue(os.path.exists(self.test_config_file))
        self.assertIn("targets", config.data)
        self.assertIn("scan_options", config.data)

    def test_get_method(self):
        config = Config(self.test_config_file)
        self.assertEqual(config.get("targets")["single_ip"], "192.168.1.1")
        self.assertEqual(config.get("nonexistent_key", "default"), "default")

    def test_create_directories(self):
        config = Config(self.test_config_file)
        for directory in [
            "reports/json",
            "reports/html",
            "reports/txt",
            "evidence/nmap",
            "evidence/ssl",
            "evidence/web",
            "evidence/vulnerabilities",
            "logs"
        ]:
            self.assertTrue(os.path.exists(directory))

if __name__ == "__main__":
    unittest.main()
