import unittest
from unittest.mock import patch, MagicMock
from network_audit import PortScanner

class TestPortScanner(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.get.side_effect = lambda key, default=None: {
            "scan_options": {
                "stealth_scan": True,
                "service_detection": True,
                "os_detection": True,
                "aggressive_scan": False,
                "top_ports": 1000,
                "port_range": "1-1000",
                "fast_scan": False
            },
            "timing": {
                "timeout": 10
            }
        }.get(key, default)
        self.port_scanner = PortScanner(self.config)

    @patch('subprocess.run')
    def test_nmap_comprehensive_scan(self, mock_run):
        mock_run.return_value.stdout = "22/tcp open ssh OpenSSH"
        mock_run.return_value.returncode = 0
        self.port_scanner.nmap_comprehensive_scan("192.168.1.1")
        self.assertIn("192.168.1.1", self.port_scanner.results)
        self.assertTrue(self.port_scanner.results["192.168.1.1"]["scan_completed"])
        self.assertIn("open_ports", self.port_scanner.results["192.168.1.1"])

if __name__ == "__main__":
    unittest.main()
