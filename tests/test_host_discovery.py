import unittest
from unittest.mock import patch, MagicMock
from network_audit import HostDiscovery, NetworkUtils

class TestHostDiscovery(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.get.return_value = 10
        self.host_discovery = HostDiscovery(self.config)

    @patch('subprocess.run')
    def test_ping_sweep(self, mock_run):
        mock_run.return_value.returncode = 0
        live_hosts = self.host_discovery.ping_sweep("192.168.1.0/30")
        self.assertIn("192.168.1.1", live_hosts)

    @patch('subprocess.run')
    def test_nmap_host_discovery(self, mock_run):
        mock_run.return_value.stdout = "Nmap scan report for 192.168.1.1\nHost is up"
        self.host_discovery.nmap_host_discovery("192.168.1.0/30")
        self.assertIn("192.168.1.1", self.host_discovery.results["live_hosts"])

    def test_run_discovery_invalid_ip(self):
        hosts = self.host_discovery.run_discovery("invalid_ip")
        self.assertEqual(hosts, [])

if __name__ == "__main__":
    unittest.main()
