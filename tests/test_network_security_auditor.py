import unittest
from unittest.mock import MagicMock, patch
from network_audit import NetworkSecurityAuditor

class TestNetworkSecurityAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = NetworkSecurityAuditor()
        self.auditor.config = MagicMock()
        self.auditor.config.get.side_effect = lambda key, default=None: {
            "targets": {"ip_range": "192.168.1.0/30"},
            "scan_options": {"fast_scan": False, "vulnerability_scan": True},
            "timing": {"timeout": 10}
        }.get(key, default)
        self.auditor.host_discovery = MagicMock()
        self.auditor.port_scanner = MagicMock()
        self.auditor.service_analyzer = MagicMock()
        self.auditor.reporter = MagicMock()

    @patch('time.time', side_effect=[1, 2])
    def test_run_comprehensive_audit(self, mock_time):
        self.auditor.host_discovery.run_discovery.return_value = ["192.168.1.1"]
        self.auditor.port_scanner.scan_hosts.return_value = {"192.168.1.1": {"open_ports": []}}
        self.auditor.service_analyzer.analyze_services.return_value = {"192.168.1.1": {}}
        self.auditor.service_analyzer.vulnerabilities = []
        self.auditor.reporter.generate_all_reports.return_value = ["report.json", "report.html", "report.txt"]

        results = self.auditor.run_comprehensive_audit()

        self.assertIn("hosts", results)
        self.assertIn("ports", results)
        self.assertIn("services", results)
        self.assertIn("vulnerabilities", results)
        self.assertIn("reports", results)
        self.assertIn("duration", results)

if __name__ == "__main__":
    unittest.main()
