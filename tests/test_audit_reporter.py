import unittest
from network_audit import AuditReporter
from unittest.mock import MagicMock
import os

class TestAuditReporter(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.get.side_effect = lambda key, default=None: {
            "targets": {"single_ip": "192.168.1.1"},
            "scan_options": {},
            "output": {"format": ["json", "html", "txt"]}
        }.get(key, default)
        self.reporter = AuditReporter(self.config)
        self.sample_hosts = ["192.168.1.1"]
        self.sample_port_results = {
            "192.168.1.1": {
                "open_ports": [{"port": 80, "service": "http", "version": "Apache"}],
                "os": "Linux"
            }
        }
        self.sample_service_results = {
            "192.168.1.1": {
                "web_80": {
                    "url": "http://192.168.1.1:80",
                    "status_code": 200,
                    "headers": {"Server": "Apache"},
                    "server": "Apache",
                    "technologies": ["Apache"]
                }
            }
        }
        self.sample_vulnerabilities = [
            {"host": "192.168.1.1", "description": "Test vuln", "severity": "High", "timestamp": "2024-01-01 00:00:00"}
        ]

    def test_generate_json_report(self):
        self.reporter.collect_all_data(self.sample_hosts, self.sample_port_results, self.sample_service_results, self.sample_vulnerabilities)
        json_file = self.reporter.generate_json_report()
        self.assertTrue(os.path.exists(json_file))
        os.remove(json_file)

    def test_generate_html_report(self):
        self.reporter.collect_all_data(self.sample_hosts, self.sample_port_results, self.sample_service_results, self.sample_vulnerabilities)
        html_file = self.reporter.generate_html_report()
        self.assertTrue(os.path.exists(html_file))
        os.remove(html_file)

    def test_generate_text_report(self):
        self.reporter.collect_all_data(self.sample_hosts, self.sample_port_results, self.sample_service_results, self.sample_vulnerabilities)
        txt_file = self.reporter.generate_text_report()
        self.assertTrue(os.path.exists(txt_file))
        os.remove(txt_file)

if __name__ == "__main__":
    unittest.main()
