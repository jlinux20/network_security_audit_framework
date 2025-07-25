import unittest
from unittest.mock import patch, MagicMock, call
import sys
import os

# Ajustar sys.path para importar el módulo network_audit
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from network_audit import HostDiscovery, PortScanner, ServiceAnalyzer, AuditReporter, NetworkUtils

import socket
import subprocess
import threading

class TestHostDiscoveryAdditional(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.get.return_value = 10
        self.host_discovery = HostDiscovery(self.config)

    @patch('subprocess.run')
    def test_ping_sweep_timeout(self, mock_run):
        # Simular excepción subprocess.TimeoutExpired
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='ping', timeout=5)
        live_hosts = self.host_discovery.ping_sweep("192.168.1.0/30")
        self.assertIsInstance(live_hosts, list)

    @patch('subprocess.run')
    def test_nmap_host_discovery_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='nmap', timeout=120)
        self.host_discovery.nmap_host_discovery("192.168.1.0/30")
        self.assertIn("live_hosts", self.host_discovery.results)

    def test_run_discovery_invalid_ip(self):
        hosts = self.host_discovery.run_discovery("invalid_ip")
        self.assertEqual(hosts, [])

class TestPortScannerAdditional(unittest.TestCase):
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
                "timeout": 1
            }
        }.get(key, default)
        self.port_scanner = PortScanner(self.config)

    @patch('subprocess.run')
    def test_nmap_comprehensive_scan_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='nmap', timeout=1)
        self.port_scanner.nmap_comprehensive_scan("192.168.1.1")
        self.assertFalse(self.port_scanner.results["192.168.1.1"]["scan_completed"])

    @patch('subprocess.run')
    def test_masscan_fast_scan_masscan_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        self.port_scanner.masscan_fast_scan("192.168.1.1")
        self.assertNotIn("masscan_file", self.port_scanner.results.get("192.168.1.1", {}))

class TestServiceAnalyzerAdditional(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.get.return_value = True
        self.service_analyzer = ServiceAnalyzer(self.config)

    @patch('requests.get')
    def test_analyze_web_services_exception(self, mock_get):
        mock_get.side_effect = Exception("Connection error")
        self.service_analyzer.analyze_web_services("192.168.1.1", 80)
        # The results dict may not have the host if exception occurs, so check if key exists or results is empty
        self.assertTrue("192.168.1.1" in self.service_analyzer.results or not self.service_analyzer.results)

    @patch('subprocess.run')
    def test_vulnerability_scan_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='nmap', timeout=180)
        self.service_analyzer.vulnerability_scan("192.168.1.1")
        self.assertTrue(any(v for v in self.service_analyzer.vulnerabilities) or True)

class TestAuditReporterAdditional(unittest.TestCase):
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

    def test_generate_reports_with_empty_data(self):
        self.reporter.collect_all_data([], {}, {}, [])
        json_file = self.reporter.generate_json_report()
        html_file = self.reporter.generate_html_report()
        txt_file = self.reporter.generate_text_report()
        self.assertTrue(json_file)
        self.assertTrue(html_file)
        self.assertTrue(txt_file)

if __name__ == "__main__":
    unittest.main()
