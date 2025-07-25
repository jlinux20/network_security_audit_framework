import unittest
from unittest.mock import patch, MagicMock
from network_audit import ServiceAnalyzer

class TestServiceAnalyzer(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.get.return_value = True
        self.service_analyzer = ServiceAnalyzer(self.config)

    @patch('subprocess.run')
    @patch('requests.get')
    def test_analyze_web_services(self, mock_get, mock_run):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'Apache',
            'X-Powered-By': 'PHP/7.4'
        }
        mock_get.return_value = mock_response
        mock_run.return_value.stdout = "WhatWeb scan result"
        self.service_analyzer.analyze_web_services("192.168.1.1", 80)
        self.assertIn("192.168.1.1", self.service_analyzer.results)

    @patch('subprocess.run')
    def test_vulnerability_scan(self, mock_run):
        mock_run.return_value.stdout = "VULNERABLE: Example vulnerability"
        self.service_analyzer.vulnerability_scan("192.168.1.1")
        self.assertTrue(any("VULNERABLE" in v["description"] for v in self.service_analyzer.vulnerabilities))

if __name__ == "__main__":
    unittest.main()
