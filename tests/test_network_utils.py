import unittest
from network_audit import NetworkUtils

class TestNetworkUtils(unittest.TestCase):
    def test_validate_ip(self):
        self.assertTrue(NetworkUtils.validate_ip("192.168.1.1"))
        self.assertFalse(NetworkUtils.validate_ip("999.999.999.999"))
        self.assertFalse(NetworkUtils.validate_ip("invalid_ip"))

    def test_validate_network(self):
        self.assertTrue(NetworkUtils.validate_network("192.168.1.0/24"))
        self.assertFalse(NetworkUtils.validate_network("192.168.1.0/33"))
        self.assertFalse(NetworkUtils.validate_network("invalid_network"))

    def test_get_network_hosts(self):
        hosts = NetworkUtils.get_network_hosts("192.168.1.0/30")
        expected_hosts = ["192.168.1.1", "192.168.1.2"]
        self.assertEqual(hosts, expected_hosts)

    def test_is_port_open(self):
        # This test assumes localhost port 80 is closed or open; we just check it returns a boolean
        result = NetworkUtils.is_port_open("127.0.0.1", 80)
        self.assertIsInstance(result, bool)

if __name__ == "__main__":
    unittest.main()
