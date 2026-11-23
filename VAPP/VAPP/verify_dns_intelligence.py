import unittest
from unittest.mock import Mock, patch

import dns.exception
import dns.resolver

from dns_intelligence import inspect_domain_dns


class DNSIntelligenceTests(unittest.TestCase):

    @patch("dns_intelligence.dns.resolver.Resolver")
    def test_public_ipv4_and_ipv6(self, resolver_class):
        resolver = resolver_class.return_value
        resolver.resolve.side_effect = [
            [Mock(address="93.184.216.34")],
            [Mock(address="2606:2800:220:1:248:1893:25c8:1946")],
        ]

        result = inspect_domain_dns("example.com")

        self.assertEqual(result["dns_status"], "RESOLVED")
        self.assertEqual(len(result["resolved_ips"]), 2)

    @patch("dns_intelligence.dns.resolver.Resolver")
    def test_private_destination_blocked(self, resolver_class):
        resolver = resolver_class.return_value
        resolver.resolve.side_effect = [
            [Mock(address="127.0.0.1")],
            dns.resolver.NoAnswer(),
        ]

        result = inspect_domain_dns("localhost")

        self.assertEqual(result["dns_status"], "BLOCKED_DESTINATION")

    @patch("dns_intelligence.dns.resolver.Resolver")
    def test_nonexistent_domain(self, resolver_class):
        resolver = resolver_class.return_value
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        result = inspect_domain_dns("nonexistent.invalid")

        self.assertEqual(result["dns_status"], "UNRESOLVED")

    @patch("dns_intelligence.dns.resolver.Resolver")
    def test_dns_timeout(self, resolver_class):
        resolver = resolver_class.return_value
        resolver.resolve.side_effect = dns.exception.Timeout()

        result = inspect_domain_dns("slow.example")

        self.assertEqual(result["dns_status"], "UNKNOWN")
        self.assertTrue(
            any("timed out" in item for item in result["findings"])
        )

    def test_empty_hostname(self):
        result = inspect_domain_dns("")

        self.assertEqual(result["dns_status"], "INVALID")
        self.assertEqual(result["resolved_ips"], [])

    def test_public_resolution_is_not_safety_verdict(self):
        with patch("dns_intelligence.dns.resolver.Resolver") as resolver_class:
            resolver = resolver_class.return_value
            resolver.resolve.side_effect = [
                [Mock(address="93.184.216.34")],
                dns.resolver.NoAnswer(),
            ]

            result = inspect_domain_dns("example.com")

        self.assertTrue(
            any("does not establish domain safety" in item
                for item in result["findings"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
