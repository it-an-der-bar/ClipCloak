import ipaddress
import os
import random
import unittest

from clipcloak.core.ipmap import IPMapper, classify_v4, classify_v6, is_netmask


class IPMapTest(unittest.TestCase):
    def setUp(self):
        self.m = IPMapper(os.urandom(32))
        self.rnd = random.Random(42)

    def test_v4_roundtrip_and_class(self):
        for _ in range(5000):
            a = ipaddress.IPv4Address(self.rnd.getrandbits(32))
            b = self.m.map_v4(a)
            if b is None:
                self.assertIsNone(classify_v4(a))
                continue
            self.assertEqual(classify_v4(a)[1], classify_v4(b)[1], (a, b))
            self.assertEqual(self.m.unmap_v4(b), a)

    def test_v4_private_stays_private(self):
        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
            n = ipaddress.ip_network(net)
            for _ in range(200):
                a = n.network_address + self.rnd.randrange(n.num_addresses)
                self.assertIn(self.m.map_v4(a), n)

    def test_v4_subnet_preserved(self):
        hosts = [self.m.map_v4(ipaddress.IPv4Address(f"10.88.10.{i}")) for i in range(2, 250)]
        nets = {ipaddress.ip_network(f"{h}/24", strict=False) for h in hosts}
        self.assertEqual(len(nets), 1)
        self.assertEqual(len(set(hosts)), len(hosts))
        other = self.m.map_v4(ipaddress.IPv4Address("10.88.11.5"))
        a16 = ipaddress.ip_network(f"{hosts[0]}/16", strict=False)
        self.assertIn(other, a16)                       # same /16 as before
        self.assertNotIn(other, nets.pop())              # but other /24

    def test_v4_special_hosts(self):
        for last in (0, 1, 254, 255):
            b = self.m.map_v4(ipaddress.IPv4Address(f"192.168.77.{last}"))
            self.assertEqual(int(b) & 0xFF, last)

    def test_v4_without_special(self):
        m = IPMapper(os.urandom(32), keep_special_hosts=False)
        for _ in range(500):
            a = ipaddress.IPv4Address(self.rnd.getrandbits(32))
            b = m.map_v4(a)
            if b is not None:
                self.assertEqual(m.unmap_v4(b), a)

    def test_v6_roundtrip_and_class(self):
        samples = [ipaddress.IPv6Address(self.rnd.getrandbits(128)) for _ in range(500)]
        samples += [ipaddress.IPv6Address(f"2a01:4f8:{self.rnd.getrandbits(16):x}::{self.rnd.getrandbits(16):x}") for _ in range(300)]
        samples += [ipaddress.IPv6Address(f"fe80::{self.rnd.getrandbits(16):x}:{self.rnd.getrandbits(16):x}") for _ in range(200)]
        samples += [ipaddress.IPv6Address(f"fd12:3456::{self.rnd.getrandbits(16):x}") for _ in range(200)]
        for a in samples:
            b = self.m.map_v6(a)
            if b is None:
                continue
            self.assertEqual(classify_v6(a)[1], classify_v6(b)[1], (a, b))
            self.assertEqual(self.m.unmap_v6(b), a)

    def test_v6_prefix_and_small_iid(self):
        a = self.m.map_v6(ipaddress.IPv6Address("2a01:4f8:1:2::1"))
        b = self.m.map_v6(ipaddress.IPv6Address("2a01:4f8:1:2::abcd"))
        self.assertEqual(int(a) >> 64, int(b) >> 64)
        self.assertEqual(int(a) & 0xFFFF, 1)

    def test_v4_mapped_v6(self):
        a = ipaddress.IPv6Address("::ffff:10.1.2.3")
        b = self.m.map_v6(a)
        self.assertIsNotNone(b.ipv4_mapped)
        self.assertIn(b.ipv4_mapped, ipaddress.ip_network("10.0.0.0/8"))
        self.assertEqual(self.m.unmap_v6(b), a)

    def test_skip_ranges(self):
        for s in ("127.0.0.1", "0.0.0.0", "192.0.2.5", "255.255.255.255"):
            self.assertIsNone(self.m.map_v4(ipaddress.IPv4Address(s)))
        for s in ("::1", "2001:db8::1", "ff02::1"):
            self.assertIsNone(self.m.map_v6(ipaddress.IPv6Address(s)))

    def test_network(self):
        n = ipaddress.ip_network("10.88.0.0/16")
        mn = self.m.map_network(n)
        self.assertEqual(mn.prefixlen, 16)
        self.assertIn(self.m.map_v4(ipaddress.IPv4Address("10.88.200.7")), mn)
        self.assertEqual(self.m.unmap_network(mn), n)

    def test_netmask(self):
        self.assertTrue(is_netmask(ipaddress.IPv4Address("255.255.255.0")))
        self.assertTrue(is_netmask(ipaddress.IPv4Address("255.255.240.0")))
        self.assertFalse(is_netmask(ipaddress.IPv4Address("255.0.255.0")))
        self.assertFalse(is_netmask(ipaddress.IPv4Address("10.0.0.1")))

    def test_deterministic_per_key(self):
        key = os.urandom(32)
        a = ipaddress.IPv4Address("85.10.20.30")
        self.assertEqual(IPMapper(key).map_v4(a), IPMapper(key).map_v4(a))


if __name__ == "__main__":
    unittest.main()
