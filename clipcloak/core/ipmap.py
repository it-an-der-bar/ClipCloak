"""Keyed, class-preserving and prefix-preserving IP address mapping.

* The address class is kept: 10/8 stays in 10/8, 172.16/12 in 172.16/12,
  192.168/16 in 192.168/16, CGNAT, link-local, ULA, global unicast … and
  public addresses stay public.
* Subnet relationships are kept (Crypto-PAn style): two addresses that share
  an n-bit prefix map to addresses that share an n-bit prefix. Hosts of the
  same /24 (IPv4) or /64 (IPv6) therefore end up in the same surrogate subnet.
* Optionally the special host parts .0/.1/.254/.255 (IPv4) and small IPv6
  interface identifiers (::1 … ::ff) are kept, so gateways and broadcast
  addresses stay recognisable.
* The mapping is a bijection and can be inverted, which allows reverting
  addresses an LLM invented inside a known surrogate subnet.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import random

V4_SKIP = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
)]
V4_CLASSES = [(ipaddress.ip_network(n), label) for n, label in (
    ("10.0.0.0/8", "private"), ("172.16.0.0/12", "private"),
    ("192.168.0.0/16", "private"), ("100.64.0.0/10", "cgnat"),
    ("169.254.0.0/16", "linklocal"), ("198.18.0.0/15", "benchmark"),
    ("224.0.0.0/4", "multicast"),
)]

V6_SKIP = [ipaddress.ip_network(n) for n in (
    "::/96", "2001:db8::/32", "ff00::/8",
)]
V6_CLASSES = [(ipaddress.ip_network(n), label) for n, label in (
    ("fe80::/10", "linklocal"), ("fd00::/8", "ula"), ("fc00::/8", "ula"),
    ("2000::/3", "global"),
)]

V4_SPECIAL_LOW = (0, 1, 254, 255)
V6_SMALL_IID = 0x100
MASK64 = (1 << 64) - 1


def is_netmask(addr: ipaddress.IPv4Address) -> bool:
    v = int(addr)
    if v == 0:
        return False
    inv = (~v) & 0xFFFFFFFF
    return (inv & (inv + 1)) == 0 and (v >> 31) == 1


def classify_v4(addr: ipaddress.IPv4Address):
    """Return (network, label) or ``None`` if the address is not mapped."""
    for n in V4_SKIP:
        if addr in n:
            return None
    for n, label in V4_CLASSES:
        if addr in n:
            return n, label
    return ipaddress.ip_network("0.0.0.0/0"), "public"


def classify_v6(addr: ipaddress.IPv6Address):
    for n in V6_SKIP:
        if addr in n:
            return None
    for n, label in V6_CLASSES:
        if addr in n:
            return n, label
    return ipaddress.ip_network("::/0"), "other"


class _PrefixPerm:
    """Crypto-PAn like prefix-preserving permutation on ``width`` bits."""

    def __init__(self, key: bytes, tag: bytes, width: int):
        self.key = key
        self.tag = tag
        self.width = width
        self._cache: dict[tuple[int, int], int] = {}

    def _flip(self, i: int, prefix: int) -> int:
        k = (i, prefix)
        v = self._cache.get(k)
        if v is None:
            msg = self.tag + i.to_bytes(2, "big") + prefix.to_bytes(16, "big")
            v = hmac.new(self.key, msg, hashlib.sha256).digest()[0] & 1
            if len(self._cache) > 200_000:
                self._cache.clear()
            self._cache[k] = v
        return v

    def forward(self, value: int, fixed: int) -> int:
        out = value
        w = self.width
        for i in range(fixed, w):
            prefix = value >> (w - i)
            if self._flip(i, prefix):
                out ^= 1 << (w - 1 - i)
        return out

    def inverse(self, value: int, fixed: int) -> int:
        w = self.width
        orig = value
        for i in range(fixed, w):
            prefix = orig >> (w - i)
            if self._flip(i, prefix):
                orig ^= 1 << (w - 1 - i)
        return orig


class IPMapper:
    def __init__(self, key: bytes, keep_special_hosts: bool = True):
        self.key = key
        self.keep_special = keep_special_hosts
        self._p4 = _PrefixPerm(key, b"ip4-prefix", 24)
        self._p6 = _PrefixPerm(key, b"ip6-prefix", 64)
        self._low4: dict[int, tuple[list[int], dict[int, int]]] = {}

    # ------------------------------------------------------------ IPv4
    def _low_table(self, upper: int):
        t = self._low4.get(upper)
        if t is None:
            seed = hmac.new(self.key, b"ip4-low" + upper.to_bytes(3, "big"), hashlib.sha256).digest()
            rng = random.Random(int.from_bytes(seed, "big"))
            if self.keep_special:
                values = [v for v in range(256) if v not in V4_SPECIAL_LOW]
            else:
                values = list(range(256))
            shuffled = values[:]
            rng.shuffle(shuffled)
            fwd = dict(zip(values, shuffled))
            inv = {b: a for a, b in fwd.items()}
            t = (fwd, inv)
            if len(self._low4) > 50_000:
                self._low4.clear()
            self._low4[upper] = t
        return t

    def _v4_upper_forward(self, upper: int, net, label) -> int:
        fixed = net.prefixlen if label != "public" else 0
        out = self._p4.forward(upper, min(fixed, 24))
        if label == "public":
            while classify_v4(ipaddress.IPv4Address(out << 8)) is None or \
                    classify_v4(ipaddress.IPv4Address(out << 8))[1] != "public":
                out = self._p4.forward(out, 0)
        return out

    def _v4_upper_inverse(self, upper: int, net, label) -> int:
        fixed = net.prefixlen if label != "public" else 0
        orig = self._p4.inverse(upper, min(fixed, 24))
        if label == "public":
            while classify_v4(ipaddress.IPv4Address(orig << 8)) is None or \
                    classify_v4(ipaddress.IPv4Address(orig << 8))[1] != "public":
                orig = self._p4.inverse(orig, 0)
        return orig

    def map_v4(self, addr: ipaddress.IPv4Address) -> ipaddress.IPv4Address | None:
        cls = classify_v4(addr)
        if cls is None:
            return None
        net, label = cls
        v = int(addr)
        upper, low = v >> 8, v & 0xFF
        new_upper = self._v4_upper_forward(upper, net, label)
        if self.keep_special and low in V4_SPECIAL_LOW:
            new_low = low
        else:
            new_low = self._low_table(upper)[0][low]
        return ipaddress.IPv4Address((new_upper << 8) | new_low)

    def unmap_v4(self, addr: ipaddress.IPv4Address) -> ipaddress.IPv4Address | None:
        cls = classify_v4(addr)
        if cls is None:
            return None
        net, label = cls
        v = int(addr)
        upper, low = v >> 8, v & 0xFF
        orig_upper = self._v4_upper_inverse(upper, net, label)
        if self.keep_special and low in V4_SPECIAL_LOW:
            orig_low = low
        else:
            orig_low = self._low_table(orig_upper)[1][low]
        return ipaddress.IPv4Address((orig_upper << 8) | orig_low)

    # ------------------------------------------------------------ IPv6
    def _iid_perm(self, upper: int, iid: int, inverse: bool) -> int:
        """4-round Feistel network on 64 bits keyed by the /64 prefix."""
        def rnd(r: int, half: int) -> int:
            msg = b"ip6-iid" + upper.to_bytes(8, "big") + bytes([r]) + half.to_bytes(4, "big")
            return int.from_bytes(hmac.new(self.key, msg, hashlib.sha256).digest()[:4], "big")

        def once(x: int) -> int:
            left, right = x >> 32, x & 0xFFFFFFFF
            if not inverse:
                for r in range(4):
                    left, right = right, left ^ rnd(r, right)
            else:
                for r in reversed(range(4)):
                    left, right = right ^ rnd(r, left), left
            return (left << 32) | right

        out = once(iid)
        if self.keep_special:
            while out < V6_SMALL_IID:  # cycle walking keeps the bijection
                out = once(out)
        return out

    @staticmethod
    def _same_v6(upper: int, label: str) -> bool:
        c = classify_v6(ipaddress.IPv6Address(upper << 64))
        return c is not None and c[1] == label

    def map_v6(self, addr: ipaddress.IPv6Address) -> ipaddress.IPv6Address | None:
        if addr.ipv4_mapped is not None:
            m = self.map_v4(addr.ipv4_mapped)
            return None if m is None else ipaddress.IPv6Address("::ffff:" + str(m))
        cls = classify_v6(addr)
        if cls is None:
            return None
        net, label = cls
        v = int(addr)
        upper, iid = v >> 64, v & MASK64
        fixed = min(net.prefixlen, 64)
        new_upper = self._p6.forward(upper, fixed)
        # stay out of skip ranges (documentation prefix inside 2000::/3)
        while not self._same_v6(new_upper, label):
            new_upper = self._p6.forward(new_upper, fixed)
        if self.keep_special and iid < V6_SMALL_IID:
            new_iid = iid
        else:
            new_iid = self._iid_perm(upper, iid, inverse=False)
        return ipaddress.IPv6Address((new_upper << 64) | new_iid)

    def unmap_v6(self, addr: ipaddress.IPv6Address) -> ipaddress.IPv6Address | None:
        if addr.ipv4_mapped is not None:
            m = self.unmap_v4(addr.ipv4_mapped)
            return None if m is None else ipaddress.IPv6Address("::ffff:" + str(m))
        cls = classify_v6(addr)
        if cls is None:
            return None
        net, label = cls
        v = int(addr)
        upper, iid = v >> 64, v & MASK64
        fixed = min(net.prefixlen, 64)
        orig_upper = self._p6.inverse(upper, fixed)
        while not self._same_v6(orig_upper, label):
            orig_upper = self._p6.inverse(orig_upper, fixed)
        if self.keep_special and iid < V6_SMALL_IID:
            orig_iid = iid
        else:
            orig_iid = self._iid_perm(orig_upper, iid, inverse=True)
        return ipaddress.IPv6Address((orig_upper << 64) | orig_iid)

    # ------------------------------------------------------------ networks
    def map_network(self, net: ipaddress.IPv4Network | ipaddress.IPv6Network):
        if net.version == 4:
            m = self.map_v4(net.network_address)
        else:
            m = self.map_v6(net.network_address)
        if m is None:
            return None
        return ipaddress.ip_network(f"{m}/{net.prefixlen}", strict=False)

    def unmap_network(self, net):
        if net.version == 4:
            m = self.unmap_v4(net.network_address)
        else:
            m = self.unmap_v6(net.network_address)
        if m is None:
            return None
        return ipaddress.ip_network(f"{m}/{net.prefixlen}", strict=False)
