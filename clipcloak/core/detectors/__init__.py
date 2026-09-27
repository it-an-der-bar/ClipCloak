"""Detector registry."""

from __future__ import annotations

from .base import Detector, DetectorContext
from .identity import (CardDetector, CustomTermDetector, IbanDetector, PhoneDetector,
                       SidDetector, UserPathDetector)
from .fingerprints import FingerprintDetector
from .infra import InfraNameDetector
from .tracking import TrackingDetector
from .network import (DomainDetector, EmailDetector, HostnameDetector, IPv4Detector,
                      IPv6Detector, MacDetector)
from .secrets import EntropyDetector, HexSecretDetector, KeyValueSecretDetector, PemDetector, TokenDetector

BUILTIN_DETECTORS: list[type[Detector]] = [
    PemDetector, TokenDetector, KeyValueSecretDetector, HexSecretDetector, EntropyDetector,
    EmailDetector, IPv4Detector, IPv6Detector, MacDetector, DomainDetector,
    HostnameDetector, UserPathDetector, IbanDetector, CardDetector, PhoneDetector,
    SidDetector, InfraNameDetector, FingerprintDetector, TrackingDetector,
    CustomTermDetector,
]


def builtin_detectors() -> list[Detector]:
    return [cls() for cls in BUILTIN_DETECTORS]


__all__ = ["Detector", "DetectorContext", "BUILTIN_DETECTORS", "builtin_detectors"]
