"""Detector registry."""

from __future__ import annotations

from .base import Detector, DetectorContext
from .identity import (CardDetector, CustomTermDetector, IbanDetector, PhoneDetector,
                       SidDetector, UserPathDetector)
from .infra import InfraNameDetector
from .network import (DomainDetector, EmailDetector, HostnameDetector, IPv4Detector,
                      IPv6Detector, MacDetector)
from .secrets import EntropyDetector, KeyValueSecretDetector, PemDetector, TokenDetector

BUILTIN_DETECTORS: list[type[Detector]] = [
    PemDetector, TokenDetector, KeyValueSecretDetector, EntropyDetector,
    EmailDetector, IPv4Detector, IPv6Detector, MacDetector, DomainDetector,
    HostnameDetector, UserPathDetector, IbanDetector, CardDetector, PhoneDetector,
    SidDetector, InfraNameDetector, CustomTermDetector,
]


def builtin_detectors() -> list[Detector]:
    return [cls() for cls in BUILTIN_DETECTORS]


__all__ = ["Detector", "DetectorContext", "BUILTIN_DETECTORS", "builtin_detectors"]
