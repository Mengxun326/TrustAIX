"""Detector protocol."""

from typing import Protocol

from trustaix.models import Finding


class Detector(Protocol):
    def detect(self, text: str, location: str) -> list[Finding]:
        """Return the findings present in text."""
