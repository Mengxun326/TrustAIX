"""Content transformations that remove sensitive values before release or forwarding."""

from typing import Any

from trustaix.detectors.sensitive_data import SensitiveDataDetector

_sensitive_data_detector = SensitiveDataDetector()


def redact_text(text: str) -> str:
    return _sensitive_data_detector.redact(text)


def redact_content(content: str | list[dict[str, Any]] | None) -> str | list[dict[str, Any]] | None:
    """Redact text strings while retaining non-text multimodal content unchanged."""
    if isinstance(content, str):
        return redact_text(content)
    if not isinstance(content, list):
        return content

    redacted: list[dict[str, Any]] = []
    for part in content:
        copy = part.copy()
        if copy.get("type") == "text" and isinstance(copy.get("text"), str):
            copy["text"] = redact_text(copy["text"])
        redacted.append(copy)
    return redacted


def text_from_content(content: str | list[dict[str, Any]] | None) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(
        part["text"]
        for part in content
        if part.get("type") == "text" and isinstance(part.get("text"), str)
    )
