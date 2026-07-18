from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from pathlib import Path
from typing import Any


UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
URL_CREDENTIAL_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@")
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)
IP_TOKEN_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])"
    r"|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----",
    re.DOTALL,
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|authorization|proxy_password)\s*[:=]\s*[^\s,;]+"
)


class Redactor:
    def __init__(self, *, include_network_identifiers: bool = False) -> None:
        self.include_network_identifiers = include_network_identifiers
        self._labels: dict[tuple[str, str], str] = {}
        self.actions: set[str] = set()
        self.home = str(Path.home())

    def _label(self, kind: str, value: str) -> str:
        key = (kind, value.lower())
        if key not in self._labels:
            digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
            self._labels[key] = f"<{kind}-{digest}>"
        return self._labels[key]

    def text(self, value: str) -> str:
        result = PRIVATE_KEY_RE.sub("<private-key-redacted>", value)
        if result != value:
            self.actions.add("private-key")
        value = result
        result = URL_CREDENTIAL_RE.sub(r"\g<scheme><credentials-redacted>@", value)
        if result != value:
            self.actions.add("url-credentials")
        value = result
        result = SENSITIVE_ASSIGNMENT_RE.sub(
            lambda match: f"{match.group(1)}=<redacted>", value
        )
        if result != value:
            self.actions.add("secret-assignment")
        value = result
        if self.home and self.home in value:
            value = value.replace(self.home, "<home>")
            self.actions.add("home-path")
        result = UUID_RE.sub(lambda match: self._label("uuid", match.group(0)), value)
        if result != value:
            self.actions.add("uuid")
        value = result
        if not self.include_network_identifiers:
            def redact_ip(match: re.Match[str]) -> str:
                token = match.group(0)
                try:
                    ipaddress.ip_address(token)
                except ValueError:
                    return token
                return self._label("ip", token)

            result = IP_TOKEN_RE.sub(redact_ip, value)
            if result != value:
                self.actions.add("ip-address")
            value = result
            result = DOMAIN_RE.sub(
                lambda match: self._label("host", match.group(0)), value
            )
            if result != value:
                self.actions.add("domain")
            value = result
        return value

    def value(self, data: Any, *, key: str | None = None) -> Any:
        if isinstance(data, str):
            if key in {"run_id", "observation_id", "schema_version", "plan_id"}:
                return data
            if key == "hostname":
                self.actions.add("hostname")
                return self._label("device", data)
            return self.text(data)
        if isinstance(data, list):
            return [self.value(item) for item in data]
        if isinstance(data, tuple):
            return [self.value(item) for item in data]
        if isinstance(data, dict):
            return {
                child_key: self.value(value, key=child_key)
                for child_key, value in data.items()
            }
        return data
