from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import struct
import tempfile
import unicodedata
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote_plus, urlsplit

from . import BUNDLE_SCHEMA_VERSION
from .models import DiagnosticBundle, load_bundle, utc_now, validate_bundle_data
from .redaction import PUBLIC_VANTAGE_POINTS, Redactor
from .report import render_report
from .util import open_regular_binary, parse_json_strict


def _json_bytes(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


_ARCHIVE_MEMBERS = {"bundle.json", "report.md", "manifest.json"}
_MANIFEST_KEYS = {
    "format",
    "format_version",
    "created_at",
    "source_schema_version",
    "network_identifiers_included",
    "redactions",
    "files",
}
_CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")
_MEMBER_SIZE_LIMITS = {
    "bundle.json": 32 * 1024 * 1024,
    "report.md": 8 * 1024 * 1024,
    "manifest.json": 64 * 1024,
}
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_ZIP_EOCD_MAGIC = b"PK\x05\x06"
_ZIP_LOCAL_MAGIC = b"PK\x03\x04"
_MAX_ARCHIVE_BYTES = 48 * 1024 * 1024
_MAX_CENTRAL_DIRECTORY_BYTES = 16 * 1024
_NETWORK_VALUE_KEYS = {
    "address",
    "config_host",
    "domain",
    "endpoint",
    "host",
    "host_alias",
    "hostname",
    "ip",
    "local_host",
    "management_address",
    "management_reference",
    "panel_reference",
    "public_ip",
    "remote_host",
    "remote_address",
    "resolver",
    "server",
    "server_alias",
    "ssh_host",
    "target",
    "target_host",
    "vantage_point",
    "vantage_points",
}
_REDACTED_NETWORK_RE = re.compile(
    r"^<(?:device|host|ip|mac)-(?:[0-9a-f]{8}|[0-9a-f]{12})>$"
)
_HOST_KEYED_MAPPING_RE = re.compile(
    r"(?:_by_(?:host|server|target|endpoint|address|ip|domain|resolver|peer|"
    r"node|router|gateway|hop|device)s?"
    r"|^(?:hosts|servers|targets|endpoints|addresses|ips|domains|resolvers|peers|"
    r"nodes|routers|gateways|hops|devices))$"
)
_MAC_RE = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){7}[0-9a-f]{2}(?![0-9a-f:-])"
    r"|(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f:-])"
    r"|(?<![0-9a-f])(?:[0-9a-f]{4}\.){3}[0-9a-f]{4}(?![0-9a-f.])"
    r"|(?<![0-9a-f])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?![0-9a-f.])"
)
_IP_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]{2,}"
    r"(?![0-9A-Fa-f:.])"
    r"|(?<![0-9A-Fa-f:.])(?:\d{1,10}\.){1,3}\d{1,10}\.?(?![0-9.])"
)
_DOMAIN_RE = re.compile(
    r"(?<![\w-])(?:[^\W_](?:[\w-]{0,61}[^\W_])?\.)+"
    r"[^\W_](?:[\w-]{0,61}[^\W_])?(?![\w-])",
    re.UNICODE,
)
_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>\"']+")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SINGLE_LABEL_HOST_CONTEXT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>"
    r"\b(?:remote-server|remote[_-]?host|local[_-]?host|hostname|host|server|"
    r"target|peer|resolver)\s*[:=]\s*"
    r"|\b(?:connect(?:ed|ing)?\s+to\s+|connection\s+to\s+|dial(?:ed|ing)?\s+|"
    r"resolv(?:ed|ing)?\s+)"
    r")"
    r"[\"']?"
    r"(?P<host>[\w.-]{1,253})"
    r"[\"']?"
    r"(?=$|[\s,;)\]}/]|:\d{1,5}\b)"
)
_UNC_HOST_RE = re.compile(
    r"(?<!\\)\\\\(?P<host>[\w.-]{1,253})(?=\\)"
)
_USER_AT_SINGLE_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}@"
    r"(?P<host>[\w.-]{1,253})(?=$|[:\s,;)\]}/])"
)
_REMOTE_COMMAND_HOST_RE = re.compile(
    r"(?i)\b(?:ssh|sftp)\s+"
    r"(?:(?:-[46AaCfgKkMNnqsTtVvXxYy]+\s+)|"
    r"(?:-(?:B|b|c|D|E|e|F|I|i|J|L|l|m|O|o|p|Q|R|S|W|w)"
    r"(?:\s+|=)?[^\s;&|]+\s+))*"
    r"(?P<host>[\w.-]{1,253})(?=$|[:\s])"
)
_REMOTE_COPY_HOST_RE = re.compile(
    r"(?i)\b(?:scp|rsync)\b[^\r\n;&|]*?\s"
    r"(?P<host>[\w.-]{1,253})(?=:)"
)
_SSH_OPTION_HOST_RE = re.compile(
    r"(?i)(?:-J\s*|-o\s*(?:ProxyJump|HostName)\s*=\s*)"
    r"(?P<host>[\w.-]{1,253})(?=$|[,\s])"
)
_NETWORK_COMMAND_HOST_RE = re.compile(
    r"(?i)\b(?:ping|traceroute|tracepath|dig|nslookup|telnet|nc|curl|wget)\b"
    r"[^\r\n;&|]*?\s(?P<host>[\w.-]{1,253})"
    r"(?=:\d{1,5}(?:/|\s|$)|/|\s+\d{1,5}\s*(?:$|[;&|])|"
    r"\s*(?:$|[;&|]))"
)
_RESIDUAL_NETWORK_COMMAND_LINE_RE = re.compile(
    r"(?im)\b(?:ssh|scp|sftp|rsync|ping|traceroute|tracert|pathping|tracepath|"
    r"dig|nslookup|telnet|nc|curl|wget)(?:\.exe)?(?=\s|$)[^\r\n]*"
    r"|\b(?:Resolve-DnsName|Test-NetConnection|Test-Connection|powershell|pwsh)"
    r"(?:\.exe)?(?=\s|$)[^\r\n]*"
)
_LEGACY_INTEGER_IP_CONTEXT_RE = re.compile(
    r"(?ix)\b(?:ip|address|host|target|server|resolver|gateway|remote|peer)"
    r"\s*[:=]\s*[\"']?"
    r"(?P<ip>0x[0-9a-f]{1,8}|0[0-7]{8,11}|[0-9]{8,10})"
    r"[\"']?(?![0-9a-f])"
)
_RESIDUAL_PROVIDER_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|"
    r"sk-(?:[A-Za-z0-9]{28,}|(?:proj|svcacct|ant-api03|or-v1)-[A-Za-z0-9_-]{16,})|"
    r"(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{8,}|glpat-[A-Za-z0-9_-]{16,}|"
    r"(?:sk|rk)_live_[A-Za-z0-9]{12,}|AIza[0-9A-Za-z_-]{30,}|"
    r"npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{32,}|"
    r"(?:dop|doo|dor)_v1_[a-fA-F0-9]{48,}|hf_[A-Za-z0-9]{16,}|"
    r"ya29\.[A-Za-z0-9_-]{16,}|"
    r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"
    r")(?![A-Za-z0-9_-])"
)
_RESIDUAL_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-\n]*PRIVATE KEY-----", re.IGNORECASE
)
_RESIDUAL_BEARER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])Bearer\s+[A-Za-z0-9._~+/=-]+"
)
_RESIDUAL_BASIC_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])Basic\s+(?P<token>[A-Za-z0-9+/]{2,}={0,2})"
    r"(?![A-Za-z0-9+/=])"
)
_RESIDUAL_CLI_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:sshpass\s+(?:-p|--password)|"
    r"curl\s+(?:[^\r\n]*?\s)?(?:-u|--user))\s+"
    r"(?!<redacted>)(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s;&|]+)"
)
_RESIDUAL_COMMAND_CREDENTIAL_RE = re.compile(
    r"(?ix)(?:"
    r"\bsshpass\b[^\r\n;&|]*?(?:-p(?:\s*=\s*|\s*)|"
    r"--password(?:\s*=\s*|\s+))"
    r"(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s;&|]+)|"
    r"\bcurl\b[^\r\n;&|]*?(?:-u(?:\s*=\s*|\s*)|"
    r"--(?:proxy-)?user(?:\s*=\s*|\s+))"
    r"(?:\"[^\"\r\n]*:[^\"\r\n]+\"|'[^'\r\n]*:[^'\r\n]+'|"
    r"[^\s;&|]*:[^\s;&|]+)|"
    r"\bhttp\b[^\r\n;&|]*?--auth(?:\s*=\s*|\s+)"
    r"(?:\"[^\"\r\n]*:[^\"\r\n]+\"|'[^'\r\n]*:[^'\r\n]+'|"
    r"[^\s;&|]*:[^\s;&|]+)|"
    r"\bmysql\b[^\r\n;&|]*?(?:-p(?=[^\s])|--password\s*=\s*)"
    r"(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s;&|]+)"
    r")"
)
_RESIDUAL_LONG_OPTION_CREDENTIAL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])--(?:password|passwd|passphrase|token|"
    r"api[-_]?key|client[-_]?secret|secret|authorization|credential|"
    r"private[-_]?key)(?:\s*=\s*|\s+)(?!<redacted>)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;&|]+)"
)
_RESIDUAL_SPACE_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:password|passwd|passphrase|token|api[-_]?key|"
    r"client[-_]?secret)\s+(?!<redacted>)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;&|]+)"
)
_RESIDUAL_SHORT_OPTION_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:redis-cli|mongosh|mysqladmin)\b[^\r\n;&|]*?"
    r"(?:-a|-p)\s+(?!<redacted>)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;&|]+)"
)
_RESIDUAL_CURL_SECRET_OPTION_RE = re.compile(
    r"(?im)\bcurl(?:\.exe)?(?=\s|$)"
    r"(?=[^\r\n]*(?<![A-Za-z0-9_-])(?:"
    r"-b|--cookie|--oauth2-bearer|--cert|--proxy-cert|--pass|"
    r"--tlspassword|--proxy-tlspassword)(?=\s|=))[^\r\n]*"
)
_RESIDUAL_SENSITIVE_COMMAND_LINE_RE = re.compile(
    r"(?im)(?:"
    r"\bnet(?:\.exe)?\s+use\b(?=[^\r\n]*/user\s*:)[^\r\n]*|"
    r"\bcmdkey(?:\.exe)?\b(?=[^\r\n]*/pass\s*:)[^\r\n]*|"
    r"\bdocker(?:\.exe)?\s+login\b(?=[^\r\n]*(?:^|\s)(?:-p|--password)(?=\s|=))[^\r\n]*|"
    r"\baz(?:\.exe)?\s+login\b(?=[^\r\n]*(?:^|\s)(?:-p|--password)(?=\s|=))[^\r\n]*|"
    r"\b(?:pscp|plink)(?:\.exe)?\b(?=[^\r\n]*(?:^|\s)-pw(?=\s|=))[^\r\n]*|"
    r"\baws(?:\.exe)?\s+configure\s+set\s+"
    r"(?:aws_)?(?:secret_access_key|session_token|access_token|password)\b[^\r\n]*|"
    r"\bopenssl(?:\.exe)?\s+pkcs12\b(?=[^\r\n]*-pass(?:in|out)(?=\s|:|=))[^\r\n]*|"
    r"\bsmbclient\b(?=[^\r\n]*(?:^|\s)-U\s+[^\s\r\n]*%[^\s\r\n]+)[^\r\n]*|"
    r"\bPGPASSWORD(?:\s*=\s*|\s+)(?!<redacted>)[^\s;&|]+"
    r"(?=[^\r\n]*\bpsql\b)[^\r\n]*"
    r")"
)
_RESIDUAL_SECRET_URL_RE = re.compile(
    r"(?ix)https?://(?:"
    r"hooks\.slack\.com/services/(?:[^/\s?#]+/){2}[^/\s?#]+|"
    r"(?:discord\.com|discordapp\.com)/api(?:/v[0-9]+)?/webhooks/"
    r"[^/\s?#]+/(?!<webhook-redacted>)[^/\s?#]+|"
    r"api\.telegram\.org/bot(?!<token-redacted>)[^/\s?#]+"
    r")"
)
_RESIDUAL_RELATIVE_PROVIDER_PATH_RE = re.compile(
    r"(?ix)(?<![A-Za-z0-9:/])(?:"
    r"/services/(?:[^/\s?#]+/){2}(?!<webhook-redacted>)[^/\s?#]+|"
    r"/api(?:/v[0-9]+)?/webhooks/[^/\s?#]+/"
    r"(?!<webhook-redacted>)[^/\s?#]+|"
    r"/bot[0-9]{3,}(?::|%3a)(?!<token-redacted>)[A-Za-z0-9_-]{8,}"
    r")"
)
_RESIDUAL_SECRET_URL_PARAMETER_RE = re.compile(
    r"(?i)[?&#;](?:auth|authorization|code|cookie|key|password|passwd|"
    r"passphrase|sas|secret|session|sig|signature|token|"
    r"api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|"
    r"client[-_]?secret|private[-_]?key|x-amz-signature|x-goog-signature|"
    r"x-goog-credential|x-amz-credential|x-amz-security-token)="
    r"(?!<redacted>(?:[&#;]|$)|%3Credacted%3E(?:[&#;]|$))[^&#;\s]+"
)
_RESIDUAL_PUTTY_KEY_RE = re.compile(
    r"(?im)^PuTTY-User-Key-File-\d+:[^\r\n]*$"
)
_RESIDUAL_NODE_LINK_RE = re.compile(
    r"(?i)\b(?:anytls|hysteria2?|hy2|juicity|mieru|shadowtls|snell|ss|ssr|"
    r"trojan|tuic|vless|vmess|wg|wireguard)://[^\s<>\"']+"
)
_RESIDUAL_URL_USERINFO_RE = re.compile(
    r"(?:[A-Za-z][A-Za-z0-9+.-]*://|(?<![A-Za-z0-9:/])/{1,2})"
    r"[^/@\s:]+:[^/@\s]+@"
)
_RESIDUAL_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:auth|authorization|credential|credentials|password|passwd|"
    r"passphrase|secret|session|token|api[_-]?key|account[_-]?key|"
    r"aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|"
    r"azure[_-]?storage[_-]?key|shared[_-]?access[_-]?(?:key|signature)|sshpass|"
    r"pgpassword|mysql[_-]?pwd|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*"
    r"(?!<redacted>)[^\s,;&]+"
)


def _string_has_residual_credential_once(value: str) -> bool:
    if any(
        pattern.search(value)
        for pattern in (
            _RESIDUAL_PROVIDER_TOKEN_RE,
            _RESIDUAL_PRIVATE_KEY_RE,
            _RESIDUAL_PUTTY_KEY_RE,
            _RESIDUAL_BEARER_RE,
            _RESIDUAL_CLI_CREDENTIAL_RE,
            _RESIDUAL_COMMAND_CREDENTIAL_RE,
            _RESIDUAL_LONG_OPTION_CREDENTIAL_RE,
            _RESIDUAL_SPACE_CREDENTIAL_RE,
            _RESIDUAL_SHORT_OPTION_CREDENTIAL_RE,
            _RESIDUAL_CURL_SECRET_OPTION_RE,
            _RESIDUAL_SENSITIVE_COMMAND_LINE_RE,
            _RESIDUAL_SECRET_URL_RE,
            _RESIDUAL_RELATIVE_PROVIDER_PATH_RE,
            _RESIDUAL_SECRET_URL_PARAMETER_RE,
            _RESIDUAL_NODE_LINK_RE,
            _RESIDUAL_URL_USERINFO_RE,
            _RESIDUAL_SECRET_ASSIGNMENT_RE,
        )
    ):
        return True
    for match in _RESIDUAL_BASIC_RE.finditer(value):
        token = match.group("token")
        try:
            decoded = base64.b64decode(
                token + "=" * (-len(token) % 4),
                validate=True,
            )
        except (binascii.Error, ValueError):
            continue
        if b":" in decoded:
            return True
    return False


def _string_has_residual_credential(value: str) -> bool:
    """Check literal text plus exactly one URL-decoded layer."""

    if _string_has_residual_credential_once(value):
        return True
    decoded = unquote_plus(value)
    return decoded != value and _string_has_residual_credential_once(decoded)


def _residual_credential_path(value: Any) -> str | None:
    """Find credential-shaped material without invoking the export redactor."""

    pending: list[tuple[Any, str]] = [(value, "$")]
    while pending:
        item, path = pending.pop()
        if isinstance(item, str):
            if _string_has_residual_credential(item):
                return path
        elif isinstance(item, list):
            pending.extend(
                (child, f"{path}[{index}]")
                for index, child in reversed(list(enumerate(item)))
            )
        elif isinstance(item, dict):
            for raw_key, child in item.items():
                if not isinstance(raw_key, str):
                    continue
                normalized = _normalized_key(raw_key)
                if (
                    normalized in _RESIDUAL_HEADER_NAME_FIELDS
                    and _declares_sensitive_header(child)
                ):
                    return f"{path}.<sensitive-header-record>"
                if normalized in _RESIDUAL_HEADER_COLLECTION_FIELDS and isinstance(
                    child, list
                ):
                    header_names = (
                        child[::2]
                        if normalized in {"raw_headers", "rawheaders"}
                        else child
                    )
                    if any(_declares_sensitive_header(name) for name in header_names):
                        return f"{path}.<sensitive-header-collection>"
                if _residual_sensitive_key(normalized) and child != "<redacted>":
                    return f"{path}.{raw_key}"
            for child_key, child in reversed(list(item.items())):
                child_path = f"{path}.{child_key}"
                if isinstance(child_key, str) and _RESIDUAL_PROVIDER_TOKEN_RE.search(
                    child_key
                ):
                    return f"{path}.<key>"
                pending.append((child, child_path))
    return None


def _validate_no_residual_credentials(data: dict[str, Any]) -> None:
    credential_redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    if credential_redactor.value(data) != data:
        raise ValueError("bundle still contains credential or unsafe control data")
    residual_path = _residual_credential_path(data)
    if residual_path:
        raise ValueError(
            f"bundle still contains credential-shaped data at {residual_path}"
        )


def _normalized_key(value: str | None) -> str:
    if not value:
        return ""
    canonical = unicodedata.normalize("NFKC", value)
    canonical = "".join(
        character
        for character in canonical
        if unicodedata.category(character) not in {"Cc", "Cf"}
        and character not in {"\u2028", "\u2029"}
    )
    # Keep this independent residual checker aligned with the exporter's
    # treatment of common JSON camelCase and acronym-prefixed credential keys.
    canonical = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", canonical)
    canonical = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", canonical)
    canonical = canonical.casefold().translate(
        str.maketrans(
            {
                "а": "a",
                "е": "e",
                "і": "i",
                "о": "o",
                "р": "p",
                "с": "c",
                "ѕ": "s",
                "х": "x",
                "у": "y",
                "һ": "h",
            }
        )
    )
    return re.sub(r"[^a-z0-9]+", "_", canonical).strip("_")


_RESIDUAL_SENSITIVE_KEYS = {
    "account_key",
    "accountkey",
    "api_key",
    "apikey",
    "api_token",
    "auth",
    "authorization",
    "access_token",
    "accesstoken",
    "aws_secret_access_key",
    "azure_storage_key",
    "azurestoragekey",
    "bearer_token",
    "client_secret",
    "clientsecret",
    "cookie",
    "credential",
    "credentials",
    "password",
    "passwd",
    "passphrase",
    "private_key",
    "proxy_authorization",
    "refresh_token",
    "refreshtoken",
    "secret",
    "secret_access_key",
    "secret_key",
    "secretkey",
    "session",
    "session_id",
    "shared_access_key",
    "shared_access_signature",
    "sharedaccesskey",
    "sharedaccesssignature",
    "sshpass",
    "token",
    "x_api_key",
}
_RESIDUAL_NON_SECRET_KEYS = {"credentials_present", "token_count"}
_RESIDUAL_SECRET_SEGMENTS = {
    "auth",
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "passphrase",
    "passwd",
    "password",
    "secret",
    "session",
    "token",
}
_RESIDUAL_SECRET_SUFFIXES = (
    "_auth",
    "_authorization",
    "_cookie",
    "_credential",
    "_credentials",
    "_passphrase",
    "_passwd",
    "_password",
    "_private_key",
    "_secret",
    "_session",
    "_token",
)
_RESIDUAL_HEADER_NAME_FIELDS = {
    "field",
    "header",
    "header_name",
    "headername",
    "key",
    "name",
}
_RESIDUAL_HEADER_COLLECTION_FIELDS = {
    "header_names",
    "headernames",
    "raw_headers",
    "rawheaders",
}


def _residual_sensitive_key(value: str) -> bool:
    if not value or value in _RESIDUAL_NON_SECRET_KEYS:
        return False
    return (
        value in _RESIDUAL_SENSITIVE_KEYS
        or value.endswith(_RESIDUAL_SECRET_SUFFIXES)
        or bool(set(value.split("_")) & _RESIDUAL_SECRET_SEGMENTS)
        or "private_key" in value
        or "api_key" in value
    )


def _residual_sensitive_header_name(value: str) -> bool:
    if not value:
        return False
    return value in {
        "authorization",
        "cookie",
        "proxy_authorization",
        "set_cookie",
        "x_api_key",
        "x_auth_token",
        "private_token",
        "x_api_token",
        "x_vault_token",
        "x_amz_security_token",
        "x_goog_api_key",
        "cf_access_client_secret",
        "x_webhook_secret",
    } or bool(
        re.fullmatch(r"x_hub_signature(?:_[0-9]+)?", value)
        or re.search(
            r"(?:^|_)(?:api_key|api_token|auth_token|client_secret|"
            r"security_token|signing_secret|vault_token|webhook_secret|"
            r"signature)$",
            value,
        )
    )


def _declares_sensitive_header(value: Any) -> bool:
    if isinstance(value, str):
        return _residual_sensitive_header_name(_normalized_key(value))
    if isinstance(value, list):
        return any(_declares_sensitive_header(item) for item in value)
    return False


def _looks_like_hostname(value: str, *, allow_single_label: bool) -> bool:
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or len(candidate) > 253 or _REDACTED_NETWORK_RE.fullmatch(candidate):
        return False
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_name.split(".")
    if not allow_single_label and len(labels) < 2:
        return False
    if not all(_HOST_LABEL_RE.fullmatch(label) for label in labels):
        return False
    if len(labels) == 1:
        return any(character.isalpha() for character in labels[0])
    return not labels[-1].isdigit()


def _looks_like_network_name(value: str) -> bool:
    if _looks_like_hostname(value, allow_single_label=True):
        return True
    if not value or len(value) > 253 or _REDACTED_NETWORK_RE.fullmatch(value):
        return False
    return bool(
        re.fullmatch(r"[\w](?:[\w.-]{0,251}[\w])?", value, re.UNICODE)
        and any(character.isalpha() for character in value)
    )


def _looks_like_ip_literal(value: str) -> bool:
    candidate = value.strip("[]")
    if candidate.endswith("."):
        candidate = candidate[:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    parts = candidate.split(".")
    if not 1 <= len(parts) <= 4 or not all(part.isdigit() for part in parts):
        return len(parts) == 1 and _legacy_integer_ip_value(candidate) is not None
    if len(parts) == 1:
        return _legacy_integer_ip_value(candidate) is not None
    numbers = [int(part, 10) for part in parts]
    limits = {
        1: (0xFFFFFFFF,),
        2: (0xFF, 0xFFFFFF),
        3: (0xFF, 0xFF, 0xFFFF),
        4: (0xFF, 0xFF, 0xFF, 0xFF),
    }[len(numbers)]
    return all(
        number <= maximum
        for number, maximum in zip(numbers, limits, strict=True)
    )


def _legacy_integer_ip_value(value: str) -> int | None:
    candidate = value.casefold()
    try:
        if candidate.startswith("0x"):
            parsed = int(candidate[2:], 16)
        elif len(candidate) > 1 and candidate.startswith("0"):
            parsed = int(candidate, 8)
        else:
            parsed = int(candidate, 10)
    except ValueError:
        return None
    return parsed if 0 <= parsed <= 0xFFFFFFFF else None


def _string_has_network_identifier(value: str, *, key: str) -> bool:
    if _REDACTED_NETWORK_RE.fullmatch(value):
        return False
    if _RESIDUAL_NETWORK_COMMAND_LINE_RE.search(value):
        return True
    if any(
        _legacy_integer_ip_value(match.group("ip")) is not None
        for match in _LEGACY_INTEGER_IP_CONTEXT_RE.finditer(value)
    ):
        return True
    if key in {
        "config_host",
        "host_alias",
        "management_address",
        "management_reference",
        "panel_reference",
        "remote_address",
        "server_alias",
        "ssh_host",
        "target_host",
    }:
        return bool(value)
    if _MAC_RE.search(value):
        return True
    if any(
        _looks_like_network_name(match.group("host"))
        for pattern in (
            _UNC_HOST_RE,
            _USER_AT_SINGLE_HOST_RE,
            _REMOTE_COMMAND_HOST_RE,
            _REMOTE_COPY_HOST_RE,
            _SSH_OPTION_HOST_RE,
            _NETWORK_COMMAND_HOST_RE,
        )
        for match in pattern.finditer(value)
    ):
        return True
    for match in _IP_RE.finditer(value):
        if _looks_like_ip_literal(match.group(0)):
            return True
    for match in _URL_RE.finditer(value):
        try:
            hostname = urlsplit(match.group(0)).hostname
        except ValueError:
            return True
        if hostname and not _REDACTED_NETWORK_RE.fullmatch(hostname):
            candidate = hostname[:-1] if hostname.endswith(".") else hostname
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                if _legacy_integer_ip_value(candidate) is not None:
                    return True
                if _looks_like_hostname(hostname, allow_single_label=True):
                    return True
            else:
                return True
    if any(
        _looks_like_hostname(match.group(0), allow_single_label=False)
        for match in _DOMAIN_RE.finditer(value)
    ):
        return True
    if any(
        _looks_like_network_name(match.group("host"))
        for match in _SINGLE_LABEL_HOST_CONTEXT_RE.finditer(value)
    ):
        return True
    if key in _NETWORK_VALUE_KEYS and value.count("@") == 1:
        user, host = value.rsplit("@", 1)
        candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", user):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                if _looks_like_network_name(candidate):
                    return True
            else:
                return True
    if key in _NETWORK_VALUE_KEYS:
        if value.startswith("[") and "]:" in value:
            host, raw_port = value[1:].rsplit("]:", 1)
        elif value.count(":") == 1:
            host, raw_port = value.rsplit(":", 1)
        else:
            host, raw_port = "", ""
        if raw_port.isdigit() and 1 <= int(raw_port) <= 65_535:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if _looks_like_network_name(host):
                    return True
            else:
                return True
    if key in {"vantage_point", "vantage_points"} and value in PUBLIC_VANTAGE_POINTS:
        return False
    return key in _NETWORK_VALUE_KEYS and _looks_like_network_name(value)


def _network_identifier_path(
    value: Any,
    *,
    path: str = "$",
    key: str = "",
) -> str | None:
    """Find a residual network identifier without invoking the export redactor."""

    host_keyed_mapping = bool(key and _HOST_KEYED_MAPPING_RE.search(key))
    if isinstance(value, str):
        # The strict bundle contract requires this exact root value. A dotted
        # version such as ``2.0`` also happens to be valid legacy IPv4 syntax,
        # so exempt only the known schema slot, never arbitrary nested text.
        if path == "$.schema_version":
            return None
        return path if _string_has_network_identifier(value, key=key) else None
    if isinstance(value, list):
        for index, item in enumerate(value):
            found = _network_identifier_path(
                item,
                path=f"{path}[{index}]",
                key="" if isinstance(item, dict) else key,
            )
            if found:
                return found
        return None
    if isinstance(value, dict):
        for child_key, item in value.items():
            normalized = _normalized_key(child_key) if isinstance(child_key, str) else ""
            if isinstance(child_key, str) and _string_has_network_identifier(
                child_key, key=""
            ):
                return f"{path}.<key>"
            if (
                isinstance(child_key, str)
                and host_keyed_mapping
                and _looks_like_network_name(child_key)
            ):
                return f"{path}.<key>"
            found = _network_identifier_path(
                item,
                path=f"{path}.{child_key}",
                key=normalized,
            )
            if found:
                return found
    return None


def _has_zip_magic(handle: BinaryIO) -> bool:
    handle.seek(0)
    return handle.read(4) in _ZIP_MAGICS


def _preflight_zip_container(handle: BinaryIO) -> None:
    """Reject oversized/ambiguous ZIP containers before ZipFile allocates entries."""

    size = os.fstat(handle.fileno()).st_size
    if size > _MAX_ARCHIVE_BYTES:
        raise ValueError("diagnostic archive exceeds the container size limit")
    tail_size = min(size, 65_557)
    handle.seek(size - tail_size)
    tail = handle.read(tail_size)
    offset = tail.rfind(_ZIP_EOCD_MAGIC)
    if offset < 0 or len(tail) - offset < 22:
        raise ValueError("diagnostic archive is missing a valid ZIP directory")
    (
        signature,
        disk_number,
        directory_disk,
        disk_entries,
        total_entries,
        directory_size,
        directory_offset,
        comment_length,
    ) = struct.unpack_from("<4s4H2LH", tail, offset)
    if signature != _ZIP_EOCD_MAGIC or offset + 22 + comment_length != len(tail):
        raise ValueError("diagnostic archive has an ambiguous ZIP directory")
    if comment_length != 0:
        raise ValueError("diagnostic archive comments are unsupported")
    if disk_number != 0 or directory_disk != 0 or disk_entries != total_entries:
        raise ValueError("multi-disk diagnostic archives are unsupported")
    if total_entries != len(_ARCHIVE_MEMBERS):
        raise ValueError("diagnostic archive must contain exactly three members")
    if directory_size > _MAX_CENTRAL_DIRECTORY_BYTES:
        raise ValueError("diagnostic archive central directory is too large")
    if directory_offset + directory_size != size - 22 - comment_length:
        raise ValueError("diagnostic archive central directory is invalid")


def _validate_canonical_zip_layout(handle: BinaryIO, archive: zipfile.ZipFile) -> None:
    """Reject every byte location not owned by one stored canonical member."""

    if archive.comment:
        raise ValueError("diagnostic archive comments are unsupported")
    expected_offset = 0
    for info in archive.infolist():
        if info.header_offset != expected_offset:
            raise ValueError("diagnostic archive contains a preamble or data gap")
        if info.comment or info.extra:
            raise ValueError("diagnostic archive member metadata is unsupported")
        if info.compress_type != zipfile.ZIP_STORED or info.compress_size != info.file_size:
            raise ValueError("diagnostic archive members must use stored encoding")
        if info.flag_bits & (0x01 | 0x08):
            raise ValueError("diagnostic archive member flags are unsupported")
        handle.seek(info.header_offset)
        header = handle.read(30)
        if len(header) != 30:
            raise ValueError("diagnostic archive local header is truncated")
        (
            signature,
            _version,
            flags,
            compression,
            _time,
            _date,
            crc,
            compressed_size,
            file_size,
            name_length,
            extra_length,
        ) = struct.unpack("<4s5H3L2H", header)
        name_bytes = handle.read(name_length)
        local_extra = handle.read(extra_length)
        if (
            signature != _ZIP_LOCAL_MAGIC
            or flags != info.flag_bits
            or compression != zipfile.ZIP_STORED
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
            or extra_length != 0
            or local_extra
            or name_bytes.decode("utf-8", errors="strict") != info.filename
        ):
            raise ValueError("diagnostic archive local header is non-canonical")
        expected_offset = 30 + name_length + info.file_size + info.header_offset
    if expected_offset != archive.start_dir:
        raise ValueError("diagnostic archive contains unaccounted member data")


def _validate_manifest(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("archive manifest must be an object")
    if set(data) != _MANIFEST_KEYS:
        missing = sorted(_MANIFEST_KEYS - data.keys())
        extra = sorted(data.keys() - _MANIFEST_KEYS)
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected: {', '.join(extra)}")
        raise ValueError(f"invalid archive manifest properties ({'; '.join(details)})")
    if data["format"] != "netops-diagnostic-archive":
        raise ValueError("unsupported archive format")
    if data["format_version"] != "1.0":
        raise ValueError("unsupported archive format version")
    if data["source_schema_version"] != BUNDLE_SCHEMA_VERSION:
        raise ValueError("unsupported source bundle schema version")
    if type(data["network_identifiers_included"]) is not bool:
        raise ValueError("network_identifiers_included must be a boolean")
    created_at = data["created_at"]
    if not isinstance(created_at, str):
        raise ValueError("archive created_at must be a timestamp string")
    try:
        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("archive created_at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("archive created_at must include a timezone")
    redactions = data["redactions"]
    if not isinstance(redactions, list) or not all(
        isinstance(item, str) for item in redactions
    ):
        raise ValueError("archive redactions must be an array of strings")
    files = data["files"]
    if not isinstance(files, dict) or set(files) != {"bundle.json", "report.md"}:
        raise ValueError("archive files must checksum bundle.json and report.md")
    if not all(
        isinstance(value, str) and _CHECKSUM_RE.fullmatch(value)
        for value in files.values()
    ):
        raise ValueError("archive file checksums must be lowercase SHA-256 values")
    return data


def export_bundle(
    source: str | Path,
    destination: str | Path,
    *,
    include_network_identifiers: bool = False,
) -> Path:
    source_path = Path(os.path.abspath(Path(source).expanduser()))
    raw_output = Path(os.path.abspath(Path(destination).expanduser()))
    output = raw_output
    if output.suffix.lower() != ".zip":
        raise ValueError("diagnostic archive output must use a .zip extension")
    same_file = source_path == raw_output
    if not same_file and os.path.exists(source_path) and os.path.exists(raw_output):
        try:
            same_file = os.path.samefile(source_path, raw_output)
        except OSError:
            same_file = False
    if same_file:
        raise ValueError("diagnostic archive output must differ from its source bundle")
    if os.path.lexists(raw_output):
        raise FileExistsError(
            f"diagnostic archive output already exists: {raw_output}"
        )
    bundle = load_bundle(source_path)
    redactor = Redactor(
        include_network_identifiers=include_network_identifiers,
        redact_hostnames=not include_network_identifiers,
    )
    redacted_data = redactor.value(bundle.to_dict())
    redacted_data["redactions"] = sorted(
        set(redacted_data.get("redactions", [])) | redactor.actions
    )
    residual_credential = _residual_credential_path(redacted_data)
    if residual_credential:
        raise ValueError(
            "support archive redaction left credential-shaped data at "
            f"{residual_credential}"
        )
    if not include_network_identifiers:
        residual_path = _network_identifier_path(redacted_data)
        if residual_path:
            raise ValueError(
                "support archive redaction left a network identifier at "
                f"{residual_path}"
            )
    redacted_bundle = DiagnosticBundle.from_dict(redacted_data)
    bundle_bytes = _json_bytes(redacted_bundle.to_dict())
    report_bytes = render_report(redacted_bundle).encode("utf-8")
    for name, payload in (("bundle.json", bundle_bytes), ("report.md", report_bytes)):
        if len(payload) > _MEMBER_SIZE_LIMITS[name]:
            raise ValueError(f"support archive member exceeds size limit: {name}")
    manifest = {
        "format": "netops-diagnostic-archive",
        "format_version": "1.0",
        "created_at": utc_now(),
        "source_schema_version": bundle.schema_version,
        "network_identifiers_included": include_network_identifiers,
        "redactions": sorted(redactor.actions),
        "files": {
            "bundle.json": hashlib.sha256(bundle_bytes).hexdigest(),
            "report.md": hashlib.sha256(report_bytes).hexdigest(),
        },
    }
    _validate_manifest(manifest)
    manifest_bytes = _json_bytes(manifest)
    if len(manifest_bytes) > _MEMBER_SIZE_LIMITS["manifest.json"]:
        raise ValueError("support archive member exceeds size limit: manifest.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            with zipfile.ZipFile(
                handle, mode="w", compression=zipfile.ZIP_STORED
            ) as archive:
                archive.writestr("bundle.json", bundle_bytes)
                archive.writestr("report.md", report_bytes)
                archive.writestr("manifest.json", manifest_bytes)
            # Keep the original writable descriptor bound to the temporary
            # inode through finalization.  Windows rejects ``fsync`` on a
            # read-only descriptor, while reopening by path would introduce a
            # replacement race before publication.
            handle.flush()
            os.fsync(handle.fileno())
        # A hard-link publish is atomic and fails if another process created the
        # destination after the preflight check.  It therefore cannot silently
        # overwrite an existing support archive on POSIX or Windows.
        assert temporary is not None
        os.link(temporary, output)
        temporary.unlink()
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return output


def inspect_bundle(path: str | Path) -> tuple[DiagnosticBundle, str]:
    source = Path(os.path.abspath(Path(path).expanduser()))
    with open_regular_binary(source) as handle:
        before = os.fstat(handle.fileno())
        if not _has_zip_magic(handle):
            if before.st_size > _MEMBER_SIZE_LIMITS["bundle.json"]:
                raise ValueError("diagnostic bundle exceeds the size limit")
            handle.seek(0)
            payload = handle.read(_MEMBER_SIZE_LIMITS["bundle.json"] + 1)
            after = os.fstat(handle.fileno())
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise ValueError("diagnostic bundle changed while being inspected")
            bundle_data = parse_json_strict(payload)
            validate_bundle_data(bundle_data)
            bundle = DiagnosticBundle.from_dict(bundle_data)
            _validate_no_residual_credentials(bundle.to_dict())
            return bundle, render_report(bundle)
        _preflight_zip_container(handle)
        handle.seek(0)
        with zipfile.ZipFile(handle, mode="r") as archive:
            listed_names = archive.namelist()
            if listed_names != ["bundle.json", "report.md", "manifest.json"]:
                raise ValueError("diagnostic archive members are not in canonical order")
            names = set(listed_names)
            if len(names) != len(listed_names):
                raise ValueError("archive contains duplicate member names")
            if names != _ARCHIVE_MEMBERS:
                missing = sorted(_ARCHIVE_MEMBERS - names)
                extra = sorted(names - _ARCHIVE_MEMBERS)
                details = []
                if missing:
                    details.append(f"missing: {', '.join(missing)}")
                if extra:
                    details.append(f"unexpected: {', '.join(extra)}")
                raise ValueError(f"invalid archive members ({'; '.join(details)})")
            _validate_canonical_zip_layout(handle, archive)
            for name in names:
                candidate = Path(name)
                if candidate.is_absolute() or ".." in candidate.parts:
                    raise ValueError(f"unsafe archive member: {name}")
                info = archive.getinfo(name)
                if info.file_size > _MEMBER_SIZE_LIMITS[name]:
                    raise ValueError(f"archive member exceeds size limit: {name}")
            try:
                bundle_bytes = archive.read("bundle.json")
                report_bytes = archive.read("report.md")
                bundle_data = parse_json_strict(bundle_bytes)
                manifest = _validate_manifest(
                    parse_json_strict(archive.read("manifest.json"))
                )
                report_bytes.decode("utf-8")
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("archive contains invalid UTF-8 or JSON") from exc
            for name, expected in manifest["files"].items():
                actual = hashlib.sha256(archive.read(name)).hexdigest()
                if expected != actual:
                    raise ValueError(f"{name} checksum mismatch")
        after = os.fstat(handle.fileno())
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("diagnostic archive changed while being inspected")
    validate_bundle_data(bundle_data)
    bundle = DiagnosticBundle.from_dict(bundle_data)
    _validate_no_residual_credentials(bundle.to_dict())
    if not manifest["network_identifiers_included"]:
        residual_path = _network_identifier_path(bundle.to_dict())
        if residual_path:
            raise ValueError(
                "archive claims network identifiers were removed but still contains "
                f"one at {residual_path}"
            )
    rendered = render_report(bundle)
    if report_bytes != rendered.encode("utf-8"):
        raise ValueError("report.md does not match the validated bundle")
    if not set(manifest["redactions"]).issubset(set(bundle.redactions)):
        raise ValueError("manifest redactions do not match bundle redactions")
    return bundle, rendered
