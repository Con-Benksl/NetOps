from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
import secrets
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, unquote_plus, urlsplit, urlunsplit


UUID_RE = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"(?![0-9a-fA-F])"
)
URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>\"']+")
NETWORK_PATH_URL_RE = re.compile(r"(?<![A-Za-z0-9:/])//[^\s<>\"']+")
RELATIVE_URL_RE = re.compile(
    r"(?<![A-Za-z0-9:/])/{1,2}[^\s<>\"']*[?#][^\s<>\"']+"
)
RELATIVE_PATH_USERINFO_RE = re.compile(
    r"(?<![A-Za-z0-9:/])(?P<prefix>/)[^/@\s:]+:[^/@\s]+@"
)
RELATIVE_SLACK_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9:/])(?P<prefix>/services/(?:[^/\s?#]+/){2})"
    r"[^/\s?#]+"
)
RELATIVE_DISCORD_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9:/])(?P<prefix>/api(?:/v[0-9]+)?/webhooks/"
    r"[^/\s?#]+/)[^/\s?#]+"
)
RELATIVE_TELEGRAM_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9:/])(?P<prefix>/bot)[0-9]{3,}(?::|%3a)"
    r"[A-Za-z0-9_-]{8,}"
)
REDACTION_MARKER_RE = re.compile(r"(?i)<(?:[a-z0-9-]+-)?redacted>")
REDACTED_PARAMETER_RE = re.compile(
    r"(?i)(?P<separator>[?&#;])[^?&#;=\s]+="
    r"<(?:[a-z0-9-]+-)?redacted>"
)
DOMAIN_RE = re.compile(
    r"(?<![\w-])(?:[^\W_](?:[\w-]{0,61}[^\W_])?\.)+"
    r"[^\W_](?:[\w-]{0,61}[^\W_])?(?![\w-])",
    re.UNICODE,
)
IP_TOKEN_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]{2,}"
    r"(?![0-9A-Fa-f:.])"
    r"|(?<![0-9A-Fa-f:.])(?:\d{1,10}\.){1,3}\d{1,10}\.?(?![0-9.])"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?"
    r"(?:-----END [^-\n]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
PUTTY_PRIVATE_KEY_RE = re.compile(
    r"(?ims)^PuTTY-User-Key-File-\d+:[^\r\n]*(?:\r?\n).*?"
    r"(?:^Private-MAC:[^\r\n]*(?:\r?\n|$)|\Z)"
)
CREDENTIAL_URI_SCHEMES = (
    "anytls",
    "hysteria",
    "hysteria2",
    "hy2",
    "juicity",
    "mieru",
    "shadowtls",
    "snell",
    "ss",
    "ssr",
    "trojan",
    "tuic",
    "vless",
    "vmess",
    "wg",
    "wireguard",
)
NODE_LINK_RE = re.compile(
    r"(?i)\b(?:"
    + "|".join(re.escape(scheme) for scheme in CREDENTIAL_URI_SCHEMES)
    + r")://[^\s<>\"']+"
)
KNOWN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-(?:[A-Za-z0-9]{32,}|(?:proj|svcacct|ant-api03|or-v1)-[A-Za-z0-9_-]{20,})|"
    r"(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|"
    r"(?:sk|rk)_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|"
    r"npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{40,}|"
    r"(?:dop|doo|dor)_v1_[a-fA-F0-9]{64}|hf_[A-Za-z0-9]{20,}|"
    r"ya29\.[A-Za-z0-9_-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r")(?![A-Za-z0-9_-])"
)
MAC_RE = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){7}[0-9a-f]{2}(?![0-9a-f:-])"
    r"|(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f:-])"
    r"|(?<![0-9a-f])(?:[0-9a-f]{4}\.){3}[0-9a-f]{4}(?![0-9a-f.])"
    r"|(?<![0-9a-f])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?![0-9a-f.])"
)
HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
ANSI_ESCAPE_RE = re.compile(
    r"\x1b(?:"
    r"\[[0-?]*[ -/]*[@-~]"
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\|$)"
    r"|[PX^_][^\x1b]*(?:\x1b\\|$)"
    r"|[@-_]"
    r")"
)
SINGLE_LABEL_HOST_CONTEXT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>"
    r"\b(?:remote-server|remote[_-]?host|local[_-]?host|hostname|host|server|"
    r"target|peer|resolver)\s*[:=]\s*"
    r"|\b(?:connect(?:ed|ing)?\s+to\s+|connection\s+to\s+|dial(?:ed|ing)?\s+|"
    r"resolv(?:ed|ing)?\s+)"
    r")"
    r"(?P<open_quote>[\"']?)"
    r"(?P<host>[\w.-]{1,253})"
    r"(?P<close_quote>[\"']?)"
    r"(?=$|[\s,;)\]}/]|:\d{1,5}\b)"
)
UNC_HOST_RE = re.compile(
    r"(?<!\\)\\\\(?P<host>[\w.-]{1,253})"
    r"(?=\\)"
)
USER_AT_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<user>[A-Za-z0-9_][A-Za-z0-9_.-]{0,63})@"
    r"(?P<host>[\w.-]{1,253})"
    r"(?=$|[:\s,;)\]}/])"
)
REMOTE_COMMAND_HOST_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:ssh|sftp)\s+"
    r"(?:(?:-[46AaCfgKkMNnqsTtVvXxYy]+\s+)|"
    r"(?:-(?:B|b|c|D|E|e|F|I|i|J|L|l|m|O|o|p|Q|R|S|W|w)"
    r"(?:\s+|=)?[^\s;&|]+\s+))*)"
    r"(?P<host>[\w.-]{1,253})"
    r"(?=$|[:\s])"
)
REMOTE_COPY_HOST_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:scp|rsync)\b[^\r\n;&|]*?\s)"
    r"(?P<host>[\w.-]{1,253})(?=:)"
)
SSH_OPTION_HOST_RE = re.compile(
    r"(?i)(?P<prefix>(?:-J\s*|-o\s*(?:ProxyJump|HostName)\s*=\s*))"
    r"(?P<host>[\w.-]{1,253})(?=$|[,\s])"
)
NETWORK_COMMAND_HOST_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:ping|traceroute|tracepath|dig|nslookup|telnet|nc|"
    r"curl|wget)\b[^\r\n;&|]*?\s)"
    r"(?P<host>[\w.-]{1,253})(?=:\d{1,5}(?:/|\s|$)|/|"
    r"\s+\d{1,5}\s*(?:$|[;&|])|\s*(?:$|[;&|]))"
)
NETWORK_COMMAND_LINE_RE = re.compile(
    r"(?im)\b(?:ssh|scp|sftp|rsync|ping|traceroute|tracert|pathping|tracepath|"
    r"dig|nslookup|telnet|nc|curl|wget)(?:\.exe)?(?=\s|$)[^\r\n]*"
    r"|\b(?:Resolve-DnsName|Test-NetConnection|Test-Connection|powershell|pwsh)"
    r"(?:\.exe)?(?=\s|$)[^\r\n]*"
)
SENSITIVE_CURL_COMMAND_LINE_RE = re.compile(
    r"(?im)\bcurl(?:\.exe)?(?=\s|$)"
    r"(?=[^\r\n]*(?<![A-Za-z0-9_-])(?:"
    r"-b|--cookie|--oauth2-bearer|--cert|--proxy-cert|--pass|"
    r"--tlspassword|--proxy-tlspassword)(?=\s|=))[^\r\n]*"
)
SENSITIVE_COMMAND_LINE_RE = re.compile(
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
LEGACY_INTEGER_IP_CONTEXT_RE = re.compile(
    r"(?ix)(?P<prefix>\b(?:ip|address|host|target|server|resolver|gateway|"
    r"remote|peer)\s*[:=]\s*[\"']?)"
    r"(?P<ip>0x[0-9a-f]{1,8}|0[0-7]{8,11}|[0-9]{8,10})"
    r"(?P<suffix>[\"']?)(?![0-9a-f])"
)


def _normalize_key(value: str) -> str:
    canonical = unicodedata.normalize("NFKC", value)
    canonical = "".join(
        character
        for character in canonical
        if unicodedata.category(character) not in {"Cc", "Cf"}
        and character not in {"\u2028", "\u2029"}
    )
    # Preserve word boundaries before case folding. Otherwise common JSON
    # spellings such as ``proxyPassword`` collapse to ``proxypassword`` and
    # bypass both the exact-key and sensitive-suffix policies.
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


SENSITIVE_KEYS = {
    "account_key",
    "accountkey",
    "api_key",
    "apikey",
    "api_token",
    "auth",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "auth_token",
    "aws_secret_access_key",
    "azure_storage_key",
    "azurestoragekey",
    "bearer_token",
    "client_secret",
    "clientsecret",
    "credential",
    "credentials",
    "password",
    "passwd",
    "passphrase",
    "pgpassword",
    "private_key",
    "proxy_password",
    "mysql_pwd",
    "secret",
    "secret_access_key",
    "secret_key",
    "secretkey",
    "shared_access_key",
    "shared_access_signature",
    "sharedaccesskey",
    "sharedaccesssignature",
    "session",
    "session_id",
    "sshpass",
    "token",
}
NON_SECRET_SEMANTIC_KEYS = {
    "credentials_present",
    "token_count",
}
SENSITIVE_KEY_SEGMENTS = {
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
SENSITIVE_KEY_SUFFIXES = (
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
SENSITIVE_KEY_PREFIXES = (
    "auth_",
    "authorization_",
    "cookie_",
)
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy_authorization",
    "set_cookie",
    "x_api_key",
    "x_auth_token",
}
SENSITIVE_URL_PARAMETERS = SENSITIVE_KEYS | SENSITIVE_HEADERS | {
    "code",
    "key",
    "sas",
    "sig",
    "signature",
    "x_amz_credential",
    "x_amz_security_token",
    "x_amz_signature",
    "x_goog_credential",
    "x_goog_signature",
}
HEADER_NAMES_PATTERN = (
    r"Authorization|Proxy-Authorization|Cookie|Set-Cookie|"
    r"X-Api-Key|X-Api-Token|X-Auth-Token|Private-Token|X-Vault-Token|"
    r"X-Amz-Security-Token|X-Goog-Api-Key|Cf-Access-Client-Secret|"
    r"X-Hub-Signature(?:-[0-9]+)?|X-Webhook-Secret"
)
SENSITIVE_HEADER_LINE_RE = re.compile(
    rf"(?im)^[ \t>*-]*(?:{HEADER_NAMES_PATTERN})[ \t]*:[^\r\n]*"
    rf"(?:\r?\n[ \t]+[^\r\n]*)*(?:\r?\n|$)"
)
SENSITIVE_INLINE_HEADER_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9-])(?:{HEADER_NAMES_PATTERN})\s*[:=][^\r\n'\"]+"
)
SENSITIVE_QUOTED_HEADER_FIELD_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9-])(?:"
    rf"(?P<quote>[\"'])(?:{HEADER_NAMES_PATTERN})(?P=quote)"
    rf"|(?:{HEADER_NAMES_PATTERN}))\s*[:=]\s*"
    rf"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|"
    rf"[^,}}\]\r\n\"']+)"
)
AZURE_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:azure[_-]?storage[_-]?key|"
    r"shared[_-]?access[_-]?(?:key|signature))\s*[:=]\s*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:"
    r"(?:[a-z0-9]+[_-])*(?:password|passwd|passphrase|token|secret|"
    r"authorization|auth|credential|credentials|private[_-]?key)|"
    r"account[_-]?key|aws[_-]?secret[_-]?access[_-]?key|"
    r"secret[_-]?access[_-]?key|azure[_-]?storage[_-]?key|"
    r"shared[_-]?access[_-]?(?:key|signature)|sshpass|pgpassword|"
    r"mysql[_-]?pwd)\b\s*[:=]\s*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&]+)"
)
GENERIC_API_KEY_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|x[_-]?api[_-]?key)\b\s*[:=]\s*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&]+)"
)
BARE_BEARER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])Bearer\s+[A-Za-z0-9._~+/=-]+"
)
BARE_BASIC_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])Basic\s+(?P<token>[A-Za-z0-9+/]{2,}={0,2})"
    r"(?![A-Za-z0-9+/=])"
)
CLI_CREDENTIAL_RE = re.compile(
    r"(?i)(?P<prefix>\bsshpass\s+(?:-p|--password)\s+|"
    r"\bcurl\s+(?:[^\r\n]*?\s)?(?:-u|--user)\s+)"
    r"(?P<credential>\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s;&|]+)"
)
COMMAND_CREDENTIAL_RE = re.compile(
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
LONG_OPTION_CREDENTIAL_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9_-])--(?:password|passwd|passphrase|token|"
    r"api[-_]?key|client[-_]?secret|secret|authorization|credential|"
    r"private[-_]?key)(?:\s*=\s*|\s+))"
    r"(?P<credential>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;&|]+)"
)
SPACE_CREDENTIAL_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:password|passwd|passphrase|token|api[-_]?key|"
    r"client[-_]?secret)\s+)"
    r"(?P<credential>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;&|]+)"
)
SHORT_OPTION_CREDENTIAL_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:redis-cli|mongosh|mysqladmin)\b[^\r\n;&|]*?"
    r"(?:-a|-p)\s+)"
    r"(?P<credential>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;&|]+)"
)
GENERIC_HOME_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:"
    r"/(?:home|Users)/(?:[^/\r\n]+(?=/|$)|[^/\s]+)|/root|"
    r"[A-Za-z]:[\\/](?:Users|Documents[ ]and[ ]Settings)[\\/]"
    r"(?:[^\\/\r\n]+(?=[\\/]|$)|[^\\/\s]+)"
    r")"
)
REDACTED_DEVICE_RE = re.compile(r"^<device-(?:[0-9a-f]{8}|[0-9a-f]{12})>$")
REDACTED_NETWORK_RE = re.compile(
    r"^<(?:device|host|ip|mac)-(?:[0-9a-f]{8}|[0-9a-f]{12})>$"
)
NETWORK_IDENTIFIER_KEYS = {
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
}
VANTAGE_POINT_KEYS = {"vantage_point", "vantage_points"}
PUBLIC_VANTAGE_POINTS = {
    "comparison",
    "local",
    "local-client",
    "local-server",
    "monitor",
    "node",
    "remote",
}
# Stable diagnostic vocabulary retained for compatibility with previously
# exported bundles. Single-label JSON keys are inherently ambiguous (field
# name versus hostname); current exports only interpret them as hosts inside an
# explicitly named host-keyed mapping such as ``latency_by_host``.
PUBLIC_MAPPING_KEYS = {
    "active",
    "address",
    "address_family",
    "available",
    "avg_ms",
    "bits_per_second",
    "command",
    "completed_at",
    "confidence",
    "control_channel",
    "cpu_count",
    "created_at",
    "credentials_present",
    "curated_tools",
    "disk_root",
    "duration_ms",
    "domain",
    "effective_port",
    "environment",
    "endpoint",
    "error",
    "evidence",
    "family",
    "findings",
    "format",
    "format_version",
    "hostname",
    "host",
    "http_status",
    "id",
    "ip",
    "limitations",
    "loadavg",
    "local_host",
    "loss_percent",
    "machine",
    "max_ms",
    "metrics",
    "mode",
    "name",
    "network_identifiers_included",
    "network_summary",
    "observation_id",
    "observations",
    "observed_at",
    "path_segments",
    "platform",
    "port",
    "probe",
    "protocol",
    "proxy_environment",
    "public_ip",
    "redactions",
    "release",
    "remote_host",
    "resolver",
    "returncode",
    "run_id",
    "schema_version",
    "scheme",
    "segment",
    "server",
    "set_variables",
    "severity",
    "source",
    "source_schema_version",
    "started_at",
    "status",
    "stderr",
    "stdout",
    "system",
    "system_proxy_enabled",
    "target",
    "targets",
    "timed_out",
    "title",
    "tun_detected",
    "tun_hints",
    "type",
    "value",
    "values",
    "vantage_point",
    "vantage_points",
}
HEADER_NAME_FIELDS = {
    "name",
    "field",
    "header_name",
    "headername",
    "header",
    "key",
}
HEADER_COLLECTION_FIELDS = {
    "header_names",
    "headernames",
    "raw_headers",
    "rawheaders",
}
HOST_KEYED_MAPPING_RE = re.compile(
    r"(?:_by_(?:host|server|target|endpoint|address|ip|domain|resolver|peer|"
    r"node|router|gateway|hop|device)s?"
    r"|^(?:hosts|servers|targets|endpoints|addresses|ips|domains|resolvers|peers|"
    r"nodes|routers|gateways|hops|devices))$"
)


def _is_sensitive_key(value: str | None) -> bool:
    if not value or value in NON_SECRET_SEMANTIC_KEYS:
        return False
    return (
        value in SENSITIVE_KEYS
        or value in SENSITIVE_HEADERS
        or value.endswith(SENSITIVE_KEY_SUFFIXES)
        or value.startswith(SENSITIVE_KEY_PREFIXES)
        or bool(set(value.split("_")) & SENSITIVE_KEY_SEGMENTS)
        or "private_key" in value
        or "api_key" in value
    )


def _is_sensitive_header_name(value: str | None) -> bool:
    if not value:
        return False
    return value in SENSITIVE_HEADERS or value in {
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


def _is_hostname(value: str, *, allow_single_label: bool) -> bool:
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or len(candidate) > 253 or REDACTED_NETWORK_RE.fullmatch(candidate):
        return False
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return False
    labels = ascii_name.split(".")
    if not allow_single_label and len(labels) < 2:
        return False
    if not all(HOST_LABEL_RE.fullmatch(label) for label in labels):
        return False
    if len(labels) == 1:
        return any(character.isalpha() for character in labels[0])
    return not labels[-1].isdigit()


def _is_network_name(value: str) -> bool:
    """Accept DNS names plus explicit SSH-style aliases in network contexts."""

    if _is_hostname(value, allow_single_label=True):
        return True
    if not value or len(value) > 253 or REDACTED_NETWORK_RE.fullmatch(value):
        return False
    return bool(
        re.fullmatch(r"[\w](?:[\w.-]{0,251}[\w])?", value, re.UNICODE)
        and any(character.isalpha() for character in value)
    )


def _is_ip_literal(value: str, *, allow_legacy: bool = True) -> bool:
    candidate = value.strip("[]")
    if candidate.endswith("."):
        candidate = candidate[:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    if not allow_legacy:
        return False
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


def _split_ssh_destination(value: str) -> tuple[str, str] | None:
    """Split ``user@host`` without mistaking arbitrary text for an endpoint."""

    if value.count("@") != 1:
        return None
    user, host = value.rsplit("@", 1)
    if not user or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", user):
        return None
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        if not _is_network_name(candidate):
            return None
    return user, candidate


def _split_host_port(value: str) -> tuple[str, int] | None:
    if value.startswith("[") and "]:" in value:
        host, raw_port = value[1:].rsplit("]:", 1)
    elif value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
    else:
        return None
    if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65_535:
        return None
    if not _is_ip_literal(host) and not _is_network_name(host):
        return None
    return host, int(raw_port)


def _canonical_label_value(kind: str, value: str) -> str:
    """Canonicalize equivalent identifier spellings before pseudonymization."""

    candidate = unicodedata.normalize("NFKC", value).translate(
        str.maketrans({"。": ".", "．": ".", "｡": "."})
    )
    if kind == "ip":
        address_text = candidate.strip("[]")
        if address_text.endswith("."):
            address_text = address_text[:-1]
        try:
            return ipaddress.ip_address(address_text).compressed.casefold()
        except ValueError:
            integer_address = _legacy_integer_ip_value(address_text)
            if integer_address is not None and "." not in address_text:
                return str(ipaddress.IPv4Address(integer_address))
            parts = address_text.split(".")
            if 1 <= len(parts) <= 4 and all(part.isdigit() for part in parts):
                numbers = [int(part, 10) for part in parts]
                limits = {
                    1: (0xFFFFFFFF,),
                    2: (0xFF, 0xFFFFFF),
                    3: (0xFF, 0xFF, 0xFFFF),
                    4: (0xFF, 0xFF, 0xFF, 0xFF),
                }[len(numbers)]
                if all(
                    number <= maximum
                    for number, maximum in zip(numbers, limits, strict=True)
                ):
                    if len(numbers) == 1:
                        packed = numbers[0]
                    elif len(numbers) == 2:
                        packed = (numbers[0] << 24) | numbers[1]
                    elif len(numbers) == 3:
                        packed = (
                            (numbers[0] << 24)
                            | (numbers[1] << 16)
                            | numbers[2]
                        )
                    else:
                        packed = (
                            (numbers[0] << 24)
                            | (numbers[1] << 16)
                            | (numbers[2] << 8)
                            | numbers[3]
                        )
                    return str(ipaddress.IPv4Address(packed))
    elif kind in {"host", "device"}:
        hostname = candidate.rstrip(".")
        try:
            return hostname.encode("idna").decode("ascii").casefold()
        except UnicodeError:
            pass
    elif kind == "mac":
        hexadecimal = re.sub(r"[^0-9A-Fa-f]", "", candidate)
        if len(hexadecimal) in {12, 16}:
            return hexadecimal.casefold()
    return candidate.casefold()


class Redactor:
    def __init__(
        self,
        *,
        include_network_identifiers: bool = False,
        redact_hostnames: bool = True,
    ) -> None:
        self.include_network_identifiers = include_network_identifiers
        self.redact_hostnames = redact_hostnames
        self._labels: dict[tuple[str, str], str] = {}
        self._label_salt = secrets.token_bytes(32)
        self.actions: set[str] = set()
        self.home = str(Path.home())

    def _label(self, kind: str, value: str) -> str:
        canonical = _canonical_label_value(kind, value)
        key = (kind, canonical)
        if key not in self._labels:
            digest = hashlib.sha256(
                self._label_salt
                + b"\0"
                + kind.encode("ascii", errors="replace")
                + b"\0"
                + canonical.encode("utf-8", errors="replace")
            ).hexdigest()[:12]
            self._labels[key] = f"<{kind}-{digest}>"
        return self._labels[key]

    def _redact_url(
        self,
        value: str,
        *,
        decode_parameter_values: bool = True,
    ) -> str:
        trailing = ""
        while value and value[-1] in ".,;)]}":
            trailing = value[-1] + trailing
            value = value[:-1]
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            # Invalid bracket/port syntax must fail closed.  Returning the raw
            # token here would re-expose userinfo or query credentials merely
            # because the surrounding URL is malformed.
            self.actions.add("malformed-url")
            if "@" in value:
                self.actions.add("url-credentials")
            return "<malformed-url-redacted>" + trailing

        netloc = parsed.netloc
        path_text = parsed.path
        userinfo = ""
        if "@" in netloc:
            host_part = netloc.rsplit("@", 1)[1]
            userinfo = "credentials-redacted@"
            netloc = f"{userinfo}{host_part}"
            self.actions.add("url-credentials")

        if hostname and not self.include_network_identifiers:
            address_hostname = hostname[:-1] if hostname.endswith(".") else hostname
            try:
                address = ipaddress.ip_address(address_hostname)
            except ValueError:
                integer_address = _legacy_integer_ip_value(address_hostname)
                address = (
                    ipaddress.IPv4Address(integer_address)
                    if integer_address is not None
                    else None
                )
            if address is not None:
                redacted_host = self._label("ip", hostname)
                self.actions.add("ip-address")
            elif _is_hostname(hostname, allow_single_label=True):
                redacted_host = self._label("host", hostname)
                self.actions.add("domain" if "." in hostname else "hostname")
            else:
                redacted_host = None
            if redacted_host is not None:
                port_suffix = f":{port}" if port is not None else ""
                netloc = f"{userinfo}{redacted_host}{port_suffix}"

        normalized_hostname = (hostname or "").casefold().rstrip(".")
        original_path = path_text
        if normalized_hostname == "hooks.slack.com" and path_text.startswith(
            "/services/"
        ):
            path_text = "/services/<webhook-redacted>"
        elif normalized_hostname in {"discord.com", "discordapp.com"}:
            path_text = re.sub(
                r"(?i)^(/api(?:/v[0-9]+)?/webhooks/[^/]+/)[^/]+",
                r"\1<webhook-redacted>",
                path_text,
            )
        elif normalized_hostname == "api.telegram.org":
            path_text = re.sub(
                r"(?i)^/bot[^/]+",
                "/bot<token-redacted>",
                path_text,
            )

        # The HTTP request target is also embedded in absolute observation URLs.
        # Apply the same conservative path rules independent of hostname so a
        # separately supplied scan path cannot reappear when target+path are
        # joined for evidence.
        path_text = re.sub(
            r"^/{1,2}[^/@\s:]+:[^/@\s]+@",
            "/credentials-redacted@",
            path_text,
        )
        for pattern, replacement in (
            (RELATIVE_SLACK_PATH_RE, "webhook-redacted"),
            (RELATIVE_DISCORD_PATH_RE, "webhook-redacted"),
            (RELATIVE_TELEGRAM_PATH_RE, "token-redacted"),
        ):
            path_text = pattern.sub(
                lambda match, marker=replacement: (
                    match.group("prefix") + f"<{marker}>"
                ),
                path_text,
            )
        if path_text != original_path:
            self.actions.add("url-path-secret")

        def redact_parameters(parameters: str) -> tuple[str, bool]:
            changed = False
            # Preserve order, spelling, duplicate keys and both commonly seen
            # separators. Rebuilding the full query through parse_qsl/urlencode
            # can silently drop malformed pieces and treats ';' as data on newer
            # Python versions, which leaves legacy signed URLs exposed.
            pieces = re.split(r"([&;])", parameters)
            for index in range(0, len(pieces), 2):
                parameter = pieces[index]
                key, separator, item = parameter.partition("=")
                if not separator:
                    continue
                normalized = _normalize_key(unquote_plus(key))
                if normalized in SENSITIVE_URL_PARAMETERS or _is_sensitive_key(
                    normalized
                ):
                    if unquote_plus(item) != "<redacted>":
                        pieces[index] = key + "=" + quote_plus("<redacted>")
                        changed = True
                    continue

                # Redirect/callback-style parameters often contain a complete
                # URL or request target. Inspect exactly one decoded layer with
                # network identifiers retained; if credential-only sanitation
                # changes it, redact the entire outer value. Disabling nested
                # value decoding keeps this bounded against recursive encoding.
                if decode_parameter_values:
                    decoded_item = unquote_plus(item)
                    credential_probe = Redactor(
                        include_network_identifiers=True,
                        redact_hostnames=False,
                    )
                    sanitized_item = credential_probe.text(
                        decoded_item,
                        _decode_url_parameter_values=False,
                    )
                    if sanitized_item != decoded_item:
                        pieces[index] = key + "=" + quote_plus("<redacted>")
                        self.actions.add("encoded-url-value-secret")
                        changed = True
            return ("".join(pieces) if changed else parameters, changed)

        if parsed.query:
            query_text, query_changed = redact_parameters(parsed.query)
            if query_changed:
                self.actions.add("url-query-secret")
        else:
            query_text = ""
        fragment_text = parsed.fragment
        if "=" in fragment_text:
            fragment_text, fragment_changed = redact_parameters(fragment_text)
            if fragment_changed:
                self.actions.add("url-fragment-secret")

        # urlsplit normalizes access to hostname/port but urlunsplit preserves the
        # original host spelling. Accessing these properties above also rejects
        # malformed ports before the URL is trusted as structured input.
        _ = (hostname, port)
        return urlunsplit(
            (parsed.scheme, netloc, path_text, query_text, fragment_text)
        ) + trailing

    def text(
        self,
        value: str,
        *,
        _decode_url_parameter_values: bool = True,
    ) -> str:
        # Normalize terminal controls before matching secrets.  Otherwise an
        # attacker-controlled command can split a header/token name with ANSI
        # or bidi controls so the safety patterns never see the real word.
        normalized = unicodedata.normalize("NFKC", value).translate(
            str.maketrans({"。": ".", "．": ".", "｡": "."})
        )
        if normalized != value:
            self.actions.add("unicode-normalization")
        controls_removed = normalized.replace("\r\n", "\n").replace("\r", "\n")
        controls_removed = ANSI_ESCAPE_RE.sub("", controls_removed)
        controls_removed = "".join(
            character
            for character in controls_removed
            if character in {"\n", "\t"}
            or (
                unicodedata.category(character) not in {"Cc", "Cf"}
                and character not in {"\u2028", "\u2029"}
            )
        )
        if controls_removed != normalized:
            self.actions.add("terminal-control")
        value = controls_removed

        result = PRIVATE_KEY_RE.sub("<private-key-redacted>", value)
        if result != value:
            self.actions.add("private-key")
        value = result

        result = PUTTY_PRIVATE_KEY_RE.sub("<private-key-redacted>", value)
        if result != value:
            self.actions.add("private-key")
        value = result

        # Encoded subscription links (notably vmess:// and ss://) do not expose
        # credentials as URL userinfo, so URL parsing alone cannot sanitize
        # them.  Treat every proxy-node URI as a credential-bearing secret.
        result = NODE_LINK_RE.sub("<node-link-redacted>", value)
        if result != value:
            self.actions.add("node-link")
        value = result

        result = KNOWN_TOKEN_RE.sub("<known-token-redacted>", value)
        if result != value:
            self.actions.add("known-token")
        value = result

        # Retaining network identifiers must never retain credentials embedded
        # in curl options. Redact the complete command because cookie/cert
        # option grammars accept attached, quoted, file and colon-password
        # forms that are unsafe to partially reconstruct.
        result = SENSITIVE_CURL_COMMAND_LINE_RE.sub(
            "<credential-command-redacted>", value
        )
        if result != value:
            self.actions.add("command-credential")
        value = result

        # These command grammars carry credentials outside ordinary key/value
        # syntax. Preserve no fragment of a recognised credential-bearing
        # command line because positional and attached forms are ambiguous.
        result = SENSITIVE_COMMAND_LINE_RE.sub(
            "<credential-command-redacted>", value
        )
        if result != value:
            self.actions.add("command-credential")
        value = result

        result = URL_RE.sub(
            lambda match: self._redact_url(
                match.group(0),
                decode_parameter_values=_decode_url_parameter_values,
            ),
            value,
        )
        value = result

        # Scheme-relative references are valid URL references too. Match them
        # even without a query so //user:password@host/path cannot bypass the
        # ordinary URL userinfo rule.
        result = NETWORK_PATH_URL_RE.sub(
            lambda match: self._redact_url(
                match.group(0),
                decode_parameter_values=_decode_url_parameter_values,
            ),
            value,
        )
        value = result

        # HTTP probe paths are deliberately relative (for example
        # /health?key=...). They do not match URL_RE but are persisted in local
        # bundles and reports, so sanitize their query/fragment credentials too.
        result = RELATIVE_URL_RE.sub(
            lambda match: self._redact_url(
                match.group(0),
                decode_parameter_values=_decode_url_parameter_values,
            ),
            value,
        )
        value = result

        # A single-slash HTTP request target is not parsed as URL netloc, but a
        # credential-shaped userinfo prefix is still unsafe to persist.
        result = RELATIVE_PATH_USERINFO_RE.sub(
            lambda match: match.group("prefix") + "credentials-redacted@",
            value,
        )
        if result != value:
            self.actions.add("url-credentials")
        value = result

        # scan_node stores the request target separately from its host. Apply
        # conservative provider-path rules without relying on a hostname; these
        # shapes carry webhook/bot credentials even when no query is present.
        provider_patterns = (
            (RELATIVE_SLACK_PATH_RE, "webhook-redacted"),
            (RELATIVE_DISCORD_PATH_RE, "webhook-redacted"),
            (RELATIVE_TELEGRAM_PATH_RE, "token-redacted"),
        )
        for pattern, replacement in provider_patterns:
            result = pattern.sub(
                lambda match, marker=replacement: (
                    match.group("prefix") + f"<{marker}>"
                ),
                value,
            )
            if result != value:
                self.actions.add("url-path-secret")
            value = result

        if not self.include_network_identifiers:
            result = NETWORK_COMMAND_LINE_RE.sub(
                "<network-command-redacted>", value
            )
            if result != value:
                self.actions.add("network-command")
            value = result

            def redact_unc_host(match: re.Match[str]) -> str:
                if not _is_network_name(match.group("host")):
                    return match.group(0)
                self.actions.add("hostname")
                return "\\\\" + self._label("host", match.group("host"))

            value = UNC_HOST_RE.sub(redact_unc_host, value)

            def redact_user_host(match: re.Match[str]) -> str:
                if not _is_network_name(match.group("host")):
                    return match.group(0)
                self.actions.add("hostname")
                return f"{match.group('user')}@{self._label('host', match.group('host'))}"

            value = USER_AT_HOST_RE.sub(redact_user_host, value)

            def redact_command_host(match: re.Match[str]) -> str:
                if not _is_network_name(match.group("host")):
                    return match.group(0)
                self.actions.add("hostname")
                return match.group("prefix") + self._label("host", match.group("host"))

            value = REMOTE_COMMAND_HOST_RE.sub(redact_command_host, value)
            value = REMOTE_COPY_HOST_RE.sub(redact_command_host, value)
            value = SSH_OPTION_HOST_RE.sub(redact_command_host, value)
            value = NETWORK_COMMAND_HOST_RE.sub(redact_command_host, value)

        result = SENSITIVE_HEADER_LINE_RE.sub(
            "<sensitive-header-removed-redacted>\n", value
        )
        if result != value:
            self.actions.add("sensitive-header")
        value = result

        result = SENSITIVE_QUOTED_HEADER_FIELD_RE.sub(
            "<sensitive-header-removed-redacted>", value
        )
        if result != value:
            self.actions.add("sensitive-header")
        value = result

        result = SENSITIVE_INLINE_HEADER_RE.sub(
            "<sensitive-header-removed-redacted>", value
        )
        if result != value:
            self.actions.add("sensitive-header")
        value = result

        result = AZURE_SECRET_ASSIGNMENT_RE.sub(
            "<secret-assignment-redacted>", value
        )
        if result != value:
            self.actions.add("secret-assignment")
        value = result

        result = SENSITIVE_ASSIGNMENT_RE.sub("<secret-assignment-redacted>", value)
        if result != value:
            self.actions.add("secret-assignment")
        value = result

        result = GENERIC_API_KEY_RE.sub("<api-key-redacted>", value)
        if result != value:
            self.actions.add("api-key")
        value = result

        result = BARE_BEARER_RE.sub("Bearer <redacted>", value)
        if result != value:
            self.actions.add("bearer-token")
        value = result

        def redact_basic(match: re.Match[str]) -> str:
            token = match.group("token")
            try:
                decoded = base64.b64decode(
                    token + "=" * (-len(token) % 4),
                    validate=True,
                )
            except (binascii.Error, ValueError):
                return match.group(0)
            if b":" not in decoded:
                return match.group(0)
            self.actions.add("basic-auth")
            return "Basic <redacted>"

        value = BARE_BASIC_RE.sub(redact_basic, value)

        result = CLI_CREDENTIAL_RE.sub(
            lambda match: f"{match.group('prefix')}<redacted>",
            value,
        )
        if result != value:
            self.actions.add("command-credential")
        value = result

        result = COMMAND_CREDENTIAL_RE.sub(
            "<command-credential-redacted>", value
        )
        if result != value:
            self.actions.add("command-credential")
        value = result

        for pattern in (
            LONG_OPTION_CREDENTIAL_RE,
            SPACE_CREDENTIAL_RE,
            SHORT_OPTION_CREDENTIAL_RE,
        ):
            result = pattern.sub(
                lambda match: f"{match.group('prefix')}<redacted>",
                value,
            )
            if result != value:
                self.actions.add("command-credential")
            value = result

        original = value
        if self.home:
            home_variants = {self.home, self.home.replace("\\", "/")}
            for home in sorted(home_variants, key=len, reverse=True):
                if home:
                    value = re.sub(
                        re.escape(home) + r"(?=$|[\\/])",
                        "<home>",
                        value,
                        flags=re.IGNORECASE if re.match(r"^[A-Za-z]:", home) else 0,
                    )
        value = GENERIC_HOME_PATH_RE.sub("<home>", value)
        if value != original:
            self.actions.add("home-path")

        result = UUID_RE.sub(lambda match: self._label("uuid", match.group(0)), value)
        if result != value:
            self.actions.add("uuid")
        value = result

        if not self.include_network_identifiers:

            def redact_ip(match: re.Match[str]) -> str:
                token = match.group(0)
                if not _is_ip_literal(token):
                    return token
                return self._label("ip", token)

            result = IP_TOKEN_RE.sub(redact_ip, value)
            if result != value:
                self.actions.add("ip-address")
            value = result

            def redact_legacy_integer_ip(match: re.Match[str]) -> str:
                token = match.group("ip")
                if _legacy_integer_ip_value(token) is None:
                    return match.group(0)
                self.actions.add("ip-address")
                return (
                    match.group("prefix")
                    + self._label("ip", token)
                    + match.group("suffix")
                )

            value = LEGACY_INTEGER_IP_CONTEXT_RE.sub(
                redact_legacy_integer_ip, value
            )

            result = MAC_RE.sub(lambda match: self._label("mac", match.group(0)), value)
            if result != value:
                self.actions.add("mac-address")
            value = result

            def redact_domain(match: re.Match[str]) -> str:
                token = match.group(0)
                if not _is_hostname(token, allow_single_label=False):
                    return token
                return self._label("host", token)

            result = DOMAIN_RE.sub(redact_domain, value)
            if result != value:
                self.actions.add("domain")
            value = result

            def redact_context_hostname(match: re.Match[str]) -> str:
                hostname = match.group("host")
                if not _is_network_name(hostname):
                    return match.group(0)
                self.actions.add("hostname")
                return (
                    match.group("prefix")
                    + match.group("open_quote")
                    + self._label("host", hostname)
                    + match.group("close_quote")
                )

            value = SINGLE_LABEL_HOST_CONTEXT_RE.sub(redact_context_hostname, value)

        # A complete request target may percent-encode its query marker or a
        # credential-bearing path rather than only encoding a parameter value.
        # Inspect one decoded layer at most, with network identifiers retained,
        # and fail closed on any credential/safety transformation.
        if _decode_url_parameter_values and "%" in value:
            decoded_value = unquote_plus(value)
            if decoded_value != value:
                probe_value = REDACTED_PARAMETER_RE.sub(
                    lambda match: (
                        match.group("separator")
                        + "netops_redacted=NETOPS_REDACTED"
                    ),
                    decoded_value,
                )
                probe_value = REDACTION_MARKER_RE.sub(
                    "NETOPS_REDACTED", probe_value
                )
                credential_probe = Redactor(
                    include_network_identifiers=True,
                    redact_hostnames=False,
                )
                sanitized_value = credential_probe.text(
                    probe_value,
                    _decode_url_parameter_values=False,
                )
                if sanitized_value != probe_value:
                    self.actions.add("encoded-credential")
                    return "<encoded-credential-redacted>"
        return value

    def value(
        self,
        data: Any,
        *,
        key: str | None = None,
        _path: tuple[str, ...] = (),
    ) -> Any:
        normalized_key = _normalize_key(key) if isinstance(key, str) else None
        host_keyed_mapping = bool(
            normalized_key and HOST_KEYED_MAPPING_RE.search(normalized_key)
        )
        if _is_sensitive_header_name(normalized_key):
            self.actions.add("sensitive-header")
            return None
        if _is_sensitive_key(normalized_key):
            self.actions.add("secret-key")
            return "<redacted>"

        if isinstance(data, str):
            if _path in {
                ("schema_version",),
                ("run_id",),
                ("observations", "observation_id"),
            }:
                # These exact root-schema identifiers are required for the
                # persisted bundle contract. In particular, a dotted schema
                # version such as ``2.0`` otherwise resembles a legacy IPv4
                # literal to the conservative text redactor. Nested fields
                # with the same names deliberately receive no bypass.
                return data
            if (
                normalized_key == "hostname"
                and self.redact_hostnames
                and not REDACTED_DEVICE_RE.fullmatch(data)
            ):
                self.actions.add("hostname")
                return self._label("device", data)
            if (
                not self.include_network_identifiers
                and normalized_key in NETWORK_IDENTIFIER_KEYS
            ):
                if _is_ip_literal(data):
                    self.actions.add("ip-address")
                    return self._label("ip", data)
                ssh_destination = _split_ssh_destination(data)
                if ssh_destination is not None:
                    user, hostname = ssh_destination
                    self.actions.add("ssh-destination")
                    return f"{user}@{self._label('host', hostname)}"
                host_port = _split_host_port(data)
                if host_port is not None:
                    hostname, port = host_port
                    self.actions.add("network-endpoint")
                    return f"{self._label('host', hostname)}:{port}"
                if normalized_key in {
                    "config_host",
                    "host_alias",
                    "management_reference",
                } and data:
                    self.actions.add("hostname")
                    return self._label("host", data)
                if _is_network_name(data):
                    self.actions.add("domain" if "." in data else "hostname")
                    return self._label("host", data)
            redacted_text = self.text(data)
            if (
                not self.include_network_identifiers
                and normalized_key in VANTAGE_POINT_KEYS
                and redacted_text == data
                and data not in PUBLIC_VANTAGE_POINTS
                and _is_network_name(data)
            ):
                self.actions.add("hostname")
                return self._label("host", data)
            return redacted_text
        if isinstance(data, list):
            if (
                normalized_key == "evidence"
                and _path
                in {("findings", "evidence"), ("path_segments", "evidence")}
                and all(
                    isinstance(item, str) and UUID_RE.fullmatch(item)
                    for item in data
                )
            ):
                # These are foreign-key references to observation_id values,
                # which are intentionally preserved. Keeping only this exact
                # schema location avoids making arbitrary environment evidence
                # an identifier-redaction bypass.
                return list(data)
            if (
                len(data) == 2
                and isinstance(data[0], str)
                and _is_sensitive_header_name(_normalize_key(data[0]))
            ):
                self.actions.add("sensitive-header")
                return None
            return [
                redacted
                for item in data
                # A list under ``targets``/``hosts`` normally contains records,
                # not a dictionary whose keys are hostnames. Do not inherit the
                # parent host-keyed-mapping interpretation into record fields;
                # scalar list entries still need their parent semantics.
                if (
                    redacted := self.value(
                        item,
                        key=None if isinstance(item, dict) else key,
                        _path=_path,
                    )
                )
                is not None
            ]
        if isinstance(data, tuple):
            return self.value(list(data), key=key, _path=_path)
        if isinstance(data, dict):
            canonical_items = [
                (
                    self.text(child_key) if isinstance(child_key, str) else child_key,
                    child_value,
                )
                for child_key, child_value in data.items()
            ]
            if any(
                isinstance(child_key, str)
                and _normalize_key(child_key) in HEADER_NAME_FIELDS
                and (
                    (
                        isinstance(child_value, str)
                        and _is_sensitive_header_name(_normalize_key(child_value))
                    )
                    or (
                        isinstance(child_value, (list, tuple))
                        and any(
                            isinstance(header_name, str)
                            and _is_sensitive_header_name(_normalize_key(header_name))
                            for header_name in child_value
                        )
                    )
                )
                for child_key, child_value in canonical_items
            ):
                # Header records are an open third-party shape. Once a record
                # declares a sensitive header name, no sibling field is safe to
                # preserve: an attacker can place the credential under ``val``,
                # ``payload``, ``data`` or another unrecognised key.
                self.actions.add("sensitive-header")
                return None
            sensitive_header_collections = {
                _normalize_key(child_key)
                for child_key, child_value in canonical_items
                if isinstance(child_key, str)
                and _normalize_key(child_key) in HEADER_COLLECTION_FIELDS
                and isinstance(child_value, (list, tuple))
                and any(
                    isinstance(header_name, str)
                    and _is_sensitive_header_name(_normalize_key(header_name))
                    for header_name in child_value[::2]
                    if _normalize_key(child_key) in {"raw_headers", "rawheaders"}
                )
            }
            sensitive_header_collections.update(
                _normalize_key(child_key)
                for child_key, child_value in canonical_items
                if isinstance(child_key, str)
                and _normalize_key(child_key) in {"header_names", "headernames"}
                and isinstance(child_value, (list, tuple))
                and any(
                    isinstance(header_name, str)
                    and _is_sensitive_header_name(_normalize_key(header_name))
                    for header_name in child_value
                )
            )
            result: dict[Any, Any] = {}
            for child_key, child_value in canonical_items:
                normalized_child = (
                    _normalize_key(child_key) if isinstance(child_key, str) else ""
                )
                if normalized_child in sensitive_header_collections or (
                    sensitive_header_collections
                    & {"header_names", "headernames"}
                    and normalized_child in {"values", "header_values", "headervalues"}
                ):
                    self.actions.add("sensitive-header")
                    continue
                if _is_sensitive_header_name(normalized_child):
                    self.actions.add("sensitive-header")
                    continue
                if _is_sensitive_key(normalized_child):
                    self.actions.add("secret-key")
                    result[child_key] = "<redacted>"
                    continue
                redacted_key = child_key
                if (
                    isinstance(child_key, str)
                    and not self.include_network_identifiers
                    and redacted_key == child_key
                    and host_keyed_mapping
                    and _is_network_name(child_key)
                ):
                    redacted_key = self._label("host", child_key)
                    self.actions.add("hostname")
                if redacted_key != child_key:
                    self.actions.add("mapping-key")
                if redacted_key in result:
                    # Redaction must not silently merge two independent evidence
                    # fields. Replace only the colliding key with a stable opaque
                    # label while retaining the already-safe value.
                    redacted_key = self._label("key", str(child_key))
                    self.actions.add("mapping-key-collision")
                # Classify the value with the canonical semantic key, not an
                # opaque mapping-key label introduced only for output. This
                # keeps network/secret semantics intact across key collisions.
                result[redacted_key] = self.value(
                    child_value,
                    key=child_key,
                    _path=(*_path, normalized_child),
                )
            return result
        return data
