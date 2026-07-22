from __future__ import annotations

import ipaddress
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

from . import FLEET_SCHEMA_VERSION
from .redaction import Redactor
from .util import load_json_limited, trusted_system_environment


SECRET_KEYS = {
    "access_token",
    "accesstoken",
    "api_key",
    "apikey",
    "password",
    "passphrase",
    "private_key",
    "privatekey",
    "refresh_token",
    "refreshtoken",
    "client_secret",
    "clientsecret",
    "token",
    "api_token",
    "apitoken",
    "secret",
    "secret_key",
    "secretkey",
    "uuid",
    "proxy_password",
    "proxypassword",
}
SECRET_KEY_SEGMENTS = {
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
NON_SECRET_KEYS = {"token_count"}
HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
FLEET_ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
SSH_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
SSH_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SSH_CONFIG_HOST_CONFLICT_FIELDS = ("user", "port", "identity_file")
ROOT_KEYS = {"schema_version", "fleet_name", "hosts"}
HOST_KEYS = {
    "alias",
    "role",
    "management",
    "ssh",
    "domains",
    "expected_services",
    "labels",
}
MANAGEMENT_KEYS = {"address", "panel_reference"}
SSH_KEYS = {
    "user",
    "port",
    "config_host",
    "identity_file",
    "credential_reference",
    "password_env",
}
DOMAIN_KEYS = {"ipv4", "ipv6", "panel"}
MAX_HOSTS = 256
MAX_DOMAIN_VALUES = 64
MAX_SERVICES = 64
MAX_LABELS = 64
_NON_SECRET_REDACTION_ACTIONS = {"home-path"}
TRANSPORT_ENVIRONMENT_KEYS = {
    "PATH",
    "HOME",
    "USERPROFILE",
    "USER",
    "LOGNAME",
    "SSH_AUTH_SOCK",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_TIME",
    "LC_NUMERIC",
    "LC_MONETARY",
    "LC_COLLATE",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TMPDIR",
    "TEMP",
    "TMP",
}


def _require_exact_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        raise ValueError(f"{label} contains unsupported fields: {extras}")


def _review_string(
    value: Any,
    *,
    label: str,
    nullable: bool = False,
    maximum: int = 1_024,
) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or value != value.strip():
        suffix = " or null" if nullable else ""
        raise ValueError(f"{label} must be a non-empty unpadded string{suffix}")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds the {maximum}-character limit")
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        or character in {"\u2028", "\u2029"}
        for character in value
    ):
        raise ValueError(f"{label} contains control characters")
    redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    redactor.text(value)
    unsafe_actions = redactor.actions - _NON_SECRET_REDACTION_ACTIONS
    if unsafe_actions:
        raise ValueError(f"{label} must not contain credentials or secret material")
    return value


def _safe_reference(value: Any, *, label: str) -> None:
    _review_string(value, label=label, nullable=True)


def _valid_hostname(value: str) -> bool:
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or len(candidate) > 253:
        return False
    return all(HOST_LABEL_RE.fullmatch(label) for label in candidate.split("."))


def _validate_domain_name(value: Any, *, label: str) -> str:
    value = _review_string(value, label=label, maximum=253)
    assert value is not None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError(f"{label} must be a hostname, not an IP address")
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"{label} is not a valid hostname") from exc
    if not _valid_hostname(ascii_name):
        raise ValueError(f"{label} is not a valid hostname")
    return value


def _validate_host_token(value: Any, *, label: str, allow_ip: bool) -> str:
    reviewed = _review_string(value, label=label, maximum=253)
    assert reviewed is not None
    value = reviewed
    if any(character in value for character in ("@", "/")) or any(
        unicodedata.category(character) in {"Cc", "Cf"}
        or character in {"\u2028", "\u2029"}
        for character in value
    ):
        raise ValueError(f"{label} contains unsafe characters")
    if value.startswith("-"):
        raise ValueError(f"{label} must not begin with an option prefix")
    if allow_ip:
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            if _valid_hostname(value):
                return value
    elif SSH_ALIAS_RE.fullmatch(value):
        return value
    raise ValueError(f"{label} is not a valid host or SSH config alias")


def load_fleet(path: str | Path) -> dict[str, Any]:
    source = Path(os.path.abspath(Path(path).expanduser()))
    fleet = load_json_limited(source, max_bytes=4 * 1_048_576)
    validate_fleet(fleet)
    return fleet


def _validate_ssh_mode(ssh: dict[str, Any], *, label: str) -> None:
    if ssh.get("config_host") is None:
        return
    conflicts = [
        field
        for field in SSH_CONFIG_HOST_CONFLICT_FIELDS
        if ssh.get(field) is not None
    ]
    if conflicts:
        raise ValueError(
            f"{label}.config_host cannot be combined with direct SSH fields: "
            f"{', '.join(conflicts)}"
        )
    # password_env remains valid with an SSH config alias: it controls the
    # authentication transport and is not a destination override.


def validate_fleet(fleet: dict[str, Any]) -> None:
    if not isinstance(fleet, dict):
        raise ValueError("fleet must be an object")
    _require_exact_keys(fleet, ROOT_KEYS, "fleet")
    if fleet.get("schema_version") != FLEET_SCHEMA_VERSION:
        raise ValueError(
            f"fleet schema must be {FLEET_SCHEMA_VERSION!r}, "
            f"got {fleet.get('schema_version')!r}"
        )
    fleet_name = fleet.get("fleet_name")
    _review_string(fleet_name, label="fleet.fleet_name", maximum=128)
    hosts = fleet.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("fleet.hosts must be a non-empty list")
    if len(hosts) > MAX_HOSTS:
        raise ValueError(f"fleet.hosts must contain at most {MAX_HOSTS} hosts")
    aliases: set[str] = set()
    for host in hosts:
        if not isinstance(host, dict):
            raise ValueError("every fleet host must be an object")
        leaked = _secret_keys(host)
        if leaked:
            raise ValueError(f"secret fields are forbidden in fleet files: {sorted(leaked)}")
        _require_exact_keys(host, HOST_KEYS, "fleet host")
        missing = {"alias", "role", "management", "ssh", "domains"} - set(host)
        if missing:
            raise ValueError(f"fleet host is missing required fields: {sorted(missing)}")
        alias = host.get("alias")
        if not isinstance(alias, str) or not FLEET_ALIAS_RE.fullmatch(alias):
            raise ValueError("every host needs a lowercase DNS-safe alias")
        _review_string(alias, label="fleet host alias", maximum=63)
        if alias in aliases:
            raise ValueError(f"duplicate host alias: {alias}")
        aliases.add(alias)
        _review_string(
            host.get("role"),
            label=f"host {alias!r} role",
            maximum=128,
        )
        management = host.get("management")
        if not isinstance(management, dict):
            raise ValueError(f"host {alias!r} management must be an object")
        _require_exact_keys(management, MANAGEMENT_KEYS, f"host {alias!r} management")
        if "address" not in management:
            raise ValueError(f"host {alias!r} management.address is required")
        address = management.get("address")
        _validate_host_token(
            address,
            label=f"host {alias!r} management.address",
            allow_ip=True,
        )
        _safe_reference(
            management.get("panel_reference"),
            label=f"host {alias!r} management.panel_reference",
        )
        ssh = host.get("ssh")
        if not isinstance(ssh, dict):
            raise ValueError(f"host {alias!r} ssh must be an object")
        _require_exact_keys(ssh, SSH_KEYS, f"host {alias!r} ssh")
        config_host = ssh.get("config_host")
        if config_host is not None:
            _validate_host_token(
                config_host,
                label=f"host {alias!r} ssh.config_host",
                allow_ip=False,
            )
        user = ssh.get("user")
        if user is not None and (
            not isinstance(user, str) or not SSH_USER_RE.fullmatch(user)
        ):
            raise ValueError(f"host {alias!r} has invalid ssh.user")
        if user is not None:
            _review_string(user, label=f"host {alias!r} ssh.user", maximum=64)
        password_env = ssh.get("password_env")
        if password_env is not None and (
            not isinstance(password_env, str)
            or not ENVIRONMENT_NAME_RE.fullmatch(password_env)
        ):
            raise ValueError(f"host {alias!r} has invalid ssh.password_env")
        if password_env is not None:
            _review_string(
                password_env,
                label=f"host {alias!r} ssh.password_env",
                maximum=128,
            )
        port = ssh.get("port", 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(f"host {alias!r} has invalid ssh.port")
        identity = ssh.get("identity_file")
        _safe_reference(identity, label=f"host {alias!r} ssh.identity_file")
        _safe_reference(
            ssh.get("credential_reference"),
            label=f"host {alias!r} ssh.credential_reference",
        )
        _validate_ssh_mode(ssh, label=f"host {alias!r} ssh")
        domains = host.get("domains")
        if not isinstance(domains, dict):
            raise ValueError(f"host {alias!r} domains must be an object")
        _require_exact_keys(domains, DOMAIN_KEYS, f"host {alias!r} domains")
        for family, values in domains.items():
            if not isinstance(values, list) or not all(
                isinstance(value, str) for value in values
            ):
                raise ValueError(
                    f"host {alias!r} domains.{family} must contain strings"
                )
            if len(values) > MAX_DOMAIN_VALUES:
                raise ValueError(
                    f"host {alias!r} domains.{family} must contain at most "
                    f"{MAX_DOMAIN_VALUES} values"
                )
            if len(values) != len(set(values)):
                raise ValueError(f"host {alias!r} domains.{family} contains duplicates")
            for index, value in enumerate(values):
                _validate_domain_name(
                    value,
                    label=f"host {alias!r} domains.{family}[{index}]",
                )
        services = host.get("expected_services", [])
        if not isinstance(services, list) or not all(
            isinstance(service, str) for service in services
        ):
            raise ValueError(f"host {alias!r} expected_services must be strings")
        if len(services) > MAX_SERVICES or len(services) != len(set(services)):
            raise ValueError(
                f"host {alias!r} expected_services must contain at most "
                f"{MAX_SERVICES} unique service names"
            )
        for service in services:
            if not SERVICE_RE.fullmatch(service):
                raise ValueError(f"host {alias!r} has invalid expected service {service!r}")
            _review_string(
                service,
                label=f"host {alias!r} expected service",
                maximum=256,
            )
        labels = host.get("labels", {})
        if not isinstance(labels, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in labels.items()
        ):
            raise ValueError(f"host {alias!r} labels must map strings to strings")
        if len(labels) > MAX_LABELS:
            raise ValueError(f"host {alias!r} labels must contain at most {MAX_LABELS} items")
        for key, value in labels.items():
            _review_string(key, label=f"host {alias!r} label key", maximum=64)
            _review_string(
                value,
                label=f"host {alias!r} labels[{key!r}]",
                maximum=256,
            )


def _secret_keys(value: Any, *, _path: tuple[str, ...] = ()) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            canonical = unicodedata.normalize("NFKC", key)
            canonical = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", canonical)
            canonical = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", canonical)
            normalized = re.sub(
                r"[^a-z0-9]+", "_", canonical.casefold()
            ).strip("_")
            compact = normalized.replace("_", "")
            segments = set(normalized.split("_"))
            safe_ssh_reference = _path[-1:] == ("ssh",) and normalized in {
                "credential_reference",
                "password_env",
            }
            if not safe_ssh_reference and normalized not in NON_SECRET_KEYS and (
                normalized in SECRET_KEYS
                or compact in SECRET_KEYS
                or bool(segments & SECRET_KEY_SEGMENTS)
                or "private_key" in normalized
                or "api_key" in normalized
            ):
                found.add(key)
            found.update(_secret_keys(child, _path=(*_path, normalized)))
    elif isinstance(value, list):
        for child in value:
            found.update(_secret_keys(child, _path=_path))
    return found


def get_host(fleet: dict[str, Any], alias: str) -> dict[str, Any]:
    for host in fleet.get("hosts", []):
        if host.get("alias") == alias:
            return host
    raise KeyError(f"unknown fleet host alias: {alias}")


def _validated_destination_fields(host: dict[str, Any]) -> tuple[dict[str, Any], str, Any]:
    if not isinstance(host, dict):
        raise ValueError("host must be an object")
    leaked = _secret_keys(host)
    if leaked:
        raise ValueError(f"secret fields are forbidden in host data: {sorted(leaked)}")
    ssh = host.get("ssh") or {}
    if not isinstance(ssh, dict):
        raise ValueError("ssh must be an object")
    config_host = ssh.get("config_host")
    if config_host is not None:
        address = _validate_host_token(
            config_host,
            label="ssh.config_host",
            allow_ip=False,
        )
    else:
        management = host.get("management") or {}
        if not isinstance(management, dict):
            raise ValueError("management must be an object")
        address = _validate_host_token(
            management.get("address"),
            label="management.address",
            allow_ip=True,
        )
    user = ssh.get("user")
    if user is not None and (
        not isinstance(user, str) or not SSH_USER_RE.fullmatch(user)
    ):
        raise ValueError("invalid ssh.user")
    if user is not None:
        _review_string(user, label="ssh.user", maximum=64)
    port = ssh.get("port", 22)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid ssh.port")
    _safe_reference(ssh.get("identity_file"), label="ssh.identity_file")
    _safe_reference(
        ssh.get("credential_reference"),
        label="ssh.credential_reference",
    )
    password_env = ssh.get("password_env")
    if password_env is not None and (
        not isinstance(password_env, str)
        or not ENVIRONMENT_NAME_RE.fullmatch(password_env)
    ):
        raise ValueError("invalid ssh.password_env")
    if password_env is not None:
        _review_string(password_env, label="ssh.password_env", maximum=128)
    _validate_ssh_mode(ssh, label="ssh")
    return ssh, address, config_host


def ssh_destination(host: dict[str, Any]) -> tuple[list[str], str]:
    ssh, address, config_host = _validated_destination_fields(host)
    user = ssh.get("user")
    destination = f"{user}@{address}" if user and not config_host else address
    password_env = ssh.get("password_env")
    options = [
        "-o",
        f"BatchMode={'no' if password_env else 'yes'}",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
    ]
    if not config_host:
        options.extend(
            [
                "-F",
                "none",
                "-o",
                f"HostName={address}",
                "-o",
                "CanonicalizeHostname=no",
                "-o",
                "ProxyCommand=none",
                "-o",
                "ProxyJump=none",
                "-p",
                str(ssh.get("port", 22)),
            ]
        )
        identity = ssh.get("identity_file")
        if identity:
            options.extend(
                [
                    "-o",
                    "IdentitiesOnly=yes",
                    "-i",
                    str(Path(identity).expanduser()),
                ]
            )
    return options, destination


def scp_destination(host: dict[str, Any]) -> tuple[list[str], str]:
    ssh, address, config_host = _validated_destination_fields(host)
    user = ssh.get("user")
    raw_address = address
    if not config_host:
        try:
            if ipaddress.ip_address(address).version == 6:
                address = f"[{address}]"
        except ValueError:
            pass
    destination = f"{user}@{address}" if user and not config_host else address
    password_env = ssh.get("password_env")
    options = [
        "-o",
        f"BatchMode={'no' if password_env else 'yes'}",
        "-o",
        "ConnectTimeout=10",
    ]
    if not config_host:
        options.extend(
            [
                "-F",
                "none",
                "-o",
                f"HostName={raw_address}",
                "-o",
                "CanonicalizeHostname=no",
                "-o",
                "ProxyCommand=none",
                "-o",
                "ProxyJump=none",
                "-P",
                str(ssh.get("port", 22)),
            ]
        )
        identity = ssh.get("identity_file")
        if identity:
            options.extend(
                [
                    "-o",
                    "IdentitiesOnly=yes",
                    "-i",
                    str(Path(identity).expanduser()),
                ]
            )
    return options, destination


def _password_transport(host: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    password_env = (host.get("ssh") or {}).get("password_env")
    if not password_env:
        return [], {}
    password = os.environ.get(password_env)
    if password is None:
        raise ValueError(
            f"SSH password environment variable {password_env!r} is not set"
        )
    return ["sshpass", "-e"], {"SSHPASS": password}


def _transport_environment() -> dict[str, str]:
    """Expose only variables required by SSH itself, never the caller's secrets."""

    return trusted_system_environment(include_home=True, include_ssh_auth=True)


def ssh_invocation(host: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    options, destination = ssh_destination(host)
    prefix, password_env = _password_transport(host)
    environment = _transport_environment()
    environment.update(password_env)
    return [*prefix, "ssh", *options, destination], environment


def scp_invocation(
    host: dict[str, Any], local_path: str, remote_path: str
) -> tuple[list[str], dict[str, str]]:
    options, destination = scp_destination(host)
    prefix, password_env = _password_transport(host)
    environment = _transport_environment()
    environment.update(password_env)
    return [
        *prefix,
        "scp",
        *options,
        local_path,
        f"{destination}:{remote_path}",
    ], environment
