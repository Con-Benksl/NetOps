from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any

from . import FLEET_SCHEMA_VERSION


SECRET_KEYS = {
    "password",
    "passphrase",
    "private_key",
    "token",
    "api_token",
    "secret",
    "uuid",
    "proxy_password",
}


def load_fleet(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    with source.open("r", encoding="utf-8") as handle:
        fleet = json.load(handle)
    validate_fleet(fleet)
    fleet["_source"] = str(source)
    return fleet


def validate_fleet(fleet: dict[str, Any]) -> None:
    if fleet.get("schema_version") != FLEET_SCHEMA_VERSION:
        raise ValueError(
            f"fleet schema must be {FLEET_SCHEMA_VERSION!r}, "
            f"got {fleet.get('schema_version')!r}"
        )
    hosts = fleet.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("fleet.hosts must be a non-empty list")
    aliases: set[str] = set()
    for host in hosts:
        if not isinstance(host, dict):
            raise ValueError("every fleet host must be an object")
        leaked = _secret_keys(host)
        if leaked:
            raise ValueError(f"secret fields are forbidden in fleet files: {sorted(leaked)}")
        alias = host.get("alias")
        if not isinstance(alias, str) or not alias.strip():
            raise ValueError("every host needs a non-empty alias")
        if alias in aliases:
            raise ValueError(f"duplicate host alias: {alias}")
        aliases.add(alias)
        management = host.get("management") or {}
        address = management.get("address")
        if not isinstance(address, str) or not address.strip():
            raise ValueError(f"host {alias!r} needs management.address")
        port = (host.get("ssh") or {}).get("port", 22)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"host {alias!r} has invalid ssh.port")
        identity = (host.get("ssh") or {}).get("identity_file")
        if identity is not None and not isinstance(identity, str):
            raise ValueError(f"host {alias!r} identity_file must be a path string")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            if any(ch.isspace() for ch in address):
                raise ValueError(f"host {alias!r} management.address contains whitespace")


def _secret_keys(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SECRET_KEYS:
                found.add(key)
            found.update(_secret_keys(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_secret_keys(child))
    return found


def get_host(fleet: dict[str, Any], alias: str) -> dict[str, Any]:
    for host in fleet.get("hosts", []):
        if host.get("alias") == alias:
            return host
    raise KeyError(f"unknown fleet host alias: {alias}")


def ssh_destination(host: dict[str, Any]) -> tuple[list[str], str]:
    ssh = host.get("ssh") or {}
    config_host = ssh.get("config_host")
    address = config_host or (host.get("management") or {}).get("address")
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
        options.extend(["-p", str(ssh.get("port", 22))])
        identity = ssh.get("identity_file")
        if identity:
            options.extend(["-i", str(Path(identity).expanduser())])
    return options, destination


def scp_destination(host: dict[str, Any]) -> tuple[list[str], str]:
    ssh = host.get("ssh") or {}
    config_host = ssh.get("config_host")
    address = config_host or (host.get("management") or {}).get("address")
    user = ssh.get("user")
    destination = f"{user}@{address}" if user and not config_host else address
    password_env = ssh.get("password_env")
    options = [
        "-o",
        f"BatchMode={'no' if password_env else 'yes'}",
        "-o",
        "ConnectTimeout=10",
    ]
    if not config_host:
        options.extend(["-P", str(ssh.get("port", 22))])
        identity = ssh.get("identity_file")
        if identity:
            options.extend(["-i", str(Path(identity).expanduser())])
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


def ssh_invocation(host: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    options, destination = ssh_destination(host)
    prefix, env = _password_transport(host)
    return [*prefix, "ssh", *options, destination], env


def scp_invocation(
    host: dict[str, Any], local_path: str, remote_path: str
) -> tuple[list[str], dict[str, str]]:
    options, destination = scp_destination(host)
    prefix, env = _password_transport(host)
    return [
        *prefix,
        "scp",
        *options,
        local_path,
        f"{destination}:{remote_path}",
    ], env
