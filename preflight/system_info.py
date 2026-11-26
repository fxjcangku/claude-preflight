"""Read device preferences without starting the Claude CLI or changing settings."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _read_command(*arguments: str) -> Optional[str]:
    try:
        result = subprocess.run(
            arguments, capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _locale_parts(locale: Optional[str]):
    match = re.match(
        r"^[a-zA-Z]{2,8}(?:[-_]([a-zA-Z]{4}))?(?:[-_]([a-zA-Z]{2}|\d{3}))?(?=[_@.-]|$)",
        locale or "",
    )
    if not match:
        return None, None
    script, region = match.groups()
    return script.title() if script else None, region.upper() if region else None


def _zone_from_path(path: str) -> Optional[str]:
    try:
        resolved = str(Path(path).resolve(strict=True))
    except (OSError, RuntimeError):
        return None
    if "/zoneinfo/" not in resolved:
        return None
    zone = resolved.rsplit("/zoneinfo/", 1)[1]
    return zone.removeprefix("posix/").removeprefix("right/")


def _system_zone() -> Optional[str]:
    zone = _zone_from_path("/etc/localtime")
    if zone:
        return zone
    try:
        zone = Path("/etc/timezone").read_text().strip()
        ZoneInfo(zone)
    except (OSError, UnicodeError, ValueError, ZoneInfoNotFoundError):
        return None
    return zone


def _terminal_zone(system_zone: Optional[str]) -> Optional[str]:
    setting = os.environ.get("TZ")
    if setting is None:
        return system_zone
    if not setting:
        return "UTC"
    setting = setting.removeprefix(":")
    if setting.startswith("/"):
        return _zone_from_path(setting)
    try:
        ZoneInfo(setting)
        return setting
    except (OSError, ValueError, ZoneInfoNotFoundError):
        # A terminal can also use a POSIX TZ rule, such as UTC0 or EST5EDT.
        posix_rule = (
            r"[A-Za-z]{3,}[+-]?\d{1,2}(?::\d{2}){0,2}"
            r"(?:[A-Za-z]{3,}[A-Za-z0-9.,:/+-]*)?"
        )
        if re.fullmatch(posix_rule, setting):
            return setting
        return None


def _proxy_state(output: Optional[str]):
    if not output or not output.startswith("<dictionary>"):
        return None, "未知"
    flags = dict(re.findall(r"^  (\w+Enable)\s*:\s*([01])\s*$", output, re.M))
    labels = {
        "HTTPEnable": "HTTP",
        "HTTPSEnable": "HTTPS",
        "SOCKSEnable": "SOCKS",
        "ProxyAutoConfigEnable": "PAC",
        "ProxyAutoDiscoveryEnable": "自动发现",
    }
    enabled = [label for key, label in labels.items() if flags.get(key) == "1"]
    return bool(enabled), "、".join(enabled) if enabled else "未启用"


def read_system() -> dict:
    """Return a sanitized snapshot. Unavailable settings have the value None."""
    locale = language = script = region = automatic = None
    proxy_enabled, proxy_summary = None, "未知"
    if sys.platform == "darwin":
        defaults = "/usr/bin/defaults"
        locale = _read_command(defaults, "read", "-g", "AppleLocale") or None
        languages = _read_command(defaults, "read", "-g", "AppleLanguages")
        first = re.search(
            r'^\s*"?([a-zA-Z]{2,8}(?:[-_][a-zA-Z0-9]{1,8})*)"?\s*,?\s*$',
            languages or "",
            re.M,
        )
        language = first.group(1) if first else None
        locale_script, region = _locale_parts(locale)
        script = _locale_parts(language)[0] or locale_script
        value = _read_command(
            defaults, "read", "/Library/Preferences/com.apple.timezone.auto", "Active"
        )
        automatic = {"1": True, "0": False}.get(value)
        proxy_enabled, proxy_summary = _proxy_state(
            _read_command("/usr/sbin/scutil", "--proxy")
        )
    system_zone = _system_zone()
    return {
        "region": region,
        "locale": locale,
        "script": script,
        "language": language,
        "system_timezone": system_zone,
        "terminal_timezone": _terminal_zone(system_zone),
        "auto_timezone": automatic,
        "proxy_enabled": proxy_enabled,
        "proxy_summary": proxy_summary,
        "claude_available": shutil.which("claude") is not None,
    }
