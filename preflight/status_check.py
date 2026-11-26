"""Read-only prerequisite self-check for the Preflight dashboard.

Inspects local installation and readiness of OneVPN 1.5.1, LuLu 4.5.7,
Claude Desktop / CLI, the official Claude proxy configuration profile,
Dock launch watcher, and macOS Taiwan locale/timezone baseline.
Never exposes subscriptions, tokens, credentials, account emails, or IPs.
"""

import json
import os
from pathlib import Path
import plistlib
import shutil
import sys

from . import configuration
from . import dock
from . import firewall_setup
from . import guard
from . import native_firewall
from . import vpn_setup


_CLAUDE_APP = Path("/Applications/Claude.app")
_LULU_APP = Path("/Applications/LuLu.app")


def _app_version(app_path):
    info_plist = app_path / "Contents/Info.plist"
    if not info_plist.is_file():
        return None
    try:
        info = plistlib.loads(info_plist.read_bytes())
        return str(info.get("CFBundleShortVersionString") or "") or None
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None


def _claude_local_session_present():
    """Return True if local Claude Desktop or CLI appears to have an initialized login/session.

    Read-only presence check only — never reads or returns tokens, cookies, or emails.
    """
    home = Path.home()
    # Claude Desktop stores session storage / cookies / local-agent-mode-sessions under Application Support/Claude
    desktop_dir = home / "Library/Application Support/Claude"
    if desktop_dir.is_dir():
        cookies = desktop_dir / "Cookies"
        local_storage = desktop_dir / "Local Storage"
        if (cookies.is_file() and cookies.stat().st_size > 4096) or (
            local_storage.is_dir() and any(local_storage.iterdir())
        ):
            return True
    # Claude Code CLI stores oauthAccount metadata in ~/.claude.json when logged in
    cli_config = home / ".claude.json"
    if cli_config.is_file() and not cli_config.is_symlink():
        try:
            data = json.loads(cli_config.read_text(encoding="utf-8"))
            if isinstance(data, dict) and bool(data.get("oauthAccount")):
                return True
        except (OSError, ValueError):
            pass
    return False


def _claude_status():
    installed = _CLAUDE_APP.is_dir()
    version = _app_version(_CLAUDE_APP) if installed else None
    cli_installed = shutil.which("claude") is not None
    running = False
    if sys.platform == "darwin":
        try:
            running = any(row[3] == guard._DESKTOP for row in guard._processes())
        except (OSError, ValueError):
            pass
    session_detected = _claude_local_session_present()

    proxy_state = "unknown"
    profile_installed = None
    if sys.platform == "darwin":
        try:
            proxy_state = firewall_setup._proxy_state()
        except Exception:
            proxy_state = "unknown"
        try:
            profile_installed = firewall_setup._profile_installed()
        except Exception:
            profile_installed = None

    watcher = {"installed": False, "loaded": False, "running": False}
    if sys.platform == "darwin":
        try:
            watcher = dock.dock_watcher_status()
        except Exception:
            pass

    if not installed:
        state = "error"
        detail = "未安装 Claude 桌面版（/Applications/Claude.app）"
    elif proxy_state == "conflict":
        state = "error"
        detail = "检测到冲突的 Claude 代理或 PAC 配置"
    elif proxy_state != "ready":
        state = "pending"
        detail = "Claude 已安装，但固定代理描述文件尚未安装"
    elif not (watcher["installed"] and watcher["loaded"] and watcher["running"]):
        state = "pending"
        detail = "Claude 固定代理已就绪，Dock 启动监护尚未运行"
    else:
        state = "ok"
        detail = "Claude 桌面版、固定代理描述文件与 Dock 监护已就绪"

    return {
        "installed": installed,
        "version": version,
        "running": running,
        "cliInstalled": cli_installed,
        "sessionDetected": session_detected,
        "proxyState": proxy_state,
        "profileInstalled": bool(profile_installed or proxy_state == "ready"),
        "bundledProfileInstalled": bool(profile_installed),
        "watcher": watcher,
        "state": state,
        "detail": detail,
    }


def _lulu_status():
    installed = _LULU_APP.is_dir()
    version = _app_version(_LULU_APP) if installed else None
    report = native_firewall.inspect_desktop_firewall(guard.DESKTOP_PORT)
    findings = {item["name"]: item for item in report.get("findings", [])}
    extension_ok = bool(findings.get("extension", {}).get("passed"))
    filter_ok = bool(findings.get("socket_filter", {}).get("passed"))
    prefs_ok = all(
        findings.get(name, {}).get("passed", False)
        for name in ("enabled", "localhost", "dns", "allow_list", "block_mode")
    )
    rules_ok = bool(
        findings.get("bundle_block", {}).get("passed")
        and findings.get("relay_allow", {}).get("passed")
        and findings.get("conflicts", {}).get("passed")
    )
    conflict = "conflicts" in findings and not findings["conflicts"]["passed"]

    if not installed:
        state = "error"
        detail = "未安装官方 LuLu 防火墙（需 4.5.7）"
    elif report["configuration_ready"]:
        state = "ok"
        detail = "LuLu 4.5.7 扩展、过滤器、全局开关与 Claude 专用规则均已通过核验"
    elif conflict:
        state = "error"
        detail = "检测到与 Claude 保护冲突的 LuLu 放行规则"
    elif not extension_ok or not filter_ok:
        state = "pending"
        detail = "请在 macOS 系统设置中批准 LuLu 4.5.7 网络扩展与套接字过滤器"
    elif not prefs_ok:
        state = "pending"
        detail = "请启用 LuLu 并关闭回环、DNS、Allow List 或 Block Mode 等全局例外"
    else:
        state = "pending"
        detail = "LuLu 已启用，待一键合并导入 Claude 专用规则"

    return {
        "installed": installed,
        "version": version,
        "ready": report["configuration_ready"],
        "extensionReady": extension_ok,
        "socketFilterReady": filter_ok,
        "prefsReady": prefs_ok,
        "rulesReady": rules_ok,
        "conflict": conflict,
        "state": state,
        "detail": detail,
    }


def _region_status():
    if sys.platform != "darwin":
        return {
            "configured": False,
            "backupAvailable": False,
            "locale": None,
            "timezone": None,
            "autoTimezone": None,
            "state": "unknown",
            "detail": "仅支持 macOS",
        }
    res = configuration.configure("status")
    current = res.get("current") or {}
    configured = bool(res.get("configured"))
    if res.get("actionRequired") == "error":
        state = "unknown"
        detail = res.get("message") or "无法读取地区和时区"
    elif configured:
        state = "ok"
        detail = "macOS 地区已设为台湾（TW），时区已固定为 Asia/Taipei"
    else:
        state = "pending"
        detail = "macOS 地区或时区尚未切换为台湾（TW / Asia/Taipei）"
    return {
        "configured": configured,
        "backupAvailable": bool(res.get("backupAvailable")),
        "locale": current.get("effectiveLocale"),
        "timezone": current.get("timezone"),
        "autoTimezone": current.get("autoTimezone"),
        "state": state,
        "detail": detail,
    }


def _backups_status():
    region_backup = False
    firewall_backup = False
    vpn_backup = False
    try:
        region_backup = bool(configuration.configure("status").get("backupAvailable"))
    except Exception:
        pass
    try:
        fw_path = firewall_setup._folder() / "firewall-setup.json"
        firewall_backup = fw_path.is_file()
    except Exception:
        pass
    try:
        vpn_path = vpn_setup._folder() / "vpn-setup.json"
        vpn_backup = vpn_path.is_file()
    except Exception:
        pass
    return {
        "any": region_backup or firewall_backup or vpn_backup,
        "region": region_backup,
        "firewall": firewall_backup,
        "vpn": vpn_backup,
    }


def collect_readiness():
    """Return a full sanitized prerequisite self-check snapshot for the UI."""
    region = _region_status()
    vpn = vpn_setup.inspect_vpn_status(live_probe=False)
    lulu = _lulu_status()
    claude = _claude_status()
    backups = _backups_status()

    all_states = [region["state"], vpn["state"], lulu["state"], claude["state"]]
    if any(s == "error" for s in all_states):
        overall = "error"
    elif any(s == "pending" for s in all_states):
        overall = "pending"
    elif all(s == "ok" for s in all_states):
        overall = "ok"
    else:
        overall = "unknown"

    return {
        "overall": overall,
        "target": {"country": "TW", "timezone": "Asia/Taipei", "taiwanOnly": True},
        "region": region,
        "vpn": vpn,
        "lulu": lulu,
        "claude": claude,
        "backups": backups,
    }
