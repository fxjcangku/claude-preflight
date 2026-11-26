"""Guide and automate native Claude firewall setup and restore only managed changes."""

import json
import os
import plistlib
import stat
import subprocess
import sys
from pathlib import Path

from . import dock
from . import lulu_rules
from .guard import DESKTOP_PORT, _private_dir, _registry_lock
from .native_firewall import inspect_desktop_firewall

_PROFILE_ID = "org.claude-preflight.desktop-proxy"
_PROFILE_UUID = "33DB1C16-73A8-402A-827F-B9191BF19172"
_PROFILE = Path(__file__).resolve().parent.parent / "config/Claude-Preflight.mobileconfig"
_LULU = Path("/Applications/LuLu.app")
_PROFILE_SETTINGS = "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
_LULU_DOWNLOAD = "https://objective-see.org/products/lulu.html"
_KEYS = {"watcher_preexisting", "watcher_started", "profile_preexisting", "profile_requested"}
_OPTIONAL_KEYS = {
    "lulu_rules_preexisting",
    "lulu_managed_rules",
    "lulu_pending_import",
    "lulu_pending_restore",
    "lulu_user_backup",
}


def _reply(status, message, action=None, **details):
    return dict(status=status, message=message, actionRequired=action, **details)


def _folder():
    return Path.home() / "Library/Application Support/Claude Preflight"


def _proxy_state():
    # Return only the state; the managed values themselves can be private.
    script = '''ObjC.import("Foundation");
    const prefs=$.NSUserDefaults.alloc.initWithSuiteName("com.anthropic.claudefordesktop");
    const url=$("egressProxyUrl"), pac=$("egressProxyPacUrl");
    const fixed=ObjC.unwrap(prefs.stringForKey(url)), auto=ObjC.unwrap(prefs.stringForKey(pac));
    const forced=Boolean(prefs.objectIsForcedForKey(url));
    forced && fixed==="http://127.0.0.1:47836" && !auto ? "ready" :
      (forced || auto || (fixed && fixed!=="http://127.0.0.1:47836") ? "conflict" : "missing");'''
    result = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", "-e", script],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, timeout=6)
    state = result.stdout.strip()
    if state not in ("ready", "conflict", "missing"):
        raise ValueError("无法确定受管代理状态")
    return state


def _profile_installed():
    data = subprocess.run(["/usr/bin/profiles", "list", "-type", "configuration", "-output", "stdout-xml"],
                          env={"LC_ALL": "C", "PATH": os.defpath}, stdin=subprocess.DEVNULL,
                          capture_output=True, check=True, timeout=8).stdout
    profiles = plistlib.loads(data)
    if not isinstance(profiles, dict) or not all(isinstance(entries, list) for entries in profiles.values()):
        raise ValueError("无法核验已安装的描述文件")
    matching = [item for entries in profiles.values() for item in entries
                if isinstance(item, dict) and item.get("ProfileIdentifier") == _PROFILE_ID]
    if any(str(item.get("ProfileUUID", "")).upper() != _PROFILE_UUID for item in matching):
        raise ValueError("检测到同名的其他描述文件")
    return bool(matching)


def _read_record(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > 262144):
            raise ValueError("恢复记录无效")
        record = json.load(stream)
        if not isinstance(record, dict):
            raise ValueError("恢复记录无效")
        keys = set(record.keys())
        if not _KEYS <= keys or not keys <= (_KEYS | _OPTIONAL_KEYS):
            raise ValueError("恢复记录无效")
        if (any(type(record[k]) is not bool for k in _KEYS) or
                record["watcher_preexisting"] and record["watcher_started"] or
                record["profile_preexisting"] and record["profile_requested"]):
            raise ValueError("恢复记录无效")
        if "lulu_rules_preexisting" in record and type(record["lulu_rules_preexisting"]) is not bool:
            raise ValueError("恢复记录无效")
        if "lulu_managed_rules" in record and not isinstance(record["lulu_managed_rules"], list):
            raise ValueError("恢复记录无效")
        if record.get("lulu_rules_preexisting") and record.get("lulu_managed_rules"):
            raise ValueError("恢复记录无效")
        return record


def _save(path, record):
    dock._atomic_write(path, json.dumps(record, ensure_ascii=True).encode("ascii"))


def _failed_names(findings):
    return {item["name"] for item in findings.get("findings", []) if not item.get("passed")}


def _lulu_ready_for_rule_import(findings):
    """True when LuLu 4.5.7 extension, socket filter, and global prefs are ready,
    and only Claude bundle rules are missing."""
    failed = _failed_names(findings)
    if not failed:
        return False
    return failed <= {"bundle_block", "relay_allow"}


def _prerequisite(proxy_state, findings=None):
    if findings is None:
        findings = inspect_desktop_firewall(DESKTOP_PORT)
    if not findings["configuration_ready"]:
        failed = _failed_names(findings)
        detail = "；".join(x["detail"] for x in findings["findings"] if not x["passed"])
        if not _LULU.is_dir():
            return _reply("pending", "请先安装官方 LuLu 4.5.7 防火墙，然后重新点击一键配置。",
                          "lulu", openURL=_LULU_DOWNLOAD)
        if failed & {"extension", "socket_filter"}:
            return _reply("pending", "请在 macOS 系统设置中批准 LuLu 4.5.7 网络扩展与套接字过滤器，完成后再次点击一键配置。" + detail,
                          "lulu", openPath=str(_LULU))
        if failed & {"enabled", "localhost", "dns", "allow_list", "block_mode"}:
            return _reply("pending", "请在 LuLu 设置中启用防火墙并关闭全局例外开关（回环、DNS、Allow List、Block Mode），完成后再次核验。" + detail,
                          "lulu", openPath=str(_LULU))
        if failed & {"conflicts"}:
            return _reply("error", "检测到与 Claude 保护冲突的 LuLu 放行规则，请先在 LuLu 规则列表中核查并处理冲突项。")
        message = ("请在 LuLu 官方界面确认网络扩展。在 Rules 菜单为 Claude.app/Contents/* 分别添加"
                   "永久阻止所有连接和放行 127.0.0.1:47836 的规则，然后再次核验。" + detail)
        destination = {"openPath": str(_LULU)} if _LULU.is_dir() else {"openURL": _LULU_DOWNLOAD}
        return _reply("pending", message, "lulu", **destination)
    if proxy_state == "conflict":
        return _reply("error", "Claude 已有其他代理或 PAC 设置，请先向管理者确认。")
    if proxy_state == "missing":
        if not _PROFILE.is_file():
            return _reply("error", "应用内缺少 Claude Preflight 代理描述文件。")
        return _reply("pending", "请在系统设置中安装 Claude Preflight 描述文件，安装后再次核验。",
                      "profile", openPath=str(_PROFILE))
    return None


def _cleanup_staging(folder):
    for name in ("lulu-import.json", "lulu-restore.json"):
        (folder / name).unlink(missing_ok=True)


def _apply(path, record, verify_import=False):
    folder = path.parent
    watcher = dock.dock_watcher_status()
    proxy = _proxy_state()
    findings = inspect_desktop_firewall(DESKTOP_PORT)
    failed = _failed_names(findings)

    if record is None:
        rules_already_ok = bool(findings["configuration_ready"] or not (failed & {"bundle_block", "relay_allow"}))
        record = dict(
            watcher_preexisting=watcher["installed"] or watcher["loaded"],
            watcher_started=False,
            profile_preexisting=proxy == "ready" or _profile_installed(),
            profile_requested=False,
            lulu_rules_preexisting=rules_already_ok,
            lulu_managed_rules=[],
        )
        _save(path, record)

    # Verify a just-completed LuLu official UI rule import
    if verify_import and record.get("lulu_pending_import"):
        pending = record["lulu_pending_import"]
        try:
            lulu_rules.verify_apply_import(
                pending["managedRules"],
                pending["baselineFingerprint"],
                pending["baselineCount"],
                port=DESKTOP_PORT,
            )
        finally:
            _cleanup_staging(folder)
        record["lulu_rules_preexisting"] = False
        existing_managed = list(record.get("lulu_managed_rules") or [])
        existing_uuids = {r["uuid"] for r in existing_managed}
        for rule in pending["managedRules"]:
            if rule["uuid"] not in existing_uuids:
                existing_managed.append(rule)
        record["lulu_managed_rules"] = existing_managed
        record.pop("lulu_pending_import", None)
        _save(path, record)
        findings = inspect_desktop_firewall(DESKTOP_PORT)

    # If LuLu extension & global prefs are ready and ONLY Claude rules are missing,
    # prepare safe merged JSON for official LuLu UI import!
    if not findings["configuration_ready"] and _lulu_ready_for_rule_import(findings):
        plan = lulu_rules.plan_apply_import(folder, port=DESKTOP_PORT)
        if plan["needed"]:
            if "lulu_user_backup" not in record and plan["userRulesBackup"] is not None:
                record["lulu_user_backup"] = plan["userRulesBackup"]
            record["lulu_rules_preexisting"] = False
            record["lulu_pending_import"] = {
                "managedRules": plan["managedRules"],
                "baselineFingerprint": plan["baselineFingerprint"],
                "baselineCount": plan["baselineCount"],
            }
            _save(path, record)
            return _reply(
                "pending",
                "已备份现有 LuLu 规则并生成合并规则文件，准备通过 LuLu 官方导入界面添加 Claude 专用规则。",
                "luluImport",
                importPath=plan["importPath"],
                openPath=str(_LULU),
            )

    prerequisite = _prerequisite(proxy, findings=findings)
    if prerequisite:
        if prerequisite["actionRequired"] == "profile" and not record["profile_preexisting"]:
            record["profile_requested"] = True
            _save(path, record)
        return prerequisite
    if not record["watcher_preexisting"] and not record["watcher_started"] and not (watcher["installed"] or watcher["loaded"]):
        # Commit intent before launchctl can change registration, including partial failures.
        record["watcher_started"] = True
        _save(path, record)
    try:
        watcher = dock.install_dock_watcher()
    except ValueError as exc:
        if "Claude 退出后" in str(exc):
            return _quit_first()
        raise
    if not (watcher["installed"] and watcher["loaded"] and watcher["running"]):
        return _reply("pending", "Dock 监护尚未就绪，请再次核验。")
    return _reply("ok", "已核验 LuLu 和 Claude 固定代理，Dock 监护已运行。")


def _quit_first():
    return _reply("pending", "请完全退出 Claude 桌面版后重试，以保护当前连接。", "quitClaude")


def _restore(path, record, verify_import=False):
    folder = path.parent
    if record is None:
        return _reply("ok", "没有需要恢复的 Preflight 设置。")

    if record["watcher_started"]:
        state = dock.dock_watcher_status()
        if state["installed"] or state["loaded"]:
            if dock._candidate() is not None:
                return _quit_first()
            state = dock.uninstall_dock_watcher()
            if state["installed"] or state["loaded"]:
                return _reply("pending", "正在移除本应用启用的 Dock 监护，请再次恢复以核验。")
        record["watcher_started"] = False
        _save(path, record)

    # Verify just-completed LuLu surgical restore import
    conflicts = []
    if verify_import and record.get("lulu_pending_restore"):
        pending = record["lulu_pending_restore"]
        try:
            lulu_rules.verify_restore_import(
                pending["removedUuids"],
                pending["expectedFingerprint"],
                pending["expectedCount"],
            )
        finally:
            _cleanup_staging(folder)
        removed = set(pending["removedUuids"])
        record["lulu_managed_rules"] = [
            r for r in (record.get("lulu_managed_rules") or []) if r["uuid"] not in removed
        ]
        conflicts.extend(pending.get("conflicts") or [])
        record.pop("lulu_pending_restore", None)
        _save(path, record)

    # Remove ONLY LuLu rules that Preflight added (never touch preexisting rules!)
    managed_lulu = record.get("lulu_managed_rules") or []
    if managed_lulu and not record.get("lulu_rules_preexisting"):
        plan = lulu_rules.plan_restore_import(folder, managed_lulu)
        conflicts.extend(plan.get("conflicts") or [])
        if plan["needed"]:
            record["lulu_pending_restore"] = {
                "removedUuids": plan["removedUuids"],
                "expectedFingerprint": plan["expectedFingerprint"],
                "expectedCount": plan["expectedCount"],
                "conflicts": plan["conflicts"],
            }
            _save(path, record)
            return _reply(
                "pending",
                "准备通过 LuLu 官方导入界面仅移除 Preflight 新增的 Claude 规则，其他程序的规则将完整保留。",
                "luluRestore",
                importPath=plan["importPath"],
                openPath=str(_LULU),
            )
        record["lulu_managed_rules"] = []
        _save(path, record)

    if record["profile_requested"] and _profile_installed():
        return _reply("pending", "请在系统设置的设备管理中移除本次向导安装的 Claude Preflight 描述文件，然后再次恢复。",
                      "removeProfile", openURL=_PROFILE_SETTINGS)
    _cleanup_staging(folder)
    path.unlink()
    if conflicts:
        return _reply("ok", "已恢复本次向导管理的项目，部分规则保留了用户后续修改：" + "；".join(conflicts),
                      conflicts=conflicts)
    return _reply("ok", "已恢复本次向导管理的项目。")


def configure_firewall(action, verify=False):
    """Return a local UI result. Opening any settings panel belongs to the native host."""
    if action not in ("status", "apply", "restore") or sys.platform != "darwin":
        return _reply("error", "此操作需要 macOS 和有效的操作选项。")
    try:
        if action == "status":
            prerequisite = _prerequisite(_proxy_state())
            if prerequisite:
                return prerequisite
            watcher = dock.dock_watcher_status()
            if all(watcher[key] for key in ("installed", "loaded", "running")):
                return _reply("ok", "已核验 LuLu、Claude 固定代理及 Dock 监护。")
            return _reply("pending", "LuLu 与代理已就绪，可以启用 Dock 监护。")
        folder = _folder()
        if action == "restore" and not folder.exists():
            return _reply("ok", "没有需要恢复的 Preflight 设置。")
        path = _private_dir(folder) / "firewall-setup.json"
        with _registry_lock(folder):
            record = _read_record(path)
            return _apply(path, record, verify_import=verify) if action == "apply" else _restore(path, record, verify_import=verify)
    except ValueError as exc:
        return _reply("error", str(exc) or "无法核验或完成配置。")
    except (OSError, plistlib.InvalidFileException, subprocess.SubprocessError):
        return _reply("error", "无法核验或完成配置。请检查当前用户的描述文件、Dock 启动项与私有恢复记录后重试。")
