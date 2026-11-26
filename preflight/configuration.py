"""Reversible, current-user locale and administrator-assisted macOS time settings."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .system_info import _automatic_timezone, _system_zone


_ZONE = "Asia/Taipei"
_KEYS = {"locale", "timezone", "autoTimezone"}
_LOCALE = re.compile(r"^(?P<language>[A-Za-z]{2,8})(?:[-_][A-Za-z]{4})?(?:[-_](?P<region>[A-Za-z]{2}|[0-9]{3}))?(?=[_@.-]|$)")
_LOCALE_READ = '''
ObjC.import("Foundation");
const d=$.NSUserDefaults.standardUserDefaults;
const v=ObjC.unwrap(d.persistentDomainForName($.NSGlobalDomain).objectForKey("AppleLocale"));
JSON.stringify({locale:v===undefined ? null : v,
 effectiveLocale:ObjC.unwrap($.NSLocale.currentLocale.localeIdentifier),
 localeForced:Boolean(d.objectIsForcedForKey("AppleLocale"))});
'''
_CORE = '''
ObjC.import("Foundation");
if (!$.NSBundle.bundleWithPath("/System/Library/PrivateFrameworks/CoreTime.framework").load) throw Error("CoreTime unavailable");
ObjC.bindFunction("TMSetAutomaticTimeZoneEnabled", ["void", ["bool"]]);
ObjC.bindFunction("TMIsAutomaticTimeZoneEnabled", ["bool", []]);
'''
_BASELINE_NOTE = "复原基准是 App 首次改动该项前的实际设置。"


def _folder():
    return Path.home() / "Library/Application Support/Claude Preflight/configuration"


def _command(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=10, env={"PATH": os.defpath, "LC_ALL": "C"})
    if result.returncode:
        raise ValueError("系统设置命令未成功。")
    return result.stdout


def _taiwan_locale(value):
    match = _LOCALE.match(value) if isinstance(value, str) else None
    if not match or len(value) > 1024 or any(ord(char) < 32 for char in value):
        raise ValueError("无法确定当前语言和地区。")
    if match.group("region"):
        return value[:match.start("region")] + "TW" + value[match.end("region"):]
    return value[:match.end()] + "_TW" + value[match.end():]


def _valid_zone(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", value):
        return False
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        return False
    return True


def _read():
    if sys.platform != "darwin":
        raise ValueError("此配置仅支持 macOS。")
    info = json.loads(_command(["/usr/bin/osascript", "-l", "JavaScript", "-e", _LOCALE_READ]))
    if not isinstance(info, dict) or set(info) != {"locale", "effectiveLocale", "localeForced"}:
        raise ValueError("无法读取当前用户的地区设置。")
    if info["locale"] is not None:
        _taiwan_locale(info["locale"])
    _taiwan_locale(info["effectiveLocale"])
    if type(info["localeForced"]) is not bool:
        raise ValueError("无法确认地区设置是否受管理。")
    info.update(timezone=_system_zone(), autoTimezone=_automatic_timezone())
    if not _valid_zone(info["timezone"]) or type(info["autoTimezone"]) is not bool:
        raise ValueError("无法确认系统时区或自动时区状态。")
    return info


def _write_locale(value):
    argv = ["/usr/bin/defaults"]
    if value is None:
        argv += ["delete", "NSGlobalDomain", "AppleLocale"]
    else:
        argv += ["write", "NSGlobalDomain", "AppleLocale", "-string", value]
    _command(argv)


def _private(info, directory=False):
    right_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not right_type or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("配置备份的位置或权限不安全。")


@contextlib.contextmanager
def _locked_folder(create):
    folder = _folder()
    if create:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(folder, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        yield None
        return
    try:
        _private(os.fstat(fd), directory=True)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield folder
    finally:
        os.close(fd)


def _backup_record(folder):
    if folder is None:
        return {}, {}
    try:
        fd = os.open(folder / "original.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}, {}
    with os.fdopen(fd, encoding="utf-8") as stream:
        _private(os.fstat(fd))
        record = json.loads(stream.read(8193))
    if not isinstance(record, dict) or record.get("version") != 1:
        raise ValueError("配置备份格式无法识别。")
    values = record.get("original")
    if not isinstance(values, dict) or not values or not set(values) <= _KEYS:
        raise ValueError("配置备份内容无法识别。")
    if "locale" in values and values["locale"] is not None:
        _taiwan_locale(values["locale"])
    if "timezone" in values and not _valid_zone(values["timezone"]):
        raise ValueError("备份中的时区无效。")
    if "autoTimezone" in values and type(values["autoTimezone"]) is not bool:
        raise ValueError("备份中的自动时区设置无效。")
    applied = record.get("applied")
    if applied is None:
        applied = {}
    if not isinstance(applied, dict) or not set(applied) <= _KEYS:
        raise ValueError("配置备份的已应用记录无效。")
    return values, applied


def _backup(folder):
    return _backup_record(folder)[0]


def _save(folder, original, applied=None):
    payload = {"version": 1, "original": original}
    if applied:
        payload["applied"] = applied
    with tempfile.NamedTemporaryFile(mode="w", dir=folder, prefix=".settings-", delete=False) as f:
        tmp = Path(f.name)
        try:
            json.dump(payload, f, ensure_ascii=True)
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp, folder / "original.json")
        dirfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        tmp.unlink(missing_ok=True)


def _goals(current, action, original):
    if action == "restore":
        return dict(original)
    current_locale = current["locale"] or current["effectiveLocale"]
    desired = _taiwan_locale(current_locale)
    goals = {"timezone": _ZONE, "autoTimezone": False}
    # A missing preference already resolving to Taiwan remains missing.
    if current["locale"] is not None or desired != current_locale:
        goals["locale"] = desired
    return goals


def _plan(current, goals):
    plan = []
    zone = goals.get("timezone", current["timezone"])
    auto = goals.get("autoTimezone", current["autoTimezone"])
    zone_change = zone != current["timezone"]
    if current["autoTimezone"] and (not auto or zone_change):
        plan.append({"operation": "setAutomaticTimezone", "enabled": False})
    if zone_change:
        plan.append({"operation": "setTimezone", "timezone": zone})
    if auto and (not current["autoTimezone"] or zone_change):
        plan.append({"operation": "setAutomaticTimezone", "enabled": True})
    return plan


def _admin_script(plan):
    lines = ["set -e"]
    for step in plan:
        if step["operation"] == "setTimezone":
            zone = step["timezone"]
            if not _valid_zone(zone):
                raise ValueError("时区无效。")
            lines.append(shlex.join(["/usr/sbin/systemsetup", "-settimezone", zone]))
        else:
            enabled = "true" if step["enabled"] else "false"
            script = _CORE + f"$.TMSetAutomaticTimeZoneEnabled({enabled});"
            script += f" for (let i=0;i<20 && Boolean($.TMIsAutomaticTimeZoneEnabled())!=={enabled};i++) $.NSThread.sleepForTimeInterval(0.1);"
            script += f' if (Boolean($.TMIsAutomaticTimeZoneEnabled())!=={enabled}) throw Error("time zone setting not confirmed");'
            lines.append(shlex.join(["/usr/bin/osascript", "-l", "JavaScript", "-e", script]))
    return "\n".join(lines)


def _result(action, message, current=None, original=None, plan=None, error=False, conflicts=None):
    configured = bool(current and _taiwan_locale(current["effectiveLocale"]) == current["effectiveLocale"]
                      and current["timezone"] == _ZONE and current["autoTimezone"] is False)
    return {"action": action, "ok": not error and not plan, "configured": configured,
            "actionRequired": "error" if error else "admin" if plan else "none",
            "adminScript": _admin_script(plan) if plan else None, "adminPlan": plan or [],
            "current": current, "backupAvailable": bool(original), "message": message,
            "baselineNote": _BASELINE_NOTE, "conflicts": conflicts or []}


def _restore_conflicts(current, original, applied):
    labels = {"locale": "系统地区", "timezone": "系统时区", "autoTimezone": "自动时区开关"}
    goals = {}
    conflicts = []
    for key, orig_val in original.items():
        if key in applied and current[key] != applied[key] and current[key] != orig_val:
            conflicts.append(f"{labels[key]}在配置后已被用户手动修改，已保留当前设置")
        else:
            goals[key] = orig_val
    return goals, conflicts


def configure(action="status", verify=False):
    """Configure as the current user. Only the native host may request elevation."""
    current = original = None
    try:
        if action not in ("status", "taiwan", "restore"):
            raise ValueError("配置操作无效。")
        with _locked_folder(create=action == "taiwan" and not verify) as folder:
            original, applied = _backup_record(folder)
            current = _read()
            if action == "status":
                return _result(action, "已读取当前设置。", current, original)
            if action == "restore" and not original:
                return _result(action, "没有由 App 改动且需要复原的设置。", current)
            conflicts = []
            if action == "restore":
                goals, conflicts = _restore_conflicts(current, original, applied)
            else:
                goals = _goals(current, action, original)
            changes = {key: value for key, value in goals.items() if current[key] != value}
            if "locale" in changes and current["localeForced"]:
                raise ValueError("地区设置由管理描述文件控制，无法更改。")
            if "locale" in changes and not verify:
                if action == "taiwan":
                    updated = dict(original)
                    if "locale" not in updated:
                        updated["locale"] = current["locale"]
                    updated_applied = dict(applied, locale=changes["locale"])
                    _save(folder, updated, updated_applied)
                    original, applied = updated, updated_applied
                _write_locale(changes["locale"])
                current = _read()
            if "locale" in goals and current["locale"] != goals["locale"]:
                raise ValueError("地区设置尚未按预期生效，已保留备份。")
            if action == "taiwan" and _taiwan_locale(current["effectiveLocale"]) != current["effectiveLocale"]:
                raise ValueError("系统当前地区尚未生效，已保留备份。")
            plan = _plan(current, goals)
            if plan and verify:
                raise ValueError("系统时区或自动时区尚未按预期生效，已保留备份。")
            if plan:
                if action == "taiwan":
                    missing = {key: current[key] for key in ("timezone", "autoTimezone")
                               if current[key] != goals[key] and key not in original}
                    new_applied = dict(applied)
                    for key in ("timezone", "autoTimezone"):
                        if key in goals and (current[key] != goals[key] or key in original):
                            new_applied[key] = goals[key]
                    if missing or new_applied != applied:
                        updated = dict(original, **missing)
                        _save(folder, updated, new_applied)
                        original, applied = updated, new_applied
                return _result(action, "请通过 macOS 管理员授权完成时区设置。", current, original, plan, conflicts=conflicts)
            if action == "restore":
                (folder / "original.json").unlink()
                if conflicts:
                    return _result(action, "已复原未冲突的设置，以下项目保留了用户后续修改：" + "；".join(conflicts),
                                   current, conflicts=conflicts)
                return _result(action, "已核对并复原 App 改动的设置。", current)
            return _result(action, "已核对台湾地区和台北时区。", current, original)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        msg = str(exc) if type(exc) is ValueError else "无法读取或写入配置，请检查设置后重试。"
        return _result(action, msg, current, original, error=True)
