"""Collect independent observations and compare them with the user's targets."""
import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .network import _ISO_COUNTRIES, probe_network
from .system_info import read_system


DEFAULT_TARGET = {"country": "TW", "timezone": "Asia/Taipei"}


def validate_target(country, timezone):
    if not isinstance(country, str) or country.strip().upper() not in _ISO_COUNTRIES:
        raise ValueError("请输入有效的两位地区代码，例如 TW。")
    if not isinstance(timezone, str):
        raise ValueError("请输入 IANA 时区，例如 Asia/Taipei。")
    zone = timezone.strip()
    try:
        ZoneInfo(zone)
    except (ValueError, OSError, ZoneInfoNotFoundError):
        raise ValueError("找不到这个 IANA 时区，例如可以填写 Asia/Taipei。") from None
    return {"country": country.strip().upper(), "timezone": zone}


def preferences_path():
    return Path.home() / "Library" / "Application Support" / "Claude Preflight" / "target.json"


def load_target():
    try:
        data = json.loads(preferences_path().read_text(encoding="utf-8"))
        return validate_target(data["country"], data["timezone"])
    except FileNotFoundError:
        return dict(DEFAULT_TARGET)
    except (TypeError, KeyError, ValueError):
        raise ValueError("本地检测目标文件损坏，请检查 " + str(preferences_path())) from None


def save_target(target):
    path = preferences_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     delete=False) as f:
        tmp = Path(f.name)
        try:
            json.dump(target, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)


def snapshot(network_probe=None):
    with ThreadPoolExecutor(max_workers=2) as workers:
        network = workers.submit(probe_network if network_probe is None else network_probe)
        system = read_system()
        net = network.result()
    return {"time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "network": net, "system": system}


def evaluate(sample, target):
    net, sys = sample["network"], sample["system"]
    values = [
        ("country", "网络出口地区", net["country"], target["country"]),
        ("region", "macOS 地区", sys["region"], target["country"]),
        ("system_timezone", "系统时区", sys["system_timezone"], target["timezone"]),
        ("terminal_timezone", "终端时区", sys["terminal_timezone"], target["timezone"]),
    ]
    checks = []
    for key, label, actual, expected in values:
        status = "unknown" if not actual else ("pass" if actual == expected else "fail")
        checks.append(dict(key=key, label=label, actual=actual, expected=expected, status=status))
    statuses = {c["status"] for c in checks}
    status = "fail" if "fail" in statuses else ("unknown" if "unknown" in statuses else "pass")
    return {"status": status, "checks": checks}
