"""Inspect LuLu 4.5.7 configuration for the installed Claude bundle, read-only.

The result describes persisted policy, not traffic observed by the kernel. LuLu's
live XPC service requires the signature of its own client. See the tagged
LuLu/Extension/{Rules,FilterDataProvider,Preferences,XPCListener}.m sources.
"""

import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from xml.parsers.expat import ExpatError


_LULU = Path("/Library/Objective-See/LuLu")
_CONTENTS = "/Applications/Claude.app/Contents/"
_DIRECTORIES = {_CONTENTS + "*", "/Applications/Claude.app/*"}
_EXTENSION = re.compile(
    r"^\s*\*\s+\*\s+VBG97UB4TA\s+com\.objective-see\.lulu\.extension\s+"
    r"\(([^)]+)\)\s+[^\n]*\[activated enabled\]\s*$", re.MULTILINE,
)


def _load(path):
    with path.open("rb") as handle:
        return plistlib.load(handle)


def _socket_filter_enabled():
    """NE configuration is distinct from system extension registration."""
    archive = _load(Path("/Library/Preferences/com.apple.networkextension.plist"))
    if archive["$archiver"] != "NSKeyedArchiver":
        raise ValueError("无法识别系统网络过滤器配置")
    objects = archive["$objects"]

    def resolve(value):
        if not isinstance(value, plistlib.UID):
            return value
        return objects[value.data] if value.data else None

    matches = []
    for ref in archive["$top"].values():
        config = resolve(ref)
        if not isinstance(config, dict) or resolve(config.get("Application")) != "com.objective-see.lulu.app":
            continue
        content = resolve(config["ContentFilter"])
        provider = resolve(content["Provider"])
        matches.append(
            resolve(content.get("Enabled")) is True
            and resolve(content["PerApp"]) is None
            and resolve(provider.get("FilterSockets")) is True
            and resolve(provider.get("DataProviderBundleIdentifier")) == "com.objective-see.lulu.extension"
        )
    return matches == [True]


def _profile():
    prefs = _load(_LULU / "preferences.plist")
    if not isinstance(prefs, dict):
        raise ValueError("LuLu 配置格式未知")
    active = prefs.get("currentProfile")
    if active is None:
        return _LULU, prefs
    if not isinstance(active, str) or not active:
        raise ValueError("LuLu 的当前配置路径无效")
    directory = Path(active).resolve(strict=True)
    if directory.parent != (_LULU / "Profiles").resolve(strict=True):
        raise ValueError("无法确认 LuLu 的活动配置目录")
    prefs = _load(directory / "preferences.plist")
    if not isinstance(prefs, dict):
        raise ValueError("LuLu 活动配置格式未知")
    return directory, prefs


def _read_rules(path):
    """Read only the live root's rule groups. Never instantiate archived classes."""
    archive = _load(path)
    if archive["$archiver"] != "NSKeyedArchiver":
        raise ValueError("未知的 LuLu 规则存档格式")
    objects = archive["$objects"]

    def obj(ref):
        if not isinstance(ref, plistlib.UID) or not 0 <= ref.data < len(objects):
            raise ValueError("无效的 LuLu 规则引用")
        return objects[ref.data] if ref.data else None

    def cls(record):
        return obj(record["$class"])["$classname"]

    def mapping(record):
        if cls(record) not in ("NSDictionary", "NSMutableDictionary"):
            raise ValueError("未知的 LuLu 规则字典类型")
        keys, values = record["NS.keys"], record["NS.objects"]
        if len(keys) != len(values):
            raise ValueError("LuLu 规则字典不完整")
        result = {obj(k): obj(v) for k, v in zip(keys, values)}
        if len(result) != len(keys):
            raise ValueError("LuLu 规则字典包含重复项")
        return result

    groups = []
    for key, item in mapping(obj(archive["$top"]["root"])).items():
        group = mapping(item)
        rules = group["rules"]
        if cls(rules) not in ("NSArray", "NSMutableArray"):
            raise ValueError("未知的 LuLu 规则列表类型")
        paths = group.get("paths")
        if paths is not None and cls(paths) not in ("NSSet", "NSMutableSet"):
            raise ValueError("未知的 LuLu 进程路径列表")
        aliases = [obj(v) for v in paths["NS.objects"]] if paths else []
        for ref in rules["NS.objects"]:
            item = obj(ref)
            if cls(item) != "Rule":
                raise ValueError("未知的 LuLu 规则类型")
            fields = ("key", "path", "action", "endpointAddr", "endpointPort",
                      "endpointHost", "scope", "expiration", "pid", "isDisabled",
                      "isEndpointAddrRegex")
            rule = {k: obj(item[k]) for k in fields}
            if (not isinstance(key, str) or key != rule["key"]
                    or not isinstance(rule["path"], str)
                    or not all(isinstance(p, str) for p in aliases)
                    or rule["action"] not in (0, 1)):
                raise ValueError("无法核对 LuLu 规则归属或动作")
            groups.append((key, aliases, rule))
    return groups


def _inside_or_overlaps(path):
    if path == "*" or path.startswith(_CONTENTS):
        return True
    return path.endswith("/*") and _CONTENTS.startswith(path[:-1])


def _code_identities():
    """Account for specific rules keyed by signing ID, even at another path."""
    root = Path(_CONTENTS)
    if not root.is_dir():
        raise ValueError("未找到标准位置的 Claude.app")
    magic = {bytes.fromhex(v) for v in ("feedface", "feedfacf", "cefaedfe",
                                        "cffaedfe", "cafebabe", "bebafeca",
                                        "cafebabf", "bfbafeca")}
    ids = set()
    # A bundle includes native helpers without their own Info.plist. Inspect
    # executable Mach-O files, avoiding nested Python/JS data and frameworks
    # loaded as libraries. rglob does not descend into directory symlinks.
    for path in root.rglob("*"):
        if (path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK)
                or path.suffix in (".dylib", ".node", ".so")):
            continue
        with path.open("rb") as stream:
            if stream.read(4) not in magic:
                continue
        env = dict(os.environ, LC_ALL="C")
        result = subprocess.run(
            ["/usr/bin/codesign", "-dv", str(path)], capture_output=True,
            timeout=3, text=True, check=False, env=env,
        )
        # Non-signed executables use their path for LuLu matching.
        if "not signed at all" in result.stderr:
            continue
        if result.returncode:
            raise ValueError("无法核对 Claude 内部程序的签名标识")
        match = re.search(r"^Identifier=(.+)$", result.stderr, re.MULTILINE)
        if not match:
            raise ValueError("Claude 内部程序的签名标识未知")
        ids.add(match[1])
    if not ids:
        raise ValueError("无法识别 Claude 安装包的可执行文件")
    return ids


def _assess_rules(groups, port, ids):
    block = allow = conflict = False
    for key, aliases, rule in groups:
        if rule["isDisabled"]:
            continue
        path = rule["path"]
        related = (any(_inside_or_overlaps(p) for p in [key, path, *aliases])
                   or key.partition(":")[0] in ids or rule["scope"] == 2)
        if not related:
            continue
        # Scope 2 applies to descendants; a transient/overlapping allow may
        # already be in use. Only permanent bundle rules count toward readiness.
        permanent = rule["pid"] is None and rule["expiration"] is None
        package = key == path and path in _DIRECTORIES and permanent
        address, endpoint_port = rule["endpointAddr"], rule["endpointPort"]
        exact_proxy = (address == "127.0.0.1" and endpoint_port == str(port)
                       and rule["endpointHost"] in (None, "127.0.0.1")
                       and rule["isEndpointAddrRegex"] == 0)
        if rule["action"] == 1:
            if package and exact_proxy:
                allow = True
            elif not exact_proxy:
                conflict = True
        elif package and address == "*" and endpoint_port == "*":
            block = True
        elif endpoint_port == str(port) and address != "*":
            conflict = True
    return block, allow, conflict


def inspect_desktop_firewall(port: int) -> dict:
    """Report configuration readiness separately from runtime enforcement."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("无效的本机受管代理端口")
    findings = []

    def add(name, passed, detail):
        findings.append({"name": name, "passed": bool(passed), "detail": detail})

    result = {"configuration_ready": False, "runtime_verified": False, "findings": findings}
    if sys.platform != "darwin":
        add("macos", False, "原生桌面保护仅适用于 macOS")
        return result
    try:
        listing = subprocess.run(
            ["/usr/bin/systemextensionsctl", "list"], check=True,
            capture_output=True, text=True, timeout=3,
        ).stdout
        matched = _EXTENSION.search(listing)
        known_version = matched and matched[1] == "4.5.7/4.5.7"
        add("extension", known_version, "LuLu 4.5.7 扩展已注册并启用" if known_version
            else "未确认受支持的 LuLu 4.5.7 扩展已注册并启用")
        if not known_version:
            return result
        add("socket_filter", _socket_filter_enabled(), "macOS 必须启用 LuLu 的全系统套接字过滤器")
        directory, prefs = _profile()
        # LuLu persists both plist booleans and NSNumber integer flags.
        def off(key, default=None):
            flag = prefs.get(key, default)
            return type(flag) in (int, bool) and flag == 0
        add("enabled", off("disabled"), "活动配置必须明确启用 LuLu")
        add("localhost", off("allowLocalHost"), "需要关闭全局回环放行")
        add("dns", off("allowDNS"), "需要关闭系统代办 DNS 放行例外")
        add("allow_list", off("useAllowList", False), "需要关闭全局放行列表")
        add("block_mode", off("blockMode", False), "全局封锁模式会覆盖端口放行")
        groups = _read_rules(directory / "rules.plist")
        block, allow, conflict = _assess_rules(groups, port, _code_identities())
        add("bundle_block", block, "需要覆盖 Claude.app 或其 Contents 目录的永久全地址全端口阻止规则")
        add("relay_allow", allow, f"需要同一目录仅放行 127.0.0.1:{port} 的永久精确规则")
        add("conflicts", not conflict, "检查全局、目录、进程与子进程规则的冲突放行")
    except (OSError, TypeError, ValueError, RuntimeError, KeyError, IndexError,
            AttributeError, ExpatError, plistlib.InvalidFileException, subprocess.SubprocessError):
        add("read", False, "无法完整核对活动配置、规则存档或应用签名")
    result["configuration_ready"] = all(f["passed"] for f in findings)
    return result


def assert_desktop_firewall(port: int) -> None:
    """Require the persisted LuLu configuration. This is not a runtime probe."""
    report = inspect_desktop_firewall(port)
    if not report["configuration_ready"]:
        failures = [item["detail"] for item in report["findings"] if not item["passed"]]
        raise ValueError("原生桌面防火墙配置校验失败：" + "；".join(failures))
