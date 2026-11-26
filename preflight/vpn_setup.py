"""Multi-phase, reversible OneVPN 1.5.1 Taiwan node and Claude split-rule setup.

OneVPN 1.5.1 disables the local Mihomo REST controller by default. Changes are
performed in three explicit phases coordinated by the native host:
  1. prepare: lock all guarded sessions, inspect the active profile, and list
              opaque Taiwan node candidates (never exposing subscription URLs,
              credentials, or raw node names in replies).
  2. commit:  after OneVPN has exited cleanly, re-read the latest Flutter
              preferences, save a private first-time baseline backup, merge the
              selected node and Claude split rules while preserving all
              unrelated rules and subscriptions, and read back to confirm.
  3. verify:  after OneVPN has relaunched, wait for GUI, OneVPNCore, proxy
              listener, and utun tunnel readiness, then live-probe the exit via
              the verified OneVPN proxy to confirm real TW egress.
"""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from . import guard
from .network import probe_network


_ONEVPN_APP = Path("/Applications/OneVPN.app")
_KNOWN_VPN_APPS = (
    ("OneVPN", "OneVPN.app", True),
    ("Clash Verge", "Clash Verge.app", False),
    ("ClashX Pro", "ClashX Pro.app", False),
    ("ClashX", "ClashX.app", False),
    ("Mihomo Party", "Mihomo Party.app", False),
    ("FlClash", "FlClash.app", False),
    ("Clash Nyanpasu", "Clash Nyanpasu.app", False),
    ("Surge", "Surge.app", False),
    ("V2rayU", "V2rayU.app", False),
    ("V2RayXS", "V2RayXS.app", False),
    ("Shadowrocket", "Shadowrocket.app", False),
    ("ShadowsocksX-NG", "ShadowsocksX-NG.app", False),
    ("Sing-box", "SFM.app", False),
    ("Hiddify", "Hiddify.app", False),
    ("Tailscale", "Tailscale.app", False),
    ("WireGuard", "WireGuard.app", False),
    ("Mullvad VPN", "Mullvad VPN.app", False),
    ("ProtonVPN", "ProtonVPN.app", False),
    ("Cloudflare WARP", "Cloudflare WARP.app", False),
    ("ExpressVPN", "ExpressVPN.app", False),
    ("Surfshark", "Surfshark.app", False),
    ("NordVPN", "NordVPN.app", False),
)
_ONEVPN_DOMAIN = "top.proxy101.onevpn"
_ONEVPN_KEY = "flutter.config"
_CLAUDE_DOMAINS = (
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "claude.app",
    "claudeusercontent.com",
    "claudemcpcontent.com",
)
_TAIWAN_RE = re.compile(
    r"(?:🇹🇼|台湾|臺灣|台北|臺北|taipei|taiwan|(?:^|[^A-Za-z])TW(?:$|[^A-Za-z]))",
    re.IGNORECASE,
)
_EXCLUDE_NODE_RE = re.compile(
    r"(?:剩余|流量|到期|官网|更新|地址|阻断|套餐|续费|重置|通知|过期|客服|失联|"
    r"expire|traffic|reset|notice|website|update|quota|remain)",
    re.IGNORECASE,
)
_SPECIAL_TARGETS = frozenset(("DIRECT", "REJECT", "COMPATIBLE", "PASS", "REJECT-DROP"))
_ENV = {"LC_ALL": "C", "PATH": os.defpath}
_WAIT_READY_SECONDS = 25.0
_POLL_INTERVAL = 0.5


def _folder():
    return Path.home() / "Library/Application Support/Claude Preflight"


def _profiles_dir():
    return Path.home() / "Library/Application Support/OneVPN/profiles"


def _reply(status, message, action=None, **details):
    return dict(status=status, message=message, actionRequired=action, **details)


def _node_token(name):
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def _atomic_write_json(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=".vpn-setup-", delete=False) as stream:
        tmp = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp, path)
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        tmp.unlink(missing_ok=True)


@contextlib.contextmanager
def _locked_state(create=True):
    folder = _folder()
    if create:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(folder, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        yield None, None
        return
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("配置备份目录权限不安全")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield folder, folder / "vpn-setup.json"
    finally:
        os.close(fd)


def _read_backup(path):
    if path is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, encoding="utf-8") as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > 131072):
            raise ValueError("OneVPN 恢复备份无效")
        data = json.loads(stream.read(131073))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("OneVPN 恢复备份格式无效")
    required = {
        "version", "profileId", "hadProxySelection", "originalProxy",
        "appliedNode", "originalOverrideEnable", "originalRuleType",
        "managedRules", "replacedRules",
    }
    if not required <= set(data):
        raise ValueError("OneVPN 恢复备份内容不完整")
    if (not isinstance(data["profileId"], str) or not data["profileId"]
            or type(data["hadProxySelection"]) is not bool
            or type(data["originalOverrideEnable"]) is not bool
            or not isinstance(data["managedRules"], list)
            or not isinstance(data["replacedRules"], list)):
        raise ValueError("OneVPN 恢复备份字段无效")
    return data


def _read_flutter_config():
    result = subprocess.run(
        ["/usr/bin/defaults", "read", _ONEVPN_DOMAIN, _ONEVPN_KEY],
        env=_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=6,
    )
    if result.returncode != 0:
        raise ValueError("未能读取 OneVPN 配置，请确认已安装并打开过 OneVPN。")
    try:
        data = json.loads(result.stdout)
    except ValueError:
        raise ValueError("OneVPN 配置数据格式无法解析。") from None
    if not isinstance(data, dict):
        raise ValueError("OneVPN 配置结构无效。")
    return data


def _write_flutter_config(config):
    payload = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    result = subprocess.run(
        ["/usr/bin/defaults", "write", _ONEVPN_DOMAIN, _ONEVPN_KEY, "-string", payload],
        env=_ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8,
    )
    if result.returncode != 0:
        raise ValueError("写入 OneVPN 配置失败。")


def _onevpn_processes():
    core_path = str(Path.home() / "Library/Application Support/OneVPN/OneVPNCore")
    table = guard._processes()
    gui = [p for p in table if p[3] == guard._GUI and p[1] == os.getuid()]
    core = [p for p in table if p[3] == core_path and p[1] == 0]
    return gui, core


def _active_profile(config):
    current_id = config.get("currentProfileId")
    profiles = config.get("profiles")
    if not isinstance(current_id, str) or not current_id or not isinstance(profiles, list):
        raise ValueError("未找到 OneVPN 当前活动订阅配置，请先在 OneVPN 中导入订阅。")
    matches = [p for p in profiles if isinstance(p, dict) and p.get("id") == current_id]
    if len(matches) != 1:
        raise ValueError("无法唯一确定 OneVPN 当前活动配置。")
    return current_id, matches[0]


def _unquote_yaml_scalar(raw):
    text = raw.strip()
    if not text:
        return ""
    if text[0] == "'" and len(text) >= 2:
        # YAML single-quoted string: '' represents literal '
        end = 1
        out = []
        while end < len(text):
            if text[end] == "'":
                if end + 1 < len(text) and text[end + 1] == "'":
                    out.append("'")
                    end += 2
                    continue
                return "".join(out)
            out.append(text[end])
            end += 1
        return "".join(out)
    if text[0] == '"' and len(text) >= 2:
        try:
            # Find closing unescaped quote
            i = 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    return json.loads(text[:i + 1])
                i += 1
        except ValueError:
            pass
    # Unquoted scalar: strip trailing comment preceded by whitespace
    cleaned = re.split(r"\s+#", text, maxsplit=1)[0].strip()
    return cleaned


def _extract_flow_name(line):
    """Extract the `name` field from an inline Clash YAML proxy mapping."""
    brace = line.find("{")
    if brace < 0:
        return None
    body = line[brace + 1:]
    match = re.search(r"(?:^|[,{]\s*)name\s*:\s*", body)
    if not match:
        return None
    rest = body[match.end():].lstrip()
    if not rest:
        return None
    if rest[0] == "'":
        return _unquote_yaml_scalar(rest)
    if rest[0] == '"':
        return _unquote_yaml_scalar(rest)
    # Unquoted value ends at comma or closing brace
    end = re.search(r"[,}]", rest)
    return (rest[:end.start()] if end else rest).strip()


def _parse_clash_profile(yaml_text):
    """Parse proxy names and proxy-groups from a Clash/Mihomo YAML profile."""
    proxies = []
    groups = {}
    section = None
    section_indent = -1
    current_group = None
    in_group_proxies = False
    group_proxies_indent = -1
    in_block_proxy = False

    for raw_line in yaml_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0 and not stripped.startswith("-"):
            key = stripped.partition(":")[0].strip()
            section = key if key in ("proxies", "proxy-groups") else None
            section_indent = indent
            current_group = None
            in_group_proxies = False
            in_block_proxy = False
            continue

        if section == "proxies":
            if stripped.startswith("-"):
                after = stripped[1:].lstrip()
                if after.startswith("{"):
                    name = _extract_flow_name(after)
                    if name:
                        proxies.append(name)
                    in_block_proxy = False
                elif after.startswith("name:"):
                    name = _unquote_yaml_scalar(after.partition(":")[2])
                    if name:
                        proxies.append(name)
                    in_block_proxy = True
                else:
                    in_block_proxy = True
            elif in_block_proxy and stripped.startswith("name:"):
                name = _unquote_yaml_scalar(stripped.partition(":")[2])
                if name:
                    proxies.append(name)
                in_block_proxy = False

        elif section == "proxy-groups":
            if stripped.startswith("-"):
                after = stripped[1:].lstrip()
                if in_group_proxies and indent >= group_proxies_indent and not after.startswith(("name:", "type:", "{")):
                    item = _unquote_yaml_scalar(after)
                    if item and current_group is not None:
                        groups[current_group]["proxies"].append(item)
                    continue
                in_group_proxies = False
                if after.startswith("{"):
                    name = _extract_flow_name(after)
                    if name:
                        current_group = name
                        groups.setdefault(name, {"type": "", "proxies": []})
                        pm = re.search(r"proxies\s*:\s*\[([^\]]*)\]", after)
                        if pm:
                            for entry in pm.group(1).split(","):
                                val = _unquote_yaml_scalar(entry)
                                if val:
                                    groups[name]["proxies"].append(val)
                elif after.startswith("name:"):
                    name = _unquote_yaml_scalar(after.partition(":")[2])
                    current_group = name or None
                    if current_group:
                        groups.setdefault(current_group, {"type": "", "proxies": []})
                else:
                    current_group = None
            elif current_group is not None:
                if in_group_proxies and indent <= group_proxies_indent and not stripped.startswith("-"):
                    in_group_proxies = False
                if stripped.startswith("name:"):
                    name = _unquote_yaml_scalar(stripped.partition(":")[2])
                    if name:
                        current_group = name
                        groups.setdefault(current_group, {"type": "", "proxies": []})
                elif stripped.startswith("type:"):
                    groups[current_group]["type"] = _unquote_yaml_scalar(stripped.partition(":")[2])
                elif stripped.startswith("proxies:"):
                    rest = stripped.partition(":")[2].strip()
                    if rest.startswith("[") and "]" in rest:
                        inner = rest[1:rest.index("]")]
                        for entry in inner.split(","):
                            val = _unquote_yaml_scalar(entry)
                            if val:
                                groups[current_group]["proxies"].append(val)
                        in_group_proxies = False
                    else:
                        in_group_proxies = True
                        group_proxies_indent = indent

    return proxies, groups


def _is_taiwan_candidate(name):
    if not isinstance(name, str):
        return False
    cleaned = name.strip()
    if not cleaned or cleaned.upper() in _SPECIAL_TARGETS:
        return False
    if _EXCLUDE_NODE_RE.search(cleaned):
        return False
    return bool(_TAIWAN_RE.search(cleaned))


def _taiwan_candidates(profile_id, profile):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", profile_id):
        raise ValueError("OneVPN 活动配置标识无效。")
    yaml_path = _profiles_dir() / f"{profile_id}.yaml"
    if yaml_path.is_symlink() or not yaml_path.is_file():
        raise ValueError("未找到 OneVPN 活动订阅的本地配置文件。")
    text = yaml_path.read_text(encoding="utf-8", errors="replace")
    proxies, groups = _parse_clash_profile(text)

    group_names = set(groups.keys())
    pool = []
    if "Proxies" in groups and groups["Proxies"]["proxies"]:
        pool = [n for n in groups["Proxies"]["proxies"] if n not in group_names]
    if not pool:
        pool = list(proxies)
    # Deduplicate while preserving order
    seen = set()
    candidates = []
    for name in pool:
        if name not in seen and _is_taiwan_candidate(name):
            seen.add(name)
            candidates.append(name)

    # Prefer the currently selected node if it is already a Taiwan candidate
    selected = (profile.get("selectedMap") or {}).get("Proxies")
    if isinstance(selected, str) and selected in candidates:
        candidates.remove(selected)
        candidates.insert(0, selected)
    return candidates


def _parse_clash_rule(value):
    if not isinstance(value, str):
        return None, None, None
    parts = [part.strip() for part in value.split(",")]
    if len(parts) < 3:
        return None, None, None
    return parts[0].upper(), parts[1].lower(), parts[2]


def _claude_rules_state(profile, target_node=None):
    override = profile.get("overrideData")
    if not isinstance(override, dict):
        return False, {}, False
    enabled = override.get("enable") is True
    rule_cfg = override.get("rule")
    if not isinstance(rule_cfg, dict):
        return enabled, {}, False
    rule_type = rule_cfg.get("type", "added")
    override_rules = rule_cfg.get("overrideRules") or []
    conflict_override = enabled and rule_type == "override" and bool(override_rules)
    added = rule_cfg.get("addedRules") if isinstance(rule_cfg.get("addedRules"), list) else []

    found = {}
    for item in added:
        if not isinstance(item, dict):
            continue
        kind, pattern, target = _parse_clash_rule(item.get("value"))
        if kind == "DOMAIN-SUFFIX" and pattern in _CLAUDE_DOMAINS:
            if target_node is None or target == target_node:
                found.setdefault(pattern, []).append(item)
    return enabled and rule_type == "added", found, conflict_override


def _is_profile_configured_for_node(profile, target_node):
    selections = profile.get("selectedMap")
    if not isinstance(selections, dict) or selections.get("Proxies") != target_node:
        return False
    rules_enabled, found, conflict = _claude_rules_state(profile, target_node)
    if conflict or not rules_enabled:
        return False
    return all(domain in found for domain in _CLAUDE_DOMAINS)


def _merge_profile(profile, target_node, backup):
    """Merge Taiwan node selection and Claude rules into profile in-place.

    Preserves all subscriptions, unrelated selectedMap keys, and unrelated rules.
    Returns updated backup record (preserving original baseline on retry).
    """
    override = profile.get("overrideData")
    if not isinstance(override, dict):
        override = {}
        profile["overrideData"] = override
    rule_cfg = override.get("rule")
    if not isinstance(rule_cfg, dict):
        rule_cfg = {"type": "added", "addedRules": [], "overrideRules": []}
        override["rule"] = rule_cfg

    orig_enable = bool(override.get("enable", False))
    orig_type = rule_cfg.get("type", "added")
    override_rules = rule_cfg.get("overrideRules")
    if orig_enable and orig_type == "override" and isinstance(override_rules, list) and override_rules:
        raise ValueError("OneVPN 当前正在使用自定义覆写规则集（override），为保留现有规则已停止自动修改。")

    selections = profile.get("selectedMap")
    if not isinstance(selections, dict):
        selections = {}
        profile["selectedMap"] = selections

    had_proxy = "Proxies" in selections
    orig_proxy = selections.get("Proxies") if had_proxy else None

    added = rule_cfg.get("addedRules")
    if not isinstance(added, list):
        added = []
        rule_cfg["addedRules"] = added

    if backup is None:
        backup = {
            "version": 1,
            "profileId": profile["id"],
            "hadProxySelection": had_proxy,
            "originalProxy": orig_proxy,
            "appliedNode": target_node,
            "originalOverrideEnable": orig_enable,
            "originalRuleType": orig_type,
            "originalAddedRuleIds": [item.get("id") for item in added if isinstance(item, dict) and isinstance(item.get("id"), str)],
            "managedRules": [],
            "replacedRules": [],
        }
    else:
        backup = json.loads(json.dumps(backup))
        backup["appliedNode"] = target_node

    managed_by_id = {entry["id"]: entry for entry in backup["managedRules"]}
    replaced_by_id = {entry["id"]: entry for entry in backup["replacedRules"]}

    # Index existing Claude DOMAIN-SUFFIX rules
    existing_by_domain = {}
    for item in added:
        if not isinstance(item, dict):
            continue
        kind, pattern, target = _parse_clash_rule(item.get("value"))
        if kind == "DOMAIN-SUFFIX" and pattern in _CLAUDE_DOMAINS:
            existing_by_domain.setdefault(pattern, []).append(item)

    to_prepend = []
    for domain in _CLAUDE_DOMAINS:
        desired = f"DOMAIN-SUFFIX,{domain},{target_node}"
        matches = existing_by_domain.get(domain, [])
        # Already has exact rule for this node?
        exact = next((m for m in matches if m.get("value") == desired), None)
        if exact is not None:
            # Reuse preexisting rule; do not claim Preflight added it unless already managed
            if exact.get("id") in managed_by_id:
                managed_by_id[exact["id"]]["value"] = desired
            continue
        # Has a rule previously managed by Preflight (e.g. switching from TW candidate 1 to 2)?
        managed_item = next((m for m in matches if m.get("id") in managed_by_id), None)
        if managed_item is not None:
            managed_item["value"] = desired
            managed_by_id[managed_item["id"]]["value"] = desired
            continue
        # Has a preexisting user rule for this Claude domain pointing to a different target?
        if matches:
            target_item = matches[0]
            item_id = target_item.get("id")
            if not isinstance(item_id, str) or not item_id:
                item_id = str(uuid.uuid4())
                target_item["id"] = item_id
            if item_id not in replaced_by_id:
                entry = {"id": item_id, "originalValue": target_item.get("value"), "appliedValue": desired}
                backup["replacedRules"].append(entry)
                replaced_by_id[item_id] = entry
            else:
                replaced_by_id[item_id]["appliedValue"] = desired
            target_item["value"] = desired
            continue
        # Add a new rule managed by Preflight
        new_id = str(uuid.uuid4())
        new_item = {"id": new_id, "value": desired}
        to_prepend.append(new_item)
        entry = {"id": new_id, "value": desired}
        backup["managedRules"].append(entry)
        managed_by_id[new_id] = entry

    if to_prepend:
        added[:0] = to_prepend

    override["enable"] = True
    rule_cfg["type"] = "added"
    selections["Proxies"] = target_node
    return backup


def _restore_profile(profile, backup):
    """Restore only Preflight-managed fields, detecting user edits as conflicts."""
    conflicts = []
    selections = profile.get("selectedMap")
    if isinstance(selections, dict):
        if selections.get("Proxies") == backup["appliedNode"]:
            if backup["hadProxySelection"]:
                selections["Proxies"] = backup["originalProxy"]
            else:
                selections.pop("Proxies", None)
        elif selections.get("Proxies") != backup["originalProxy"]:
            conflicts.append("OneVPN 当前节点已被用户手动修改，已保留当前节点")

    override = profile.get("overrideData")
    rule_cfg = override.get("rule") if isinstance(override, dict) else None
    added = rule_cfg.get("addedRules") if isinstance(rule_cfg, dict) and isinstance(rule_cfg.get("addedRules"), list) else None

    if added is not None:
        managed_map = {entry["id"]: entry["value"] for entry in backup["managedRules"]}
        replaced_map = {entry["id"]: entry for entry in backup["replacedRules"]}
        kept = []
        for item in added:
            if not isinstance(item, dict):
                kept.append(item)
                continue
            item_id = item.get("id")
            if item_id in managed_map:
                if item.get("value") == managed_map[item_id]:
                    continue  # Remove unmodified Preflight-added rule
                conflicts.append("部分 Claude 分流规则已被用户修改，已保留用户修改")
                kept.append(item)
            elif item_id in replaced_map:
                entry = replaced_map[item_id]
                if item.get("value") == entry["appliedValue"]:
                    item["value"] = entry["originalValue"]
                elif item.get("value") != entry["originalValue"]:
                    conflicts.append("原有 Claude 分流规则已被用户修改，已保留用户修改")
                kept.append(item)
            else:
                kept.append(item)
        rule_cfg["addedRules"] = kept

    if isinstance(override, dict) and isinstance(rule_cfg, dict) and not conflicts:
        if override.get("enable") is True and backup["originalOverrideEnable"] is False:
            orig_ids = set(backup.get("originalAddedRuleIds") or [])
            remaining_ids = {item.get("id") for item in (rule_cfg.get("addedRules") or []) if isinstance(item, dict)}
            if remaining_ids <= orig_ids:
                override["enable"] = False
            else:
                conflicts.append("检测到用户在配置后新增了其他覆写规则，已保持规则覆写开启")
        if rule_cfg.get("type") == "added" and backup["originalRuleType"] != "added":
            rule_cfg["type"] = backup["originalRuleType"]

    return conflicts


def _wait_onevpn_ready(timeout=_WAIT_READY_SECONDS):
    deadline = time.monotonic() + timeout
    last_error = "OneVPN 尚未就绪"
    while time.monotonic() < deadline:
        try:
            return guard._identity()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            last_error = str(exc) or last_error
            time.sleep(_POLL_INTERVAL)
    raise ValueError(f"等待 OneVPN 代理与隧道就绪超时：{last_error}")


def _detect_system_proxy_info():
    """Return (enabled, protocol_label, host_port_str, port_int_or_None)."""
    try:
        out = guard._output(["/usr/sbin/scutil", "--proxy"])
    except (OSError, subprocess.SubprocessError):
        return False, "未知", None, None
    fields = dict(re.findall(r"^  (\w+)\s*:\s*(\S+)\s*$", out, re.M))
    protocols = []
    host_port = None
    port_num = None
    for prefix, label in (("HTTPS", "HTTPS"), ("HTTP", "HTTP"), ("SOCKS", "SOCKS")):
        if fields.get(prefix + "Enable") == "1":
            protocols.append(label)
            if host_port is None:
                host = fields.get(prefix + "Proxy", "")
                port = fields.get(prefix + "Port", "")
                if host and port.isdigit():
                    host_port = f"{host}:{port}"
                    port_num = int(port)
    return bool(protocols), ("/".join(protocols) if protocols else "未开启"), host_port, port_num


def _active_utun_interfaces():
    """Return list of UP+RUNNING utun interface names with assigned addresses."""
    try:
        out = guard._output(["/sbin/ifconfig"])
    except (OSError, subprocess.SubprocessError):
        return []
    active = []
    current = None
    has_up = False
    has_inet = False
    for line in out.splitlines():
        if not line.startswith(("\t", " ")):
            if current and has_up and has_inet:
                active.append(current)
            match = re.match(r"^(utun\d+):\s*flags=\w+<([^>]+)>", line)
            if match:
                current = match.group(1)
                flags = set(match.group(2).split(","))
                has_up = {"UP", "RUNNING"}.issubset(flags)
                has_inet = False
            else:
                current = None
                has_up = False
                has_inet = False
        elif current:
            stripped = line.strip()
            if stripped.startswith("inet ") and not stripped.startswith("inet 127."):
                has_inet = True
    if current and has_up and has_inet:
        active.append(current)
    return active


def detect_installed_vpns():
    """Auto-discover installed and running macOS VPN/proxy apps (privacy-safe)."""
    apps_dir = Path("/Applications")
    proc_comms = []
    try:
        proc_comms = [row[3] for row in guard._processes()]
    except (OSError, subprocess.SubprocessError):
        pass
    detected = []
    for label, bundle, auto_cfg in _KNOWN_VPN_APPS:
        app_path = apps_dir / bundle
        if not app_path.is_dir():
            continue
        prefix = str(app_path) + "/"
        running = any(comm.startswith(prefix) for comm in proc_comms)
        detected.append({
            "name": label,
            "running": running,
            "autoConfigSupported": auto_cfg,
        })
    return detected


def _read_generic_clash_candidates():
    """Best-effort, read-only scan of standard Clash/Mihomo profile dirs for Taiwan candidates."""
    home = Path.home()
    search_dirs = [
        home / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles",
        home / "Library/Application Support/Clash Verge/profiles",
        home / ".config/clash",
        home / ".config/mihomo",
    ]
    for folder in search_dirs:
        if not folder.is_dir():
            continue
        yamls = sorted(folder.glob("*.yaml"), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in yamls[:3]:
            if path.is_symlink() or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                proxies, groups = _parse_clash_profile(text)
                pool = list(proxies)
                for g in groups.values():
                    pool.extend(g.get("proxies") or [])
                seen = set()
                cands = []
                for name in pool:
                    if name not in seen and _is_taiwan_candidate(name):
                        seen.add(name)
                        cands.append(name)
                if cands:
                    return len(cands)
            except OSError:
                continue
    return 0


def inspect_vpn_status(live_probe=False):
    """Read-only universal VPN status summary for the UI prerequisite self-check."""
    detected_apps = detect_installed_vpns() if sys.platform == "darwin" else []
    running_apps = [a for a in detected_apps if a["running"]]
    onevpn_installed = _ONEVPN_APP.is_dir()
    proxy_enabled, proxy_proto, proxy_addr, proxy_port = (
        _detect_system_proxy_info() if sys.platform == "darwin" else (False, "未知", None, None)
    )
    utuns = _active_utun_interfaces() if sys.platform == "darwin" else []

    active_app = None
    if running_apps:
        # Prefer OneVPN if running, otherwise the first running VPN app
        onevpn_running = next((a for a in running_apps if a["name"] == "OneVPN"), None)
        active_app = onevpn_running or running_apps[0]
    elif detected_apps:
        onevpn_entry = next((a for a in detected_apps if a["name"] == "OneVPN"), None)
        active_app = onevpn_entry or detected_apps[0]

    status = {
        "installed": bool(detected_apps),
        "onevpnInstalled": onevpn_installed,
        "detectedApps": detected_apps,
        "activeApp": active_app["name"] if active_app else ("系统代理/VPN" if (proxy_enabled or utuns) else None),
        "autoConfigSupported": bool(onevpn_installed),
        "running": bool(running_apps) or (proxy_enabled and bool(utuns)),
        "proxyReady": proxy_enabled,
        "proxyProtocol": proxy_proto,
        "proxyAddress": proxy_addr,
        "proxyPort": proxy_port,
        "tunnelReady": bool(utuns),
        "tunnels": utuns,
        "identityVerified": False,
        "taiwanCandidates": 0,
        "taiwanSelected": False,
        "claudeRulesReady": False,
        "claudeRulesCount": 0,
        "backupAvailable": False,
        "liveCountry": None,
        "verified": False,
        "state": "unknown",
        "detail": "",
    }
    if sys.platform != "darwin":
        status["detail"] = "仅支持 macOS"
        return status

    try:
        with _locked_state(create=False) as (_folder_path, backup_path):
            status["backupAvailable"] = bool(_read_backup(backup_path))
    except (OSError, ValueError):
        pass

    if onevpn_installed:
        try:
            gui, core = _onevpn_processes()
            if len(gui) == 1 and len(core) == 1:
                status["running"] = True
        except (OSError, subprocess.SubprocessError):
            pass

        identity = None
        try:
            identity = guard._identity()
            status["running"] = True
            status["proxyReady"] = True
            status["proxyPort"] = identity.port
            status["proxyAddress"] = f"127.0.0.1:{identity.port}"
            status["tunnelReady"] = bool(identity.tunnels)
            status["identityVerified"] = True
        except (OSError, ValueError, subprocess.SubprocessError):
            pass

        try:
            config = _read_flutter_config()
            profile_id, profile = _active_profile(config)
            candidates = _taiwan_candidates(profile_id, profile)
            status["taiwanCandidates"] = len(candidates)
            selected = (profile.get("selectedMap") or {}).get("Proxies")
            status["taiwanSelected"] = isinstance(selected, str) and selected in candidates
            rules_enabled, found, conflict = _claude_rules_state(
                profile, selected if status["taiwanSelected"] else None
            )
            status["claudeRulesCount"] = len(found)
            status["claudeRulesReady"] = (
                rules_enabled and not conflict and status["taiwanSelected"]
                and all(domain in found for domain in _CLAUDE_DOMAINS)
            )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            status["detail"] = str(exc)

        if live_probe and (identity is not None or proxy_port is not None):
            try:
                probe_port = identity.port if identity is not None else proxy_port
                country, _ip = guard._trace_via_port(probe_port, seconds=6)
                status["liveCountry"] = country
                status["verified"] = country == "TW" and status["claudeRulesReady"]
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
    else:
        # Generic / any-VPN path (Clash Verge, Surge, Mihomo Party, WireGuard, etc.)
        status["taiwanCandidates"] = _read_generic_clash_candidates()
        if live_probe and (proxy_enabled or utuns or status["running"]):
            net = probe_network()
            if net.get("country"):
                status["liveCountry"] = net["country"]
                status["verified"] = net["country"] == "TW"

    app_label = status["activeApp"] or "VPN"
    if not status["installed"] and not (proxy_enabled or utuns):
        status["state"] = "error"
        status["detail"] = "未检测到已安装的 VPN 客户端或活动代理（VPN 与台湾节点需自备）"
    elif not status["running"] and not (proxy_enabled or utuns):
        status["state"] = "error"
        status["detail"] = f"已检测到 {app_label}，但当前未运行或未连接"
    elif not (status["proxyReady"] or status["tunnelReady"]):
        status["state"] = "error"
        status["detail"] = f"{app_label} 正在运行，但系统代理和 TUN 隧道均未开启"
    elif onevpn_installed and status["activeApp"] == "OneVPN":
        if status["taiwanCandidates"] == 0:
            status["state"] = "error"
            status["detail"] = "OneVPN 当前订阅中未找到台湾候选节点"
        elif not status["claudeRulesReady"]:
            status["state"] = "pending"
            status["detail"] = "OneVPN 已连接，点击一键配置可自动合并台湾节点与 Claude 分流规则"
        elif live_probe and status["liveCountry"] and status["liveCountry"] != "TW":
            status["state"] = "error"
            status["detail"] = f"OneVPN 实测出口为 {status['liveCountry']}，不是台湾（TW）"
        elif status["verified"] or (not live_probe and status["claudeRulesReady"] and (status["proxyReady"] or status["tunnelReady"])):
            status["state"] = "ok"
            status["detail"] = f"OneVPN 代理（{status['proxyAddress'] or '就绪'}）与 Claude 台湾分流规则已就绪"
        else:
            status["state"] = "unknown"
            status["detail"] = "已配置规则，等待实测台湾出口"
    else:
        # Universal VPN app active
        if live_probe and status["liveCountry"]:
            if status["liveCountry"] == "TW":
                status["state"] = "ok"
                status["detail"] = f"已检测到 {app_label}（{status['proxyAddress'] or 'TUN 隧道'}），实测出口为 TW"
            else:
                status["state"] = "error"
                status["detail"] = f"已检测到 {app_label}，但当前实测出口为 {status['liveCountry']}，请在 VPN 中切换至台湾节点"
        else:
            status["state"] = "ok" if (status["proxyReady"] or status["tunnelReady"]) else "pending"
            extra = f"，发现 {status['taiwanCandidates']} 个台湾候选节点" if status["taiwanCandidates"] else ""
            status["detail"] = f"已自动识别 {app_label}（{status['proxyAddress'] or 'TUN 隧道'}）{extra}，请以实测出口 TW 为准"
    return status


def configure_vpn(action="status", phase="prepare", node=None):
    """Execute one phase of VPN configuration, verification, or restoration."""
    if sys.platform != "darwin" or action not in ("status", "apply", "restore") or phase not in ("prepare", "commit", "verify"):
        return _reply("error", "此操作需要 macOS 和有效的配置参数。")

    if not _ONEVPN_APP.is_dir():
        if action == "restore":
            return _reply("ok", "未检测到 OneVPN 备份，没有需要复原的 VPN 自动配置。", needRestart=False)
        info = inspect_vpn_status(live_probe=True)
        if info["liveCountry"] == "TW":
            return _reply(
                "ok",
                f"已自动识别 {info['activeApp'] or '当前 VPN'} 并实测确认台湾出口（TW）。"
                "（注：自动写入分流规则目前支持 OneVPN 1.5.1；当前 VPN 出口已符合台湾要求。）",
                needRestart=False,
                measuredCountry="TW",
            )
        if info["liveCountry"]:
            return _reply(
                "error",
                f"已识别 {info['activeApp'] or '当前 VPN'}，但实测出口为 {info['liveCountry']}（非台湾 TW）。"
                "请先在您的 VPN 客户端切换到台湾节点后重新检测。",
                needRestart=False,
                measuredCountry=info["liveCountry"],
            )
        return _reply(
            "error",
            "未检测到可用的台湾 VPN 出口。请安装并启动您的 VPN（如 OneVPN、Clash Verge、Surge 等）并连接台湾节点。VPN 与节点需自备。",
            needRestart=False,
        )

    try:
        if action == "status":
            info = inspect_vpn_status(live_probe=True)
            code = "ok" if info["state"] == "ok" else ("pending" if info["state"] == "pending" else "error")
            return _reply(code, info["detail"], **{k: v for k, v in info.items() if k != "detail"})

        if action == "apply":
            return _apply_phase(phase, node)
        return _restore_phase(phase)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        msg = str(exc) if type(exc) is ValueError else "无法读取或更新 OneVPN 配置，请检查后重试。"
        return _reply("error", msg)


def _select_candidate(candidates, node_token):
    if not candidates:
        raise ValueError("当前 OneVPN 订阅中未找到台湾候选节点，请先在 OneVPN 中导入包含台湾节点的订阅。")
    if node_token is None:
        return candidates[0], _node_token(candidates[0])
    for candidate in candidates:
        token = _node_token(candidate)
        if token == node_token:
            return candidate, token
    raise ValueError("指定的台湾候选节点已不在当前 OneVPN 订阅中。")


def _apply_phase(phase, node):
    if phase == "prepare":
        confirmed, unconfirmed = guard.lock_sessions()
        if unconfirmed:
            return _reply("pending", f"已有 {unconfirmed} 个受管会话未确认锁定，请先退出对应 Claude 客户端后重试。",
                          "quitClaude")
        config = _read_flutter_config()
        profile_id, profile = _active_profile(config)
        candidates = _taiwan_candidates(profile_id, profile)
        target_node, token = _select_candidate(candidates, node)
        tokens = [_node_token(c) for c in candidates]
        already_configured = _is_profile_configured_for_node(profile, target_node)
        if already_configured:
            try:
                identity = guard._identity()
                country, _ip = guard._trace_via_port(identity.port, seconds=8)
                if guard._identity() == identity and country == "TW":
                    return _reply("ok", "已核验 OneVPN 台湾节点与 Claude 分流规则，实测出口为 TW。",
                                  needRestart=False, node=token, candidates=tokens,
                                  measuredCountry="TW", lockedSessions=confirmed)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        return _reply("pending", "已锁定受管连接，准备退出 OneVPN 以安全写入台湾节点与分流规则。",
                      "restartOneVPN", needRestart=True, node=token, candidates=tokens,
                      lockedSessions=confirmed)

    if phase == "commit":
        gui, _core = _onevpn_processes()
        if gui:
            raise ValueError("OneVPN 仍在运行。需先正常退出 OneVPN 再写入配置，避免偏好被覆盖。")
        with _locked_state(create=True) as (_folder_path, backup_path):
            backup = _read_backup(backup_path)
            config = _read_flutter_config()
            profile_id, profile = _active_profile(config)
            candidates = _taiwan_candidates(profile_id, profile)
            target_node, token = _select_candidate(candidates, node)
            if backup is not None and backup["profileId"] != profile_id:
                raise ValueError("检测到 OneVPN 活动订阅与首次备份不同，请先复原后再切换。")
            updated_backup = _merge_profile(profile, target_node, backup)
            # Save baseline backup BEFORE modifying OneVPN defaults
            _atomic_write_json(backup_path, updated_backup)
            _write_flutter_config(config)
            # Read back to confirm write persisted
            verify_config = _read_flutter_config()
            _vid, verify_profile = _active_profile(verify_config)
            if not _is_profile_configured_for_node(verify_profile, target_node):
                raise ValueError("写入 OneVPN 偏好后读回校验未通过，已保留备份。")
            return _reply("pending", "已安全合并 OneVPN 台湾节点和 Claude 分流规则，正在重开 OneVPN 并实测出口。",
                          "relaunchOneVPN", node=token)

    # phase == "verify"
    identity = _wait_onevpn_ready()
    config = _read_flutter_config()
    profile_id, profile = _active_profile(config)
    candidates = _taiwan_candidates(profile_id, profile)
    target_node, token = _select_candidate(candidates, node)
    if not _is_profile_configured_for_node(profile, target_node):
        raise ValueError("OneVPN 重开后读回配置与预期不符，已保留备份。")
    try:
        country, _ip = guard._trace_via_port(identity.port, seconds=10)
    except (OSError, ValueError, subprocess.SubprocessError):
        return _reply("error", "OneVPN 代理已就绪，但台湾出口实测超时或失败，无法确认出口为 TW。",
                      measuredCountry=None, node=token, retryable=True)
    if guard._identity() != identity:
        return _reply("error", "出口实测期间 OneVPN 状态发生变化，请重试验证。",
                      measuredCountry=None, node=token, retryable=True)
    if country != "TW":
        return _reply("error", f"当前候选节点实测出口为 {country}，不是台湾（TW）。",
                      measuredCountry=country, node=token, retryable=True)
    return _reply("ok", "已配置 OneVPN 台湾节点及 Claude 分流规则，并实测确认出口为 TW。",
                  measuredCountry="TW", node=token)


def _restore_phase(phase):
    with _locked_state(create=False) as (_folder_path, backup_path):
        backup = _read_backup(backup_path)
    if backup is None:
        return _reply("ok", "没有由 Preflight 修改且需要复原的 OneVPN 设置。", needRestart=False)

    if phase == "prepare":
        confirmed, unconfirmed = guard.lock_sessions()
        if unconfirmed:
            return _reply("pending", f"已有 {unconfirmed} 个受管会话未确认锁定，请先退出对应 Claude 客户端后再复原。",
                          "quitClaude")
        return _reply("pending", "已锁定受管连接，准备退出 OneVPN 以按备份复原设置。",
                      "restartOneVPN", needRestart=True, lockedSessions=confirmed)

    if phase == "commit":
        gui, _core = _onevpn_processes()
        if gui:
            raise ValueError("OneVPN 仍在运行。需先正常退出 OneVPN 再复原偏好。")
        with _locked_state(create=False) as (_folder_path, backup_path):
            backup = _read_backup(backup_path)
            if backup is None:
                return _reply("ok", "没有需要复原的 OneVPN 设置。")
            config = _read_flutter_config()
            profiles = config.get("profiles")
            if not isinstance(profiles, list):
                raise ValueError("OneVPN 配置中缺少订阅列表。")
            target_profile = next((p for p in profiles if isinstance(p, dict) and p.get("id") == backup["profileId"]), None)
            if target_profile is None:
                return _reply("error", "首次配置时的 OneVPN 订阅已不存在，已保留备份以便核查。")
            conflicts = _restore_profile(target_profile, backup)
            _write_flutter_config(config)
            backup_path.unlink(missing_ok=True)
            if conflicts:
                return _reply("pending", "已复原未冲突的 OneVPN 设置，以下项目保留了用户后续修改：" + "；".join(conflicts),
                              "relaunchOneVPN", conflicts=conflicts)
            return _reply("pending", "已按备份复原 OneVPN 设置，正在重开 OneVPN。",
                          "relaunchOneVPN", conflicts=[])

    # phase == "verify"
    try:
        _wait_onevpn_ready(timeout=15.0)
    except ValueError:
        return _reply("ok", "已复原 OneVPN 设置。请确认 OneVPN 已按您的偏好重新连接。")
    return _reply("ok", "已复原 OneVPN 设置并确认 OneVPN 重新就绪。")
