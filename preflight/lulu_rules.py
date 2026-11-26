"""Safe LuLu 4.5.7 rule backup, merge-export, verification, and surgical restore.

LuLu 4.5.7 provides no CLI rule import. Its official GUI "Rules -> Import..."
accepts a JSON dictionary keyed by rule key. When every imported rule has
`type == 3` (RULE_TYPE_USER), LuLu executes `importRules:userOnly:YES`, which
replaces ONLY user-created rules while leaving Apple, default, baseline, and
passive rules untouched.

To guarantee zero data loss for other applications:
  1. Read the active profile's `rules.plist` directly (read-only).
  2. Refuse to proceed if any existing user-created rule cannot be faithfully
     represented in LuLu's JSON format (for example, temporary PID-scoped rules
     or multi-path alias groups that JSON import does not preserve).
  3. Fingerprint every unrelated rule (both non-user and other-app user rules).
  4. Merge all existing user-created rules with only the missing Claude rules,
     reusing preexisting valid Claude rules without claiming Preflight added them.
  5. Save an atomic `0600` baseline backup BEFORE staging JSON for LuLu's UI.
  6. After LuLu's official UI finishes importing, re-read `rules.plist` and
     verify both unrelated-rule preservation and Claude rule readiness.
  7. On restore, remove ONLY rules created by Preflight (checking for user
     modifications as conflicts) while keeping all user rules added before or
     after setup.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import tempfile
import uuid

from .guard import DESKTOP_PORT
from .native_firewall import (
    _DIRECTORIES,
    _assess_rules,
    _code_identities,
    _inside_or_overlaps,
    _profile,
    inspect_desktop_firewall,
)


_APPLE_EPOCH = 978307200  # 2001-01-01T00:00:00Z
_RULE_TYPE_USER = 3
_CLAUDE_BUNDLE_PATH = "/Applications/Claude.app/*"
_LULU_DATE_FMT = "%Y-%m-%dT%H:%M:%S+0000"


def _format_lulu_date(timestamp):
    return datetime.fromtimestamp(_APPLE_EPOCH + float(timestamp), tz=timezone.utc).strftime(_LULU_DATE_FMT)


def _now_lulu_date():
    return datetime.now(tz=timezone.utc).strftime(_LULU_DATE_FMT)


def _unarchive_value(objects, ref, depth=0):
    """Safely unarchive primitive Foundation containers without instantiating classes."""
    if depth > 8:
        raise ValueError("LuLu 规则存档嵌套层级异常")
    if isinstance(ref, plistlib.UID):
        if not 0 <= ref.data < len(objects):
            raise ValueError("无效的 LuLu 规则对象引用")
        if ref.data == 0:
            return None
        value = objects[ref.data]
    else:
        value = ref

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if not isinstance(value, dict) or "$class" not in value:
        raise ValueError("无法识别的 LuLu 规则字段类型")

    cls_obj = objects[value["$class"].data]
    cls_name = cls_obj.get("$classname")
    if cls_name in ("NSString", "NSMutableString"):
        return value.get("NS.string")
    if cls_name == "NSDate":
        return {"__nsdate__": float(value["NS.time"])}
    if cls_name in ("NSArray", "NSMutableArray"):
        return [_unarchive_value(objects, item, depth + 1) for item in value.get("NS.objects", [])]
    if cls_name in ("NSSet", "NSMutableSet"):
        return [_unarchive_value(objects, item, depth + 1) for item in value.get("NS.objects", [])]
    if cls_name in ("NSDictionary", "NSMutableDictionary"):
        keys = value.get("NS.keys", [])
        vals = value.get("NS.objects", [])
        if len(keys) != len(vals):
            raise ValueError("LuLu 规则字典键值数量不匹配")
        result = {}
        for k_ref, v_ref in zip(keys, vals):
            k = _unarchive_value(objects, k_ref, depth + 1)
            if not isinstance(k, str):
                raise ValueError("LuLu 规则字典键类型无效")
            result[k] = _unarchive_value(objects, v_ref, depth + 1)
        return result
    raise ValueError(f"无法安全序列化的 LuLu 规则对象类型：{cls_name}")


def read_full_rules(path):
    """Read all reachable rules with full metadata needed for lossless JSON merge."""
    with Path(path).open("rb") as handle:
        archive = plistlib.load(handle)
    if archive.get("$archiver") != "NSKeyedArchiver":
        raise ValueError("未知的 LuLu 规则存档格式")
    objects = archive["$objects"]

    def obj(ref):
        if not isinstance(ref, plistlib.UID) or not 0 <= ref.data < len(objects):
            raise ValueError("无效的 LuLu 规则引用")
        return objects[ref.data] if ref.data else None

    def cls_name(record):
        return obj(record["$class"])["$classname"]

    def mapping(record):
        if cls_name(record) not in ("NSDictionary", "NSMutableDictionary"):
            raise ValueError("未知的 LuLu 规则字典类型")
        keys, values = record["NS.keys"], record["NS.objects"]
        if len(keys) != len(values):
            raise ValueError("LuLu 规则字典不完整")
        result = {obj(k): obj(v) for k, v in zip(keys, values)}
        if len(result) != len(keys):
            raise ValueError("LuLu 规则字典包含重复项")
        return result

    records = []
    root_map = mapping(obj(archive["$top"]["root"]))
    for key, item in root_map.items():
        group = mapping(item)
        rules_arr = group["rules"]
        if cls_name(rules_arr) not in ("NSArray", "NSMutableArray"):
            raise ValueError("未知的 LuLu 规则列表类型")
        paths = group.get("paths")
        aliases = []
        if paths is not None:
            if cls_name(paths) not in ("NSSet", "NSMutableSet"):
                raise ValueError("未知的 LuLu 进程路径列表")
            aliases = [obj(v) for v in paths["NS.objects"]]
        for ref in rules_arr["NS.objects"]:
            raw_rule = obj(ref)
            if cls_name(raw_rule) != "Rule":
                raise ValueError("未知的 LuLu 规则类型")
            creation = _unarchive_value(objects, raw_rule.get("creation"))
            expiration = _unarchive_value(objects, raw_rule.get("expiration"))
            cs_info = _unarchive_value(objects, raw_rule.get("csInfo"))
            rule = {
                "key": obj(raw_rule["key"]),
                "uuid": obj(raw_rule.get("uuid")),
                "path": obj(raw_rule["path"]),
                "name": obj(raw_rule.get("name")),
                "endpointAddr": obj(raw_rule["endpointAddr"]),
                "endpointPort": obj(raw_rule["endpointPort"]),
                "endpointHost": obj(raw_rule.get("endpointHost")),
                "isEndpointAddrRegex": obj(raw_rule.get("isEndpointAddrRegex")),
                "type": obj(raw_rule.get("type")),
                "scope": obj(raw_rule.get("scope")),
                "action": obj(raw_rule["action"]),
                "isDisabled": obj(raw_rule.get("isDisabled")),
                "pid": obj(raw_rule.get("pid")),
                "creation": _format_lulu_date(creation["__nsdate__"]) if isinstance(creation, dict) and "__nsdate__" in creation else None,
                "expiration": _format_lulu_date(expiration["__nsdate__"]) if isinstance(expiration, dict) and "__nsdate__" in expiration else None,
                "csInfo": cs_info,
            }
            if (not isinstance(key, str) or key != rule["key"]
                    or not isinstance(rule["path"], str)
                    or not all(isinstance(p, str) for p in aliases)
                    or rule["action"] not in (0, 1)):
                raise ValueError("无法核对 LuLu 规则归属或动作")
            records.append((key, aliases, rule))
    return records


def _is_rule_json_safe(aliases, rule):
    """Ensure a user-created rule can round-trip through LuLu's official JSON import."""
    if rule["pid"] is not None:
        return False, "检测到按进程 PID 生效的临时用户规则，官方 JSON 导入无法保留临时进程规则"
    if any(p != rule["path"] for p in aliases):
        return False, "检测到含多路径别名的用户规则，官方 JSON 导入无法保证完整保留"
    if not isinstance(rule["uuid"], str) or not rule["uuid"]:
        return False, "检测到缺少 UUID 的用户规则，无法安全合并导入"
    if not isinstance(rule["name"], str):
        return False, "检测到缺少名称字段的用户规则，无法安全合并导入"
    if not isinstance(rule["endpointAddr"], str) or not isinstance(rule["endpointPort"], str):
        return False, "检测到端点字段异常的用户规则，无法安全合并导入"
    if rule["csInfo"] is not None and not isinstance(rule["csInfo"], dict):
        return False, "检测到签名信息异常的用户规则，无法安全合并导入"
    return True, None


def rule_to_lulu_json(rule):
    """Serialize a Rule dict to the exact JSON schema accepted by LuLu 4.5.7 initFromJSON:."""
    payload = {
        "key": rule["key"],
        "uuid": rule["uuid"],
        "path": rule["path"],
        "name": rule["name"],
        "endpointAddr": rule["endpointAddr"],
        "endpointPort": rule["endpointPort"],
        "isEndpointAddrRegex": int(rule["isEndpointAddrRegex"] or 0),
        "type": int(rule["type"]),
        "scope": int(rule["scope"] if rule["scope"] is not None else 0),
        "action": int(rule["action"]),
    }
    if rule.get("endpointHost") is not None:
        payload["endpointHost"] = rule["endpointHost"]
    if rule.get("isDisabled") is not None:
        payload["isDisabled"] = int(rule["isDisabled"])
    if rule.get("creation") is not None:
        payload["creation"] = rule["creation"]
    if rule.get("expiration") is not None:
        payload["expiration"] = rule["expiration"]
    if rule.get("csInfo") is not None:
        payload["csInfo"] = rule["csInfo"]
    return payload


def _canonical_rule_identity(rule):
    """Stable comparable tuple for verifying unrelated rule preservation."""
    return (
        rule["key"],
        rule["uuid"],
        rule["path"],
        rule["name"],
        rule["endpointAddr"],
        rule["endpointPort"],
        rule.get("endpointHost"),
        int(rule.get("isEndpointAddrRegex") or 0),
        int(rule["type"]) if rule.get("type") is not None else None,
        int(rule["scope"] if rule.get("scope") is not None else 0),
        int(rule["action"]),
        int(rule["isDisabled"]) if rule.get("isDisabled") is not None else None,
        rule.get("expiration"),
    )


def unrelated_fingerprint(records, exclude_uuids=frozenset()):
    """Compute a deterministic digest of all rules NOT owned by Preflight."""
    items = []
    for _key, _aliases, rule in records:
        if rule.get("uuid") in exclude_uuids:
            continue
        items.append(_canonical_rule_identity(rule))
    items.sort(key=lambda row: json.dumps(row, ensure_ascii=True))
    encoded = json.dumps(items, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(items)


def _make_claude_rules(need_block, need_allow, port=DESKTOP_PORT):
    created = []
    now = _now_lulu_date()
    if need_block:
        created.append({
            "key": _CLAUDE_BUNDLE_PATH,
            "uuid": str(uuid.uuid4()).upper(),
            "path": _CLAUDE_BUNDLE_PATH,
            "name": "*",
            "endpointAddr": "*",
            "endpointPort": "*",
            "endpointHost": None,
            "isEndpointAddrRegex": 0,
            "type": _RULE_TYPE_USER,
            "scope": 0,
            "action": 0,
            "isDisabled": None,
            "pid": None,
            "creation": now,
            "expiration": None,
            "csInfo": None,
        })
    if need_allow:
        created.append({
            "key": _CLAUDE_BUNDLE_PATH,
            "uuid": str(uuid.uuid4()).upper(),
            "path": _CLAUDE_BUNDLE_PATH,
            "name": "*",
            "endpointAddr": "127.0.0.1",
            "endpointPort": str(port),
            "endpointHost": "127.0.0.1",
            "isEndpointAddrRegex": 0,
            "type": _RULE_TYPE_USER,
            "scope": 0,
            "action": 1,
            "isDisabled": None,
            "pid": None,
            "creation": now,
            "expiration": None,
            "csInfo": None,
        })
    return created


def _write_private_json(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=".lulu-", delete=False) as stream:
        tmp = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _group_user_rules_for_json(records):
    """Build LuLu JSON mapping containing ONLY user-created rules (type == 3)."""
    grouped = {}
    for key, aliases, rule in records:
        if rule.get("type") != _RULE_TYPE_USER:
            continue
        safe, reason = _is_rule_json_safe(aliases, rule)
        if not safe:
            raise ValueError(f"{reason}，已停止自动导入以保护现有 LuLu 规则。")
        grouped.setdefault(key, []).append(rule_to_lulu_json(rule))
    return grouped


def plan_apply_import(staging_dir, port=DESKTOP_PORT, rules_path=None, code_ids=None):
    """Inspect active LuLu rules and prepare a safe user-only merged JSON import.

    Returns dict:
      - needed: bool (False when preexisting rules already satisfy requirements)
      - importPath: Path to staged merged JSON (when needed=True)
      - managedRules: list of canonical rule dicts created by Preflight
      - baselineFingerprint: SHA-256 of all preexisting rules
      - baselineCount: count of all preexisting rules
      - userRulesBackup: serialized backup of preexisting user-created rules
    """
    if rules_path is None:
        directory, _prefs = _profile()
        rules_path = directory / "rules.plist"
    if code_ids is None:
        code_ids = _code_identities()

    records = read_full_rules(rules_path)
    block, allow, conflict = _assess_rules(records, port, code_ids)
    if conflict:
        raise ValueError("检测到与 Claude 保护冲突的 LuLu 放行规则，为避免误删原有规则，请先在 LuLu 规则列表核查冲突项。")

    fingerprint, total_count = unrelated_fingerprint(records)
    if block and allow:
        return {
            "needed": False,
            "importPath": None,
            "managedRules": [],
            "baselineFingerprint": fingerprint,
            "baselineCount": total_count,
            "userRulesBackup": None,
        }

    # Build user-created rules JSON (strictly type == 3 so LuLu runs userOnly=YES)
    merged = _group_user_rules_for_json(records)
    user_backup = json.loads(json.dumps(merged))

    new_rules = _make_claude_rules(need_block=not block, need_allow=not allow, port=port)
    for rule in new_rules:
        merged.setdefault(rule["key"], []).append(rule_to_lulu_json(rule))

    import_path = Path(staging_dir) / "lulu-import.json"
    _write_private_json(import_path, merged)
    return {
        "needed": True,
        "importPath": str(import_path),
        "managedRules": [rule_to_lulu_json(r) for r in new_rules],
        "baselineFingerprint": fingerprint,
        "baselineCount": total_count,
        "userRulesBackup": user_backup,
    }


def verify_apply_import(managed_rules, expected_fingerprint, expected_count, port=DESKTOP_PORT,
                        rules_path=None, code_ids=None):
    """Read back LuLu rules.plist after UI import and verify both safety and readiness."""
    if rules_path is None:
        directory, _prefs = _profile()
        rules_path = directory / "rules.plist"
    if code_ids is None:
        code_ids = _code_identities()

    records = read_full_rules(rules_path)
    managed_uuids = {r["uuid"] for r in managed_rules}
    actual_fp, actual_count = unrelated_fingerprint(records, exclude_uuids=managed_uuids)
    if actual_fp != expected_fingerprint or actual_count != expected_count:
        raise ValueError("导入后核验发现原有 LuLu 规则数量或内容发生变化，请立即使用备份恢复。")

    present_uuids = {r["uuid"] for _k, _a, r in records}
    missing = managed_uuids - present_uuids
    if missing:
        raise ValueError("LuLu 规则导入未生效，未在规则文件中读回新增的 Claude 规则。")

    block, allow, conflict = _assess_rules(records, port, code_ids)
    if not (block and allow and not conflict):
        raise ValueError("导入后的 Claude 防火墙规则未通过完整核验。")
    return True


def plan_restore_import(staging_dir, managed_rules, rules_path=None):
    """Build a safe user-only JSON that removes ONLY unmodified Preflight-added rules.

    Any rule edited by the user after setup is kept and reported as a conflict.
    Any new rules added by the user after setup are fully preserved.
    """
    if not managed_rules:
        return {"needed": False, "importPath": None, "conflicts": [], "expectedFingerprint": None, "expectedCount": 0}
    if rules_path is None:
        directory, _prefs = _profile()
        rules_path = directory / "rules.plist"

    records = read_full_rules(rules_path)
    managed_by_uuid = {r["uuid"]: r for r in managed_rules}
    conflicts = []
    removals = set()

    for _key, _aliases, rule in records:
        uid = rule.get("uuid")
        if uid not in managed_by_uuid:
            continue
        expected = managed_by_uuid[uid]
        if _canonical_rule_identity(rule) == _canonical_rule_identity(expected):
            removals.add(uid)
        else:
            conflicts.append("Preflight 添加的 Claude LuLu 规则已被用户手动修改，已保留用户修改")

    if not removals:
        return {"needed": False, "importPath": None, "conflicts": conflicts,
                "expectedFingerprint": None, "expectedCount": 0}

    remaining_records = [item for item in records if item[2].get("uuid") not in removals]
    merged = _group_user_rules_for_json(remaining_records)
    expected_fp, expected_count = unrelated_fingerprint(remaining_records)

    restore_path = Path(staging_dir) / "lulu-restore.json"
    _write_private_json(restore_path, merged)
    return {
        "needed": True,
        "importPath": str(restore_path),
        "conflicts": conflicts,
        "removedUuids": sorted(removals),
        "expectedFingerprint": expected_fp,
        "expectedCount": expected_count,
    }


def verify_restore_import(removed_uuids, expected_fingerprint, expected_count, rules_path=None):
    """Read back LuLu rules.plist after restore import and confirm surgical removal."""
    if rules_path is None:
        directory, _prefs = _profile()
        rules_path = directory / "rules.plist"
    records = read_full_rules(rules_path)
    present_uuids = {r.get("uuid") for _k, _a, r in records}
    if set(removed_uuids) & present_uuids:
        raise ValueError("复原导入尚未生效，Preflight 添加的 Claude 规则仍然存在。")
    actual_fp, actual_count = unrelated_fingerprint(records)
    if actual_fp != expected_fingerprint or actual_count != expected_count:
        raise ValueError("复原后核验发现其他 LuLu 规则发生变化，请检查 LuLu 规则列表。")
    return True
