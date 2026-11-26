import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from preflight import firewall_setup as fw
from preflight import lulu_rules as lr


PORT = 47836
IDS = {"com.anthropic.claudefordesktop"}


def _build_rules_plist(groups):
    """Build a valid NSKeyedArchiver plist matching LuLu 4.5.7's rules.plist structure.

    groups: list of (key, aliases, [rule_dict, ...])
    """
    objects = ["$null"]

    def ref(val):
        if val is None:
            return plistlib.UID(0)
        if isinstance(val, dict) and "__nsdate__" in val:
            cls_uid = ref({"$classname": "NSDate"})
            return ref({"$class": cls_uid, "NS.time": float(val["__nsdate__"])})
        if isinstance(val, dict) and "$class" not in val and "$classname" not in val:
            cls_uid = ref({"$classname": "NSMutableDictionary"})
            keys = [ref(k) for k in val.keys()]
            vals = [ref(v) for v in val.values()]
            return ref({"$class": cls_uid, "NS.keys": keys, "NS.objects": vals})
        if isinstance(val, list):
            cls_uid = ref({"$classname": "NSMutableArray"})
            return ref({"$class": cls_uid, "NS.objects": [ref(v) for v in val]})
        objects.append(val)
        return plistlib.UID(len(objects) - 1)

    def mapping(pairs):
        cls_uid = ref({"$classname": "NSMutableDictionary"})
        return ref({"$class": cls_uid, "NS.keys": [ref(k) for k, _ in pairs], "NS.objects": [v for _, v in pairs]})

    root_pairs = []
    for key, aliases, rules in groups:
        rule_refs = []
        for r in rules:
            encoded = {k: ref(v) for k, v in r.items()}
            encoded["$class"] = ref({"$classname": "Rule"})
            rule_refs.append(ref(encoded))
        rules_arr = ref({"$class": ref({"$classname": "NSMutableArray"}), "NS.objects": rule_refs})
        group_pairs = [("rules", rules_arr)]
        if aliases:
            paths_set = ref({"$class": ref({"$classname": "NSMutableSet"}), "NS.objects": [ref(a) for a in aliases]})
            group_pairs.append(("paths", paths_set))
        root_pairs.append((key, mapping(group_pairs)))

    root = mapping(root_pairs)
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$top": {"root": root}, "$objects": objects}, fmt=plistlib.FMT_BINARY)


def _sample_rule(key, path, action, addr="*", port="*", host=None, rtype=3, uuid="1111-2222", pid=None, scope=0):
    return {
        "key": key,
        "uuid": uuid,
        "path": path,
        "name": "*",
        "endpointAddr": addr,
        "endpointPort": port,
        "endpointHost": host,
        "isEndpointAddrRegex": 0,
        "type": rtype,
        "scope": scope,
        "action": action,
        "isDisabled": None,
        "pid": pid,
        "creation": {"__nsdate__": 700000000.0},
        "expiration": None,
        "csInfo": None,
    }


def _simulate_lulu_user_only_import(rules_plist_path, import_json_path):
    """Emulate LuLu 4.5.7's `importRules:userOnly:YES` behavior faithfully."""
    existing = lr.read_full_rules(rules_plist_path)
    imported = json.loads(Path(import_json_path).read_text(encoding="utf-8"))
    # Verify EVERY rule in JSON has type == 3 (triggering userOnly=YES in LuLu!)
    for rules in imported.values():
        for r in rules:
            assert r["type"] == 3, "Non-user rule would trigger full overwrite in LuLu!"

    # Keep all non-user rules untouched
    by_key = {}
    for key, aliases, r in existing:
        if r["type"] != 3:
            by_key.setdefault(key, {"aliases": aliases, "rules": []})["rules"].append(r)

    # Merge imported user rules
    for key, rules in imported.items():
        bucket = by_key.setdefault(key, {"aliases": [], "rules": []})
        for r in rules:
            bucket["rules"].append({
                "key": r["key"],
                "uuid": r["uuid"],
                "path": r["path"],
                "name": r["name"],
                "endpointAddr": r["endpointAddr"],
                "endpointPort": r["endpointPort"],
                "endpointHost": r.get("endpointHost"),
                "isEndpointAddrRegex": r.get("isEndpointAddrRegex", 0),
                "type": r["type"],
                "scope": r.get("scope", 0),
                "action": r["action"],
                "isDisabled": r.get("isDisabled"),
                "pid": None,
                "creation": {"__nsdate__": 700000000.0},
                "expiration": None,
                "csInfo": r.get("csInfo"),
            })

    groups = [(k, v["aliases"], v["rules"]) for k, v in by_key.items()]
    rules_plist_path.write_bytes(_build_rules_plist(groups))


class LuLuRuleMergeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.rules_plist = self.root / "rules.plist"
        self.apple_rule = _sample_rule("com.apple.Safari", "/Applications/Safari.app/Contents/MacOS/Safari", 1, rtype=1, uuid="APPLE-1")
        self.other_user_rule = _sample_rule("/Applications/Other.app/bin", "/Applications/Other.app/bin", 1, addr="1.1.1.1", port="443", rtype=3, uuid="USER-OTHER-1")

    def test_merge_import_preserves_all_other_rules_and_restores_surgically(self):
        self.rules_plist.write_bytes(_build_rules_plist([
            (self.apple_rule["key"], [], [self.apple_rule]),
            (self.other_user_rule["key"], [], [self.other_user_rule]),
        ]))
        plan = lr.plan_apply_import(self.root, port=PORT, rules_path=self.rules_plist, code_ids=IDS)
        self.assertTrue(plan["needed"])
        self.assertEqual(len(plan["managedRules"]), 2)
        staged = json.loads(Path(plan["importPath"]).read_text(encoding="utf-8"))
        # Strictly user-only JSON (type == 3) preserving Other.app rule + adding 2 Claude rules
        self.assertNotIn("com.apple.Safari", staged)
        self.assertIn("/Applications/Other.app/bin", staged)
        self.assertEqual(len(staged["/Applications/Claude.app/*"]), 2)

        _simulate_lulu_user_only_import(self.rules_plist, plan["importPath"])
        self.assertTrue(lr.verify_apply_import(
            plan["managedRules"], plan["baselineFingerprint"], plan["baselineCount"],
            port=PORT, rules_path=self.rules_plist, code_ids=IDS,
        ))

        # Now user adds a NEW rule for another app after setup
        current = lr.read_full_rules(self.rules_plist)
        extra_user = _sample_rule("/Applications/Later.app/bin", "/Applications/Later.app/bin", 0, rtype=3, uuid="USER-LATER-2")
        groups_by_key = {}
        for k, a, r in current:
            groups_by_key.setdefault(k, [a, []])[1].append({**r, "creation": {"__nsdate__": 700000000.0}})
        groups_by_key[extra_user["key"]] = [[], [extra_user]]
        self.rules_plist.write_bytes(_build_rules_plist([(k, v[0], v[1]) for k, v in groups_by_key.items()]))

        # Restore removes ONLY Preflight-added Claude rules, keeping Apple + Other.app + Later.app!
        rplan = lr.plan_restore_import(self.root, plan["managedRules"], rules_path=self.rules_plist)
        self.assertTrue(rplan["needed"])
        self.assertEqual(rplan["conflicts"], [])
        self.assertEqual(len(rplan["removedUuids"]), 2)
        _simulate_lulu_user_only_import(self.rules_plist, rplan["importPath"])
        self.assertTrue(lr.verify_restore_import(
            rplan["removedUuids"], rplan["expectedFingerprint"], rplan["expectedCount"],
            rules_path=self.rules_plist,
        ))
        final_uuids = {r["uuid"] for _k, _a, r in lr.read_full_rules(self.rules_plist)}
        self.assertEqual(final_uuids, {"APPLE-1", "USER-OTHER-1", "USER-LATER-2"})

    def test_preexisting_claude_rules_are_reused_without_import(self):
        c_block = _sample_rule("/Applications/Claude.app/*", "/Applications/Claude.app/*", 0, "*", "*", rtype=3, uuid="EXIST-BLK")
        c_allow = _sample_rule("/Applications/Claude.app/*", "/Applications/Claude.app/*", 1, "127.0.0.1", str(PORT), "127.0.0.1", rtype=3, uuid="EXIST-ALW")
        self.rules_plist.write_bytes(_build_rules_plist([
            ("/Applications/Claude.app/*", [], [c_block, c_allow]),
            (self.other_user_rule["key"], [], [self.other_user_rule]),
        ]))
        plan = lr.plan_apply_import(self.root, port=PORT, rules_path=self.rules_plist, code_ids=IDS)
        self.assertFalse(plan["needed"])
        self.assertEqual(plan["managedRules"], [])

    def test_temporary_pid_user_rule_aborts_import_to_avoid_data_loss(self):
        temp_rule = _sample_rule("/Applications/Temp.app/bin", "/Applications/Temp.app/bin", 1, rtype=3, uuid="TMP-PID", pid=999)
        self.rules_plist.write_bytes(_build_rules_plist([
            (temp_rule["key"], [], [temp_rule]),
        ]))
        with self.assertRaisesRegex(ValueError, "临时用户规则"):
            lr.plan_apply_import(self.root, port=PORT, rules_path=self.rules_plist, code_ids=IDS)

    def test_restore_preserves_user_edited_managed_rule_as_conflict(self):
        self.rules_plist.write_bytes(_build_rules_plist([(self.other_user_rule["key"], [], [self.other_user_rule])]))
        plan = lr.plan_apply_import(self.root, port=PORT, rules_path=self.rules_plist, code_ids=IDS)
        _simulate_lulu_user_only_import(self.rules_plist, plan["importPath"])
        # User edits the Preflight-added allow rule's port
        recs = lr.read_full_rules(self.rules_plist)
        edited_uuid = plan["managedRules"][1]["uuid"]
        by_key = {}
        for k, a, r in recs:
            item = dict(r, creation={"__nsdate__": 700000000.0})
            if item["uuid"] == edited_uuid:
                item["endpointPort"] = "443"
            by_key.setdefault(k, [a, []])[1].append(item)
        self.rules_plist.write_bytes(_build_rules_plist([(k, v[0], v[1]) for k, v in by_key.items()]))

        rplan = lr.plan_restore_import(self.root, plan["managedRules"], rules_path=self.rules_plist)
        self.assertTrue(rplan["conflicts"])
        # Only the unmodified block rule is scheduled for removal; edited allow rule is preserved
        self.assertEqual(len(rplan["removedUuids"]), 1)
        self.assertNotIn(edited_uuid, rplan["removedUuids"])

    def test_firewall_setup_orchestrates_lulu_import_and_verify(self):
        self.rules_plist.write_bytes(_build_rules_plist([(self.other_user_rule["key"], [], [self.other_user_rule])]))
        state_dir = self.root / "state"
        missing_rules = {
            "configuration_ready": False,
            "findings": [
                {"name": "extension", "passed": True, "detail": "ok"},
                {"name": "socket_filter", "passed": True, "detail": "ok"},
                {"name": "enabled", "passed": True, "detail": "ok"},
                {"name": "localhost", "passed": True, "detail": "ok"},
                {"name": "dns", "passed": True, "detail": "ok"},
                {"name": "allow_list", "passed": True, "detail": "ok"},
                {"name": "block_mode", "passed": True, "detail": "ok"},
                {"name": "bundle_block", "passed": False, "detail": "missing"},
                {"name": "relay_allow", "passed": False, "detail": "missing"},
                {"name": "conflicts", "passed": True, "detail": "ok"},
            ],
        }
        ready_rules = {"configuration_ready": True, "findings": []}
        watcher_on = {"installed": True, "loaded": True, "running": True}
        with patch.object(fw.sys, "platform", "darwin"), \
             patch.object(fw, "_folder", return_value=state_dir), \
             patch.object(fw, "_proxy_state", return_value="ready"), \
             patch.object(fw, "_profile_installed", return_value=False), \
             patch.object(fw.dock, "dock_watcher_status", return_value=watcher_on), \
             patch.object(fw.dock, "install_dock_watcher", return_value=watcher_on), \
             patch.object(lr, "_profile", return_value=(self.root, {})), \
             patch.object(lr, "_code_identities", return_value=IDS), \
             patch.object(fw, "inspect_desktop_firewall", side_effect=[missing_rules, missing_rules, ready_rules]):
            step1 = fw.configure_firewall("apply")
            self.assertEqual(step1["status"], "pending")
            self.assertEqual(step1["actionRequired"], "luluImport")
            _simulate_lulu_user_only_import(self.rules_plist, step1["importPath"])
            step2 = fw.configure_firewall("apply", verify=True)
            self.assertEqual(step2["status"], "ok")
            # Temporary staged JSON cleaned up
            self.assertFalse(Path(step1["importPath"]).exists())


if __name__ == "__main__":
    unittest.main()
