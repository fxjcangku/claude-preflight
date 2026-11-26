import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from preflight import native_firewall as firewall


PORT = 47836
BUNDLE = "/Applications/Claude.app/*"
REGISTERED = ("*\t*\tVBG97UB4TA\tcom.objective-see.lulu.extension "
              "(4.5.7/4.5.7)\tLuLu\t[activated enabled]")


def record(action, address="*", port="*", path=BUNDLE, **overrides):
    return {
        "key": path, "path": path, "action": action, "endpointAddr": address,
        "endpointPort": port, "endpointHost": None, "scope": None, "pid": None,
        "expiration": None, "isDisabled": None, "isEndpointAddrRegex": 0,
        **overrides,
    }


def group(*rows):
    return [(row["key"], [], row) for row in rows]


class NativeFirewallTests(unittest.TestCase):
    def setUp(self):
        self.block = record(0)
        self.allow = record(1, "127.0.0.1", str(PORT), endpointHost="127.0.0.1")
        self.identities = {"com.anthropic.claudefordesktop"}

    def test_requires_two_permanent_bundle_rules(self):
        for path in (BUNDLE, "/Applications/Claude.app/Contents/*"):
            rows = group(dict(self.block, key=path, path=path), dict(self.allow, key=path, path=path))
            self.assertEqual(firewall._assess_rules(rows, PORT, self.identities), (True, True, False))
        rows = group(self.block, dict(self.allow, pid=149))
        self.assertFalse(firewall._assess_rules(rows, PORT, self.identities)[1])
        rows = group(dict(self.block, isDisabled=1), self.allow)
        self.assertFalse(firewall._assess_rules(rows, PORT, self.identities)[0])
        self.assertFalse(firewall._assess_rules(group(self.block, self.allow), PORT + 1, set())[1])

    def test_global_nested_and_signing_identity_conflicts_are_rejected(self):
        candidates = [
            record(1, path="*"), record(1, path="/Applications/*"),
            record(1, path="/Applications/Claude.app/Contents/Frameworks/executable"),
            record(1, path="/elsewhere/program", key="com.anthropic.claudefordesktop:Signer"),
            record(1, path="/elsewhere/program", scope=2),
            dict(self.allow, isEndpointAddrRegex=1),
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                verdict = firewall._assess_rules(group(self.block, self.allow, candidate), PORT, self.identities)
                self.assertTrue(verdict[2])
        unrelated = record(1, path="/Applications/Unrelated.app/Contents/MacOS/bin")
        self.assertFalse(firewall._assess_rules(group(self.block, self.allow, unrelated), PORT, set())[2])

    def test_reads_reachable_archive_rules_and_rejects_a_damaged_reference(self):
        objects = ["$null"]

        def ref(value):
            if value is None:
                return plistlib.UID(0)
            objects.append(value)
            return plistlib.UID(len(objects) - 1)

        def mapping(pairs):
            return ref({"$class": ref({"$classname": "NSMutableDictionary"}),
                        "NS.keys": [ref(k) for k, _ in pairs], "NS.objects": [v for _, v in pairs]})

        encoded = {k: ref(v) for k, v in self.allow.items()}
        encoded["$class"] = ref({"$classname": "Rule"})
        encoded_ref = ref(encoded)
        rules = ref({"$class": ref({"$classname": "NSMutableArray"}), "NS.objects": [encoded_ref]})
        root = mapping([(BUNDLE, mapping([("rules", rules)]))])
        ref(dict(encoded, action=ref(0)))  # Orphan object outside the active rule map.
        archive = {"$archiver": "NSKeyedArchiver", "$top": {"root": root}, "$objects": objects}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.plist"
            path.write_bytes(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))
            self.assertEqual(firewall._read_rules(path), group(self.allow))
            encoded["path"] = plistlib.UID(len(objects) + 10)
            path.write_bytes(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))
            with self.assertRaises(ValueError):
                firewall._read_rules(path)

    def test_configuration_and_runtime_are_separate(self):
        prefs = {"disabled": False, "allowLocalHost": False, "allowDNS": False}
        listing = subprocess.CompletedProcess([], 0, stdout=REGISTERED)
        with patch.object(firewall.sys, "platform", "darwin"), \
             patch.object(firewall.subprocess, "run", return_value=listing), \
             patch.object(firewall, "_socket_filter_enabled", return_value=True), \
             patch.object(firewall, "_profile", return_value=(Path("/unused"), prefs)), \
             patch.object(firewall, "_read_rules", return_value=group(self.block, self.allow)), \
             patch.object(firewall, "_code_identities", return_value=self.identities):
            ready = firewall.inspect_desktop_firewall(PORT)
            self.assertTrue(ready["configuration_ready"])
            self.assertFalse(ready["runtime_verified"])
            firewall.assert_desktop_firewall(PORT)
            for key in ("disabled", "allowLocalHost", "allowDNS", "useAllowList", "blockMode"):
                with self.subTest(key=key), patch.dict(prefs, {key: True}):
                    with self.assertRaises(ValueError):
                        firewall.assert_desktop_firewall(PORT)
            with patch.object(firewall, "_socket_filter_enabled", return_value=False):
                self.assertFalse(firewall.inspect_desktop_firewall(PORT)["configuration_ready"])
            with patch.object(firewall, "_read_rules", side_effect=ValueError):
                self.assertFalse(firewall.inspect_desktop_firewall(PORT)["configuration_ready"])
