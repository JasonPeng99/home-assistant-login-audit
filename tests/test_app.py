import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "login-audit" / "app.py"
SPEC = importlib.util.spec_from_file_location("login_audit", MODULE_PATH)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class AuditTests(unittest.TestCase):
    def test_parse_failure(self):
        line = (
            "2026-08-09 06:15:49.922 WARNING [homeassistant.components.http.ban] "
            "Login attempt or request with invalid authentication from example (203.0.113.10). "
            "Requested URL: '/auth/login_flow/abc'. (Mozilla/5.0 Line/26.11.0/IAB)"
        )
        lists = {"safe_ips": ["203.0.113.10/32"], "blacklist_ips": []}
        rows = APP.parse_failures(line, lists)
        self.assertEqual(1, len(rows))
        self.assertEqual("203.0.113.10", rows[0]["ip"])
        self.assertEqual("safe", rows[0]["classification"])
        self.assertIn("Line/26.11.0", rows[0]["agent"])

    def test_safe_cidr(self):
        self.assertTrue(APP.ip_in_list("192.168.1.18", ["192.168.1.0/24"]))
        self.assertFalse(APP.ip_in_list("192.168.2.18", ["192.168.1.0/24"]))

    def test_blacklist_takes_precedence(self):
        lists = {"safe_ips": ["192.168.1.0/24"], "blacklist_ips": ["192.168.1.18/32"]}
        self.assertEqual("blacklist", APP.classify_ip("192.168.1.18", lists))
        self.assertEqual("safe", APP.classify_ip("192.168.1.19", lists))

    def test_validate_networks_canonicalizes_and_rejects_invalid_input(self):
        self.assertEqual(["192.168.1.0/24"], APP.validate_networks(["192.168.1.18/24", "192.168.1.0/24"]))
        with self.assertRaises(ValueError):
            APP.validate_networks(["not-an-ip"])

    def test_ip_ban_sync_preserves_unmanaged_and_removes_only_managed(self):
        original = (APP.IP_BANS_PATH, APP.MANAGED_BANS_PATH, APP.RESTART_REQUIRED_PATH)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            APP.IP_BANS_PATH = base / "ip_bans.yaml"
            APP.MANAGED_BANS_PATH = base / "managed.json"
            APP.RESTART_REQUIRED_PATH = base / "restart"
            APP.IP_BANS_PATH.write_text(
                "198.51.100.1:\n  banned_at: '2026-08-01T00:00:00+00:00'\n"
                "203.0.113.10:\n  banned_at: '2026-08-02T00:00:00+00:00'\n",
                encoding="utf-8",
            )
            APP.MANAGED_BANS_PATH.write_text(json.dumps(["203.0.113.10"]), encoding="utf-8")
            try:
                status = APP.sync_ip_bans(["203.0.113.11/32", "192.0.2.0/24"])
                content = APP.IP_BANS_PATH.read_text(encoding="utf-8")
                self.assertIn("198.51.100.1:", content)
                self.assertNotIn("203.0.113.10:", content)
                self.assertIn("203.0.113.11:", content)
                self.assertEqual(["192.0.2.0/24"], status["audit_only_cidrs"])
                self.assertTrue(status["restart_required"])
            finally:
                APP.IP_BANS_PATH, APP.MANAGED_BANS_PATH, APP.RESTART_REQUIRED_PATH = original

    def test_success_never_exposes_token_fields(self):
        data = {
            "users": [{"id": "u1", "name": "安娜"}],
            "refresh_tokens": [{
                "user_id": "u1", "token_type": "normal", "token": "secret",
                "jwt_key": "secret2", "created_at": "2026-08-08T22:15:57+00:00",
                "last_used_at": "2026-08-08T22:15:57+00:00",
                "last_used_ip": "203.0.113.10", "client_id": "https://example.test/",
            }],
        }
        rows = APP.successful_logins(data, {"safe_ips": ["203.0.113.10/32"], "blacklist_ips": []})
        self.assertEqual("安娜", rows[0]["user"])
        self.assertNotIn("token", rows[0])
        self.assertNotIn("jwt_key", rows[0])


if __name__ == "__main__":
    unittest.main()
