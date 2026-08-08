import importlib.util
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
