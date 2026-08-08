#!/usr/bin/env python3
"""Read-only Home Assistant login audit viewer for Supervisor Ingress."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


PORT = 8099
AUTH_PATH = Path("/homeassistant/.storage/auth")
OPTIONS_PATH = Path("/data/options.json")
EVENTS_PATH = Path("/data/login_failures.jsonl")
SETTINGS_PATH = Path("/data/ip_lists.json")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
FAILURE_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r".*?Login attempt or request with invalid authentication from "
    r"(?P<host>.*?) \((?P<ip>[^)]+)\)\. Requested URL: '(?P<url>[^']*)'\."
    r"(?: \((?P<agent>.*)\))?"
)
LOCK = threading.Lock()


def load_options() -> dict[str, Any]:
    defaults = {"safe_ips": [], "retention_days": 90, "max_records": 2000}
    try:
        loaded = json.loads(OPTIONS_PATH.read_text(encoding="utf-8"))
        defaults.update(loaded)
    except (OSError, ValueError, TypeError):
        pass
    defaults["safe_ips"] = [str(value).strip() for value in defaults["safe_ips"] if str(value).strip()]
    return defaults


def validate_networks(values: Any) -> list[str]:
    if not isinstance(values, list) or len(values) > 200:
        raise ValueError("IP list must be an array with at most 200 entries")
    result = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        try:
            network = str(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid IP or CIDR: {text[:128]}") from exc
        if network not in result:
            result.append(network)
    return result


def load_ip_lists() -> dict[str, list[str]]:
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        return {
            "safe_ips": validate_networks(data.get("safe_ips", [])),
            "blacklist_ips": validate_networks(data.get("blacklist_ips", [])),
        }
    except FileNotFoundError:
        # Import the existing app option once when upgrading from 0.1.x.
        return {"safe_ips": validate_networks(load_options()["safe_ips"]), "blacklist_ips": []}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"IP list load failed: {type(exc).__name__}: {exc}", flush=True)
        return {"safe_ips": [], "blacklist_ips": []}


def save_ip_lists(safe_ips: Any, blacklist_ips: Any) -> dict[str, list[str]]:
    data = {
        "safe_ips": validate_networks(safe_ips),
        "blacklist_ips": validate_networks(blacklist_ips),
    }
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = SETTINGS_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(SETTINGS_PATH)
    return data


def normalize_ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return str(value).strip()[:128]


def ip_in_list(value: Any, networks: list[str]) -> bool:
    normalized = normalize_ip(value)
    if not normalized:
        return False
    for entry in networks:
        try:
            if ipaddress.ip_address(normalized) in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if normalized == entry:
                return True
    return False


def classify_ip(value: Any, lists: dict[str, list[str]]) -> str:
    if ip_in_list(value, lists["blacklist_ips"]):
        return "blacklist"
    if ip_in_list(value, lists["safe_ips"]):
        return "safe"
    return "unknown"


def client_label(client_id: Any) -> str:
    value = str(client_id or "未知").strip()
    labels = {
        "https://home-assistant.io/android": "Home Assistant Android App",
        "https://oauth-redirect.googleusercontent.com/r/hajj-8f5db": "Google Assistant",
        "https://pitangui.amazon.com/": "Amazon Alexa",
    }
    return labels.get(value, value[:300])


def load_auth() -> dict[str, Any]:
    data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))["data"]
    return data


def admin_user_ids(data: dict[str, Any]) -> set[str]:
    return {
        user["id"]
        for user in data.get("users", [])
        if user.get("is_active") and (user.get("is_owner") or "system-admin" in user.get("group_ids", []))
    }


def successful_logins(data: dict[str, Any], lists: dict[str, list[str]]) -> list[dict[str, Any]]:
    users = {user["id"]: user for user in data.get("users", [])}
    rows = []
    for token in data.get("refresh_tokens", []):
        if token.get("token_type") != "normal":
            continue
        user = users.get(token.get("user_id"), {})
        ip = normalize_ip(token.get("last_used_ip"))
        rows.append(
            {
                "status": "success",
                "user": str(user.get("name") or "未知使用者")[:200],
                "created_at": token.get("created_at"),
                "last_used_at": token.get("last_used_at"),
                "ip": ip,
                "classification": classify_ip(ip, lists),
                "client": client_label(token.get("client_id")),
            }
        )
    rows.sort(key=lambda row: row.get("created_at") or "", reverse=True)
    return rows


def supervisor_logs() -> str:
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    if not token:
        return ""
    request = urllib.request.Request(
        "http://supervisor/core/logs",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.read(8 * 1024 * 1024).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def parse_failures(log_text: str, lists: dict[str, list[str]]) -> list[dict[str, Any]]:
    rows = []
    for raw_line in ANSI_RE.sub("", log_text).splitlines():
        match = FAILURE_RE.search(raw_line)
        if not match:
            continue
        item = match.groupdict()
        ip = normalize_ip(item.get("ip"))
        rows.append(
            {
                "status": "failure",
                "timestamp": item["timestamp"],
                "ip": ip,
                "classification": classify_ip(ip, lists),
                "host": item.get("host", "")[:300],
                "url": item.get("url", "")[:500],
                "agent": (item.get("agent") or "")[:1000],
            }
        )
    return rows


def failure_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row.get("timestamp"), row.get("ip"), row.get("url"), row.get("agent"))


def load_saved_failures() -> list[dict[str, Any]]:
    rows = []
    try:
        for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines():
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
            except ValueError:
                continue
    except OSError:
        pass
    return rows


def persist_failures(new_rows: list[dict[str, Any]], options: dict[str, Any]) -> list[dict[str, Any]]:
    with LOCK:
        combined = load_saved_failures()
        known = {failure_key(row) for row in combined}
        combined.extend(row for row in new_rows if failure_key(row) not in known)
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(options["retention_days"]))
        kept = []
        for row in combined:
            try:
                stamp = datetime.fromisoformat(str(row["timestamp"]).replace(" ", "T")).replace(tzinfo=timezone.utc)
                if stamp >= cutoff:
                    kept.append(row)
            except (KeyError, TypeError, ValueError):
                kept.append(row)
        kept = kept[-int(options["max_records"]):]
        EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVENTS_PATH.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in kept), encoding="utf-8")
        return sorted(kept, key=lambda row: row.get("timestamp") or "", reverse=True)


def collect() -> dict[str, Any]:
    options = load_options()
    lists = load_ip_lists()
    auth = load_auth()
    failures = parse_failures(supervisor_logs(), lists)
    failures = persist_failures(failures, options)
    for failure in failures:
        failure["classification"] = classify_ip(failure.get("ip"), lists)
        failure.pop("safe", None)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "successes": successful_logins(auth, lists),
        "failures": failures,
        **lists,
    }


INDEX_FALLBACK = """<!doctype html><html lang=\"zh-Hant\"><head><meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>HA 登入稽核</title>
<style>
:root{color-scheme:light dark;--bg:#f4f6f8;--card:#fff;--text:#18212b;--muted:#617080;--line:#dce2e8;--ok:#16803d;--bad:#bd2c2c;--safe:#e6f6ec;--warn:#fff0ee} @media(prefers-color-scheme:dark){:root{--bg:#101418;--card:#1b2229;--text:#edf2f7;--muted:#a8b4c0;--line:#34404b;--safe:#143824;--warn:#492020}}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:14px system-ui,-apple-system,sans-serif} main{max-width:1400px;margin:auto;padding:20px}.top{display:flex;gap:16px;align-items:center;justify-content:space-between;flex-wrap:wrap}h1{margin:0;font-size:24px}.muted{color:var(--muted)}button{border:0;border-radius:8px;padding:10px 16px;background:#03a9f4;color:white;cursor:pointer}.cards{display:grid;grid-template-columns:repeat(3,minmax(150px,1fr));gap:12px;margin:18px 0}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}.number{font-size:28px;font-weight:700;margin-top:5px}.tabs{display:flex;gap:8px;margin:18px 0 10px}.tab{background:transparent;color:var(--text);border:1px solid var(--line)}.tab.active{background:#03a9f4;color:#fff}.table-wrap{overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line)}th{position:sticky;top:0;background:var(--card)}tr.safe{background:var(--safe)}tr.unsafe{background:var(--warn)}.badge{display:inline-block;padding:3px 8px;border-radius:99px;font-weight:600}.badge.ok{color:var(--ok);background:var(--safe)}.badge.bad{color:var(--bad);background:var(--warn)}.agent{max-width:360px;overflow:hidden;text-overflow:ellipsis}#error{color:var(--bad);margin:12px 0}.hide{display:none}@media(max-width:700px){main{padding:12px}.cards{grid-template-columns:1fr}th,td{padding:9px 8px}}
</style></head><body><main><div class=\"top\"><div><h1>Home Assistant 登入稽核</h1><div class=\"muted\" id=\"updated\">載入中…</div></div><button onclick=\"loadAudit()\">重新整理</button></div><div id=\"error\"></div>
<section class=\"cards\"><div class=\"card\">成功工作階段<div class=\"number\" id=\"successCount\">-</div></div><div class=\"card\">登入失敗<div class=\"number\" id=\"failureCount\">-</div></div><div class=\"card\">非安全 IP 失敗<div class=\"number\" id=\"unsafeCount\">-</div></div></section>
<div class=\"tabs\"><button class=\"tab active\" onclick=\"showTab('failure',this)\">登入失敗</button><button class=\"tab\" onclick=\"showTab('success',this)\">登入成功</button></div>
<div id=\"failure\" class=\"table-wrap\"><table><thead><tr><th>時間</th><th>來源 IP</th><th>判定</th><th>裝置／瀏覽器</th><th>請求</th></tr></thead><tbody></tbody></table></div>
<div id=\"success\" class=\"table-wrap hide\"><table><thead><tr><th>建立時間</th><th>使用者</th><th>最後使用</th><th>來源 IP</th><th>判定</th><th>登入端</th></tr></thead><tbody></tbody></table></div>
<script>
const esc=s=>String(s??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));
const time=s=>s?new Date(s.includes('T')?s:s.replace(' ','T')).toLocaleString('zh-TW'):'—';
function badge(s){return s?'<span class=\"badge ok\">安全 IP</span>':'<span class=\"badge bad\">需注意</span>'}
function showTab(id,b){document.querySelectorAll('.table-wrap').forEach(x=>x.classList.add('hide'));document.getElementById(id).classList.remove('hide');document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active')}
async function loadAudit(){document.getElementById('error').textContent='';try{const r=await fetch('api/audit',{cache:'no-store'});if(!r.ok)throw new Error(await r.text());const d=await r.json();successCount.textContent=d.successes.length;failureCount.textContent=d.failures.length;unsafeCount.textContent=d.failures.filter(x=>!x.safe).length;updated.textContent='更新：'+time(d.generated_at)+'｜安全 IP：'+d.safe_ips.join(', ');document.querySelector('#failure tbody').innerHTML=d.failures.map(x=>`<tr class=\"${x.safe?'safe':'unsafe'}\"><td>${time(x.timestamp)}</td><td>${esc(x.ip)}</td><td>${badge(x.safe)}</td><td class=\"agent\" title=\"${esc(x.agent)}\">${esc(x.agent||'—')}</td><td>${esc(x.url)}</td></tr>`).join('')||'<tr><td colspan=\"5\">目前沒有失敗紀錄</td></tr>';document.querySelector('#success tbody').innerHTML=d.successes.map(x=>`<tr class=\"${x.safe?'safe':''}\"><td>${time(x.created_at)}</td><td>${esc(x.user)}</td><td>${time(x.last_used_at)}</td><td>${esc(x.ip||'—')}</td><td>${badge(x.safe)}</td><td>${esc(x.client)}</td></tr>`).join('')||'<tr><td colspan=\"6\">目前沒有成功紀錄</td></tr>'}catch(e){document.getElementById('error').textContent='載入失敗：'+e.message}}
loadAudit();setInterval(loadAudit,60000);
</script></main></body></html>"""
try:
    INDEX = Path("/app/index.html").read_text(encoding="utf-8")
except OSError:
    INDEX = INDEX_FALLBACK


class Handler(BaseHTTPRequestHandler):
    server_version = "HALoginAudit/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}", flush=True)

    def send_body(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'")
        self.end_headers()
        self.wfile.write(body)

    def ingress_admin(self) -> bool:
        user_id = self.headers.get("X-Remote-User-Id", "")
        try:
            return user_id in admin_user_ids(load_auth())
        except (OSError, ValueError, KeyError):
            return False

    def do_GET(self) -> None:
        if not self.ingress_admin():
            self.send_body(403, "僅限 Home Assistant 管理員使用".encode(), "text/plain; charset=utf-8")
            return
        path = self.path.split("?", 1)[0].rstrip("/")
        if path.endswith("/api/audit") or path == "/api/audit":
            try:
                body = json.dumps(collect(), ensure_ascii=False).encode()
                self.send_body(200, body, "application/json; charset=utf-8")
            except Exception as exc:  # keep secrets and tracebacks out of HTTP responses
                print(f"audit collection failed: {type(exc).__name__}: {exc}", flush=True)
                self.send_body(500, b'{"error":"audit collection failed"}', "application/json")
            return
        self.send_body(200, INDEX.encode(), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        if not self.ingress_admin():
            self.send_body(403, "僅限 Home Assistant 管理員使用".encode(), "text/plain; charset=utf-8")
            return
        path = self.path.split("?", 1)[0].rstrip("/")
        if not (path.endswith("/api/settings") or path == "/api/settings"):
            self.send_body(404, b'{"error":"not found"}', "application/json")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 32768:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            result = save_ip_lists(payload.get("safe_ips"), payload.get("blacklist_ips"))
            self.send_body(200, json.dumps(result, ensure_ascii=False).encode(), "application/json; charset=utf-8")
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.send_body(400, json.dumps({"error": str(exc)}, ensure_ascii=False).encode(), "application/json; charset=utf-8")


def poll_forever() -> None:
    while True:
        try:
            options = load_options()
            persist_failures(parse_failures(supervisor_logs(), load_ip_lists()), options)
        except Exception as exc:
            print(f"background audit failed: {type(exc).__name__}: {exc}", flush=True)
        time.sleep(15)


if __name__ == "__main__":
    threading.Thread(target=poll_forever, daemon=True).start()
    print(f"HA Login Audit listening on {PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
