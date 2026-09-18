#!/usr/bin/env python3
"""网关网络层 HTTP API 全链路 E2E（真 server 二进制 + 真 SSH 跳板 + 真库）。

运行依赖（缺一不适用，非 CI 常规测试）。连接参数全部经 env 注入
（清单见仓库根 .env.example，自备测试库，凭据不进脚本）：
- GW_E2E_HOST：测试库主机（Redis 6379 / Mongo 27017 经 SSH 隧道，
  TDengine 6041 直连；SSH 22 privateKey 认证）。
- GW_E2E_REDIS_PASSWORD / GW_E2E_MONGO_PASSWORD。
- 本机私钥（GW_E2E_SSH_KEY，缺省 ~/.ssh/id_ed25519，无口令，
  在跳板 authorized_keys 内）。
- dbmaster-server release 二进制（cargo build --release）。

链路：embedded server 二进制 → /api/gw/connections（test/register）→
/api/gw/connections/{id}/query（SSE）→ 跳板隧道 → Redis/Mongo/TDengine。
七断言：负例直连拒绝 / redis test 经隧道 / redis query PING / mongo ping /
tdengine 直连 / tdengine 经隧道（跳板本机地址语义）/ 列表无凭据泄漏。
用法：python scripts/e2e_gw_http.py（退出码 0 = 全过；必需 env 缺失时
打印 SKIP 并退出 0）。
"""
import json, os, subprocess, tempfile, time, urllib.request, socket, sys

EXE = r"C:\Users\hobbs\Projects\dbmaster\dbmaster-server\target\release\dbmaster-server.exe"
USER = "root"

# ── env 门控（任一缺失 → 打印 SKIP 后 exit 0）──
HOST = os.environ.get("GW_E2E_HOST", "")
REDIS_PASSWORD = os.environ.get("GW_E2E_REDIS_PASSWORD", "")
MONGO_PASSWORD = os.environ.get("GW_E2E_MONGO_PASSWORD", "")
_missing = [n for n, v in (("GW_E2E_HOST", HOST),
                           ("GW_E2E_REDIS_PASSWORD", REDIS_PASSWORD),
                           ("GW_E2E_MONGO_PASSWORD", MONGO_PASSWORD)) if not v]
if _missing:
    print("SKIP: " + " / ".join(_missing) + " not set")
    sys.exit(0)
KEY_PATH = os.environ.get("GW_E2E_SSH_KEY",
                          os.path.join(os.path.expanduser("~"), ".ssh", "id_ed25519"))
KEY = open(KEY_PATH).read()
results = []

def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))

def api(method, path, body=None, sse=False, timeout=30):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if sse:
            events, cur = [], {}
            start = time.time()
            for raw in r:
                line = raw.decode().rstrip("\n")
                if line.startswith("event: "): cur["event"] = line[7:]
                elif line.startswith("data: "):
                    cur["data"] = line[6:]
                    events.append(cur); cur = {}
                if time.time() - start > timeout: break
            return events
        return json.loads(r.read().decode())

def ssh_block():  # privateKey 认证（真实场景：跳板只收公钥）
    return {"host": HOST, "port": 22, "username": USER, "authMode": "privateKey", "privateKey": KEY}

# ── 起 embedded server ──
datadir = tempfile.mkdtemp(prefix="dbm-e2e-gw-")
proc = subprocess.Popen([EXE, "--embedded", "--data-dir", datadir],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.PIPE,
    text=True, encoding="utf-8")
line = proc.stdout.readline()
hs = json.loads(line)
PORT, TOKEN = hs["port"], hs["access_token"]
time.sleep(0.5)
print(f"server up: port={PORT}\n")

try:
    # ① 负例：Redis 直连（外部不可达）→ 必须 ok:false（证明隧道不是摆设）
    r = api("POST", "/api/gw/connections/test",
            {"dbType": "redis", "host": HOST, "port": 6379, "password": REDIS_PASSWORD})
    check("test redis 直连(负例) 拒绝", r.get("ok") is False, r.get("error", "")[:60])

    # ② Redis + SSH 隧道 test → ok:true
    r = api("POST", "/api/gw/connections/test",
            {"dbType": "redis", "host": HOST, "port": 6379, "password": REDIS_PASSWORD, "ssh": ssh_block()})
    check("test redis 经 SSH 隧道 通过", r.get("ok") is True, f"elapsed={r.get('elapsedMs')}ms")

    # ③ Redis 注册 + query PING（SSE）
    r = api("POST", "/api/gw/connections",
            {"name": "e2e-ssh-redis", "dbType": "redis", "host": HOST, "port": 6379,
             "password": REDIS_PASSWORD, "readOnly": False, "ssh": ssh_block()})
    rid = r["serverConnId"]
    ev = api("POST", f"/api/gw/connections/{rid}/query",
             {"kind": "redis", "command": ["PING"]}, sse=True)
    fin = [e for e in ev if e.get("event") == "complete"]
    pong_ok = any("PONG" in e.get("data", "") for e in ev)
    check("redis query PING 经隧道", bool(fin) and pong_ok, f"events={[e.get('event') for e in ev]}")

    # ④ Mongo + SSH 隧道：注册 + runCommand ping
    r = api("POST", "/api/gw/connections",
            {"name": "e2e-ssh-mongo", "dbType": "mongodb", "host": HOST, "port": 27017,
             "username": "admin", "password": MONGO_PASSWORD, "defaultDatabase": "admin",
             "ssh": ssh_block()})
    mid = r["serverConnId"]
    ev = api("POST", f"/api/gw/connections/{mid}/query",
             {"kind": "mongo", "command": {"ping": 1}, "database": "admin"}, sse=True)
    ok1 = any('"ok":1' in e.get("data", "") or '"ok": 1' in e.get("data", "") for e in ev)
    check("mongo runCommand ping 经隧道", any(e.get("event") == "complete" for e in ev) and ok1 and not any(e.get("event") == "error" for e in ev),
          f"events={[e.get('event') for e in ev]}")

    # ⑤ TDengine 直连（6041 对外开放）注册 + SELECT SERVER_VERSION()
    r = api("POST", "/api/gw/connections",
            {"name": "e2e-direct-td", "dbType": "tdengine", "host": HOST, "port": 6041,
             "username": "root", "password": "taosdata"})
    tid = r["serverConnId"]
    ev = api("POST", f"/api/gw/connections/{tid}/query",
             {"kind": "tdengine", "sql": "SELECT SERVER_VERSION()"}, sse=True)
    ver = any("3.3" in e.get("data", "") for e in ev)
    check("tdengine 直连 SELECT SERVER_VERSION()", any(e.get("event") == "complete" for e in ev) and ver and not any(e.get("event") == "error" for e in ev),
          f"events={[e.get('event') for e in ev]}")

    # ⑥ TDengine 走隧道 + 跳板本机地址语义（target=127.0.0.1:6041 从跳板视角）
    r = api("POST", "/api/gw/connections",
            {"name": "e2e-ssh-td", "dbType": "tdengine", "host": "127.0.0.1", "port": 6041,
             "username": "root", "password": "taosdata", "ssh": ssh_block()})
    tid2 = r["serverConnId"]
    ev = api("POST", f"/api/gw/connections/{tid2}/query",
             {"kind": "tdengine", "sql": "SELECT SERVER_VERSION()"}, sse=True)
    check("tdengine 经隧道(跳板本机地址)", any(e.get("event") == "complete" for e in ev)
          and any("3.3" in e.get("data", "") for e in ev)
          and not any(e.get("event") == "error" for e in ev), "")

    # ⑦ 秘密不落 extra（安全审计点：注册行的 extra 不含 privateKey/password）
    r = api("GET", "/api/gw/connections")
    plain = json.dumps(r, ensure_ascii=False)
    check("列表投影无凭据泄漏", "BEGIN OPENSSH" not in plain and REDIS_PASSWORD not in plain)
finally:
    proc.kill(); proc.wait()
    import shutil; shutil.rmtree(datadir, ignore_errors=True)

ok = sum(1 for _, o, _ in results if o)
print(f"\n=== {ok}/{len(results)} passed ===")
sys.exit(0 if ok == len(results) else 1)
