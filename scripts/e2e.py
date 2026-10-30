#!/usr/bin/env python3
"""End-to-end test of GhostCash.

Starts a bank server, an app server and three wallet agents (alice, bob,
carol) on temporary ports with small crypto parameters, then drives the real
HTTP APIs through the whole scenario:

  signup -> generate coins -> transfer -> redeem -> double spend (traced to the
  withdrawer) -> forged redeem -> offline/unknown receiver -> insufficient
  balance -> bank restart (state survives)

Run `make servers` first (or `make e2e`). Exits non-zero if any check fails.
Set E2E_FULL=1 to run with the specified sizes (256-bit q, 3072-bit p, 2048-bit
RSA) instead of the small test sizes.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.environ.get("E2E_BUILD", os.path.join(ROOT, "build"))  # E2E_BUILD: run against another set of binaries
UI = os.path.join(ROOT, "ui")

BANK_PORT, APP_PORT = 19000, 18000
WALLET_PORTS = {"alice": 18081, "bob": 18082, "carol": 18083, "erin": 18084}
# wallet key -> registered username, where they differ (capital letters are allowed)
USERNAMES = {"erin": "Erin"}
INTERNAL_KEY = "e2e-internal-key"

procs = []
failures = []


def http(port, path, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except ValueError:
            return e.code, {"error": raw.decode(errors="replace")}


def wallet(user, path, method="GET", body=None):
    return http(WALLET_PORTS[user], path, method, body)


def check(name, condition, detail=""):
    print(("  PASS  " if condition else "  FAIL  ") + name + ("" if condition else "   <- " + str(detail)))
    if not condition:
        failures.append(name)


def start(name, argv, logdir):
    log = open(os.path.join(logdir, name + ".log"), "w")
    p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
    procs.append((name, p))
    return p


def wait_up(port, path="/health", timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        try:
            http(port, path)
            return
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.2)
    raise RuntimeError("port %d did not come up" % port)


def start_bank(tmp, logdir):
    argv = [os.path.join(BUILD, "bank_server"), "--port", str(BANK_PORT),
            "--state", os.path.join(tmp, "bank_state.json"), "--key", INTERNAL_KEY]
    if not os.environ.get("E2E_FULL"):
        argv.append("--fast")
    p = start("bank", argv, logdir)
    wait_up(BANK_PORT)
    return p


def balance(user):
    s, r = wallet(user, "/api/state")
    return r.get("bank_balance")


def main():
    for b in ("bank_server", "app_server", "wallet_agent"):
        if not os.path.exists(os.path.join(BUILD, b)):
            sys.exit("missing build/%s -- run `make servers` first" % b)

    tmp = tempfile.mkdtemp(prefix="ghostcash-e2e-")
    logdir = os.path.join(tmp, "logs")
    os.makedirs(logdir)
    print("working directory:", tmp)

    try:
        bank = start_bank(tmp, logdir)
        def start_app():
            p = start("app", [os.path.join(BUILD, "app_server"), "--port", str(APP_PORT), "--bank-port", str(BANK_PORT),
                              "--key", INTERNAL_KEY, "--users", os.path.join(tmp, "users.json")], logdir)
            wait_up(APP_PORT)
            return p

        app = start_app()
        for user, port in WALLET_PORTS.items():
            start("wallet-" + user, [os.path.join(BUILD, "wallet_agent"), "--port", str(port),
                                     "--app-port", str(APP_PORT), "--data", os.path.join(tmp, "data-" + user),
                                     "--ui", UI], logdir)
            wait_up(port, "/api/state")

        print("\n[1] accounts")
        for user in WALLET_PORTS:
            name = USERNAMES.get(user, user)
            s, r = wallet(user, "/api/signup", "POST", {"username": name, "password": "pw-" + user})
            check("signup " + name, s == 200 and r.get("username") == name, r)
        check("new accounts start with 100", balance("alice") == 100)
        s, r = wallet("alice", "/api/signup", "POST", {"username": "alice", "password": "x" * 6})
        check("duplicate username rejected", s == 409, (s, r))
        s, r = wallet("bob", "/api/login", "POST", {"username": "bob", "password": "wrong"})
        check("wrong password rejected", s == 401, (s, r))

        print("\n[2] generate coins (withdrawal)")
        s, r = wallet("alice", "/api/generate", "POST", {"denomination": 5})
        check("alice generates a 5-coin", s == 200, r)
        s, r = wallet("alice", "/api/generate", "POST", {"denomination": 1})
        check("alice generates a 1-coin", s == 200, r)
        check("alice's bank balance is debited (100 - 5 - 1)", balance("alice") == 94, balance("alice"))
        s, st = wallet("alice", "/api/state")
        coins = st["coins"]
        check("alice holds two unspent coins locally", len(coins) == 2 and not any(c["spent"] for c in coins), coins)
        s, r = wallet("alice", "/api/generate", "POST", {"denomination": 7})
        check("unsupported denomination rejected", s == 400, (s, r))

        print("\n[3] transfer and redeem")
        five = [c for c in coins if c["denomination"] == 5][0]["id"]
        s, r = wallet("alice", "/api/transfer", "POST", {"to": "bob", "coin_id": five})
        check("alice pays the 5-coin to bob", s == 200 and r.get("ok") is True, r)
        check("transfer steps are reported", len(r.get("steps", [])) >= 3, r)
        s, st = wallet("bob", "/api/state")
        check("bob holds a pending 5 payment", len(st["received"]) == 1 and st["received"][0]["status"] == "pending"
              and st["received"][0]["amount"] == 5, st["received"])
        check("bob's bank balance unchanged until redeemed", st["bank_balance"] == 100, st["bank_balance"])
        s, st = wallet("alice", "/api/state")
        check("alice's coin is marked spent", [c for c in st["coins"] if c["id"] == five][0]["spent"])
        s, r = wallet("alice", "/api/transfer", "POST", {"to": "bob", "coin_id": five})
        check("honest wallet refuses to re-spend", s == 400, (s, r))

        s, r = wallet("bob", "/api/redeem", "POST", {})
        check("bob redeems: accepted", s == 200 and r["results"][0]["status"] == "accepted", r)
        check("bob's balance is credited (100 + 5)", balance("bob") == 105, balance("bob"))
        s, r = wallet("bob", "/api/redeem", "POST", {})
        check("nothing left to redeem", r["results"] == [], r)

        print("\n[4] double spend is detected and traced")
        s, r = wallet("alice", "/api/generate", "POST", {"denomination": 5})
        s, st = wallet("alice", "/api/state")
        fresh = [c for c in st["coins"] if c["denomination"] == 5 and not c["spent"]][0]["id"]
        s, r = wallet("alice", "/api/transfer", "POST", {"to": "bob", "coin_id": fresh})
        check("alice pays the coin to bob", s == 200 and r.get("ok") is True, r)
        s, r = wallet("alice", "/api/transfer", "POST", {"to": "carol", "coin_id": fresh, "force": True})
        check("alice re-spends the same coin at carol (malicious)", s == 200 and r.get("ok") is True, r)
        s, r = wallet("bob", "/api/redeem", "POST", {})
        check("first redeem (bob) accepted", r["results"][0]["status"] == "accepted", r)
        s, r = wallet("carol", "/api/redeem", "POST", {})
        check("second redeem (carol) is a double spend", r["results"][0]["status"] == "double_spend", r)
        check("carol is not credited", balance("carol") == 100, balance("carol"))
        s, adm = http(BANK_PORT, "/admin/state", headers={"X-Internal-Key": INTERNAL_KEY})
        check("bank flagged exactly alice", adm.get("flagged") == ["alice"], adm)

        print("\n[5] forged and malformed requests")
        s, r = http(APP_PORT, "/login", "POST", {"username": "alice", "password": "pw-alice"})
        token = r["token"]
        fake = {"transcript": {"coin": {"serial": "00", "A": "2", "S": "3", "signature": "4", "denomination": 5},
                               "receiver_id": "alice", "time": "t", "nonce": "n", "y": "5"}}
        s, r = http(APP_PORT, "/redeem", "POST", fake, {"X-Token": token})
        check("forged transcript is invalid", s == 200 and r.get("status") == "invalid", (s, r))
        fake["transcript"]["receiver_id"] = "bob"
        s, r = http(APP_PORT, "/redeem", "POST", fake, {"X-Token": token})
        check("redeeming someone else's receiver id is refused", s == 403, (s, r))
        s, r = http(APP_PORT, "/withdraw", "POST", {"denomination": 1, "blinded_m": "1", "tag": "1"})
        check("withdraw without a session is refused", s == 401, (s, r))
        s, r = http(BANK_PORT, "/accounts/alice/balance")
        check("bank refuses calls without the internal key", s == 403, (s, r))

        print("\n[6] unreachable receivers and insufficient balance")
        s, r = wallet("alice", "/api/transfer", "POST", {"to": "nobody", "coin_id": five, "force": True})
        check("transfer to an unknown user fails", s in (404, 409), (s, r))
        http(APP_PORT, "/signup", "POST", {"username": "dave", "password": "pw-dave"})
        s, r = wallet("alice", "/api/transfer", "POST", {"to": "dave", "coin_id": five, "force": True})
        check("transfer to an offline user fails", s == 409 and "offline" in r.get("error", ""), (s, r))

        got_error = None
        for _ in range(12):
            s, r = wallet("alice", "/api/generate", "POST", {"denomination": 10})
            if s != 200:
                got_error = (s, r)
                break
        check("withdrawing beyond the balance is rejected", got_error is not None
              and "insufficient" in got_error[1].get("error", ""), got_error)

        print("\n[7] capital letters, case-insensitive names, paying yourself")
        s, r = http(APP_PORT, "/login", "POST", {"username": "erin", "password": "pw-erin"})
        check("login resolves to the registered spelling", s == 200 and r.get("username") == "Erin", (s, r))
        s, r = http(APP_PORT, "/signup", "POST", {"username": "ERIN", "password": "other1"})
        check("a name differing only by case is taken", s == 409, (s, r))
        s, r = http(APP_PORT, "/signup", "POST", {"username": "bad name!", "password": "pw-x"})
        check("invalid characters are rejected", s == 400, (s, r))

        s, st = wallet("alice", "/api/state")
        one = [c for c in st["coins"] if c["denomination"] == 1 and not c["spent"]][0]["id"]
        s, r = wallet("alice", "/api/transfer", "POST", {"to": "erin", "coin_id": one})
        check("alice pays 'erin' (lower case) and it reaches Erin", s == 200 and r.get("ok") is True, r)
        s, r = wallet("erin", "/api/redeem", "POST", {})
        check("Erin redeems it", s == 200 and r["results"][0]["status"] == "accepted", r)
        check("Erin is credited (100 + 1)", balance("erin") == 101, balance("erin"))

        s, r = wallet("erin", "/api/generate", "POST", {"denomination": 5})
        s, st = wallet("erin", "/api/state")
        mine = [c for c in st["coins"] if c["denomination"] == 5][0]["id"]
        before = balance("erin")
        s, r = wallet("erin", "/api/transfer", "POST", {"to": "Erin", "coin_id": mine})
        check("Erin pays herself", s == 200 and r.get("ok") is True, r)
        s, r = wallet("erin", "/api/redeem", "POST", {})
        check("the self-payment redeems and the coin value returns to her balance",
              s == 200 and r["results"][0]["status"] == "accepted" and balance("erin") == before + 5,
              (r, balance("erin"), before))

        print("\n[8] state survives a bank restart")
        before = {u: balance(u) for u in WALLET_PORTS}
        bank.terminate()
        bank.wait()
        start_bank(tmp, logdir)
        after = {u: balance(u) for u in WALLET_PORTS}
        check("balances identical after restart", before == after, (before, after))
        s, adm = http(BANK_PORT, "/admin/state", headers={"X-Internal-Key": INTERNAL_KEY})
        check("flagged account survives restart", adm.get("flagged") == ["alice"], adm)

        print("\n[9] app server restart: sessions are lost, accounts and local coins are not")
        coins_before = len(wallet("alice", "/api/state")[1]["coins"])
        app.terminate()
        app.wait()
        app = start_app()
        s, st = wallet("alice", "/api/state")
        check("the wallet falls back to the sign-in form", st.get("logged_in") is False, st)
        s, r = wallet("alice", "/api/login", "POST", {"username": "ALICE", "password": "pw-alice"})
        check("accounts survive the restart (login, any capitalisation)", s == 200 and r.get("username") == "alice", (s, r))
        s, st = wallet("alice", "/api/state")
        check("local coins are still there after logging back in", len(st["coins"]) == coins_before, st.get("coins"))
        check("bank balance unchanged", balance("alice") == before["alice"], (balance("alice"), before["alice"]))

    finally:
        for name, p in procs:
            p.terminate()
        for name, p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        if failures:
            print("\nlogs kept in", logdir)
        else:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\n%s: %d check(s) failed" % ("FAILED" if failures else "OK", len(failures)))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
