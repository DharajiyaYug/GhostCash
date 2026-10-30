// wallet_agent.cpp
//
// The GhostCash wallet: a local program run by each user. It holds the coins
// and their secrets (a, s) in a local SQLite database and performs *all*
// cryptography on the user's machine -- blinding, tags, challenge responses,
// signature and proof checks. The app server and the bank only ever see
// blinded values (withdrawal), coins and challenges in transit (transfer), or
// finished transcripts (redeem).
//
// It also serves the local web UI on http://127.0.0.1:<port>/ and a small JSON
// API the UI calls:
//
//   POST /api/signup   {username, password}
//   POST /api/login    {username, password}
//   POST /api/logout
//   GET  /api/state                      balance, coins, received payments, history
//   POST /api/generate {denomination}    withdraw a coin from the bank
//   POST /api/transfer {to, coin_id, force?}   pay a coin to another user
//   POST /api/redeem   {id?}             redeem one (or all) received payments
//
// A transfer is the interactive protocol, relayed through the app server:
//   payer -> receiver: coin            receiver checks it, answers with a
//   receiver -> payer: challenge       challenge bound to itself; the payer
//   payer -> receiver: response y      answers; the receiver verifies and
//   receiver -> payer: accepted        keeps the transcript to redeem later.
//
// Usage: wallet_agent [--port 8081] [--app-host 127.0.0.1] [--app-port 8000]
//                     [--data ./wallet-data] [--ui ./ui]

#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/hash_utils.hpp"
#include "ghostcash/merchant.hpp"
#include "ghostcash/public_keys.hpp"
#include "ghostcash/rng.hpp"
#include "ghostcash/serialize.hpp"
#include "ghostcash/transcript.hpp"
#include "ghostcash/wallet.hpp"
#include "net_common.hpp"

#include <sqlite3.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using net::fail;
using net::json;
using net::reply;

namespace {

// ---- local SQLite store ---------------------------------------------------

class Db {
public:
    using Row = std::vector<std::string>;

    explicit Db(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
            std::string msg = sqlite3_errmsg(db_);
            sqlite3_close(db_);
            throw std::runtime_error("cannot open wallet database: " + msg);
        }
        query(
            "CREATE TABLE IF NOT EXISTS coins("
            " id INTEGER PRIMARY KEY AUTOINCREMENT, serial TEXT UNIQUE, denom INTEGER,"
            " coin_json TEXT, a TEXT, s TEXT, spent INTEGER DEFAULT 0, created TEXT)");
        query(
            "CREATE TABLE IF NOT EXISTS transcripts("
            " id INTEGER PRIMARY KEY AUTOINCREMENT, serial TEXT UNIQUE, from_user TEXT, amount INTEGER,"
            " transcript_json TEXT, status TEXT DEFAULT 'pending', note TEXT DEFAULT '', created TEXT)");
        query(
            "CREATE TABLE IF NOT EXISTS history("
            " id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, kind TEXT, detail TEXT)");
    }

    ~Db() { sqlite3_close(db_); }
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    // Runs one statement with text-bound parameters; returns all rows as
    // strings (NULL becomes "").
    std::vector<Row> query(const std::string& sql, const std::vector<std::string>& params = {}) {
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite: ") + sqlite3_errmsg(db_));
        }
        for (size_t i = 0; i < params.size(); ++i) {
            sqlite3_bind_text(st, static_cast<int>(i) + 1, params[i].c_str(), -1, SQLITE_TRANSIENT);
        }
        std::vector<Row> rows;
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            Row row;
            int cols = sqlite3_column_count(st);
            for (int c = 0; c < cols; ++c) {
                const unsigned char* text = sqlite3_column_text(st, c);
                row.push_back(text ? reinterpret_cast<const char*>(text) : "");
            }
            rows.push_back(std::move(row));
        }
        std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) throw std::runtime_error("sqlite: " + err);
        return rows;
    }

private:
    sqlite3* db_ = nullptr;
};

// ---- agent state ----------------------------------------------------------

struct Incoming {          // a payment where we are the receiver
    PaymentSession session;
    std::string from;
};

enum class OutState { WaitingChallenge, WaitingResult, Done };

struct Outgoing {          // a payment where we are the payer
    std::string to;
    long long coin_id = 0;
    WalletCoin wc;
    OutState state = OutState::WaitingChallenge;
    bool ok = false;
    std::string message;
    std::vector<std::string> steps;
};

struct Agent {
    std::mutex mu;
    std::condition_variable cv;

    std::string app_host = "127.0.0.1";
    int app_port = 8000;
    std::string data_dir = "./wallet-data";

    // Valid while logged in (username non-empty).
    std::string username, token;
    unsigned long generation = 0; // bumped on every login/logout; stops stale inbox threads
    GroupParams group;
    PublicKeyRing ring;
    std::unique_ptr<Wallet> wallet;
    std::unique_ptr<Merchant> merchant;
    std::unique_ptr<Db> db;
    std::map<std::string, Incoming> incoming;
    std::map<std::string, Outgoing> outgoing;
};

Agent ag;

std::string short_serial(const std::string& serial) { return serial.substr(0, 8); }

// ---- calls to the app server (caller holds ag.mu where state is touched) --

json app_call(const std::string& method, const std::string& path, const json& body, int& status,
              bool with_token = true) {
    httplib::Client cli(ag.app_host, ag.app_port);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(30);
    httplib::Headers headers;
    if (with_token) headers.emplace("X-Token", ag.token);
    httplib::Result r = (method == "POST") ? cli.Post(path.c_str(), headers, body.dump(), "application/json")
                                           : cli.Get(path.c_str(), headers);
    if (!r) throw std::runtime_error("cannot reach the app server");
    status = r->status;
    return json::parse(r->body);
}

void add_history(const std::string& kind, const std::string& detail) {
    if (ag.db) ag.db->query("INSERT INTO history(ts, kind, detail) VALUES(?,?,?)", {net::now_iso(), kind, detail});
}

// Sends one relayed transfer message. Returns "" on success, else the error.
std::string send_message(const std::string& to, const std::string& type, const std::string& transfer_id,
                         const json& payload) {
    int status = 0;
    json r = app_call("POST", "/transfer/send",
                      {{"to", to}, {"type", type}, {"transfer_id", transfer_id}, {"payload", payload}}, status);
    return status == 200 ? "" : r.value("error", "send failed");
}

void finish_outgoing(Outgoing& o, bool ok, const std::string& message) {
    o.state = OutState::Done;
    o.ok = ok;
    o.message = message;
    o.steps.push_back(message);
    ag.cv.notify_all();
}

// ---- incoming transfer messages (called with ag.mu held) ------------------

void on_coin(const std::string& from, const std::string& tid, const json& payload) {
    Coin coin = wire::coin_from_json(payload.at("coin"));

    // A careful receiver never accepts the same coin twice.
    if (!ag.db->query("SELECT 1 FROM transcripts WHERE serial=?", {coin.serial}).empty()) {
        send_message(from, "reject", tid, {{"reason", "coin already received"}});
        add_history("rejected", "refused coin " + short_serial(coin.serial) + " from " + from + ": already received");
        return;
    }

    PaymentSession session;
    if (!ag.merchant->begin_payment(coin, net::now_iso(), session)) {
        send_message(from, "reject", tid, {{"reason", "coin failed verification"}});
        add_history("rejected", "refused coin from " + from + ": failed verification");
        return;
    }
    ag.incoming[tid] = Incoming{session, from};
    send_message(from, "challenge", tid, {{"time", session.time}, {"nonce", session.nonce}});
    add_history("challenge", "coin " + short_serial(coin.serial) + " from " + from + " verified; challenge sent");
}

void on_challenge(const std::string& from, const std::string& tid, const json& payload) {
    auto it = ag.outgoing.find(tid);
    if (it == ag.outgoing.end() || it->second.to != from || it->second.state != OutState::WaitingChallenge) return;
    Outgoing& o = it->second;

    o.steps.push_back(from + " verified the coin and sent a challenge");
    WalletCoin wc = o.wc; // a copy, so a forced re-spend of a spent coin still answers
    BigInt y;
    // pay() re-derives the challenge for the receiver we mean to pay.
    if (!ag.wallet->pay(wc, o.to, payload.at("time").get<std::string>(), payload.at("nonce").get<std::string>(), y)) {
        finish_outgoing(o, false, "wallet refused to answer: coin already spent");
        return;
    }
    std::string err = send_message(from, "response", tid, {{"y", wire::hex(y)}});
    if (!err.empty()) {
        finish_outgoing(o, false, "could not send response: " + err);
        return;
    }
    ag.db->query("UPDATE coins SET spent=1 WHERE id=?", {std::to_string(o.coin_id)});
    o.state = OutState::WaitingResult;
    o.steps.push_back("answered the challenge (y = s + a*x)");
}

void on_response(const std::string& from, const std::string& tid, const json& payload) {
    auto it = ag.incoming.find(tid);
    if (it == ag.incoming.end() || it->second.from != from) return;
    Incoming in = it->second;
    ag.incoming.erase(it);

    Transcript t;
    BigInt y = wire::from_hex(payload.at("y"));
    if (!ag.merchant->finish_payment(in.session, y, t)) {
        send_message(from, "reject", tid, {{"reason", "response did not verify"}});
        add_history("rejected", "response from " + from + " did not verify");
        return;
    }
    try {
        ag.db->query("INSERT INTO transcripts(serial, from_user, amount, transcript_json, created) VALUES(?,?,?,?,?)",
                     {t.coin.serial, from, std::to_string(t.coin.denomination),
                      wire::transcript_to_json(t).dump(), net::now_iso()});
    } catch (const std::exception&) {
        send_message(from, "reject", tid, {{"reason", "coin already received"}});
        return;
    }
    send_message(from, "accepted", tid, json::object());
    add_history("received", "accepted " + std::to_string(t.coin.denomination) + " from " + from +
                            " (coin " + short_serial(t.coin.serial) + "); redeem it to credit your account");
}

void on_result(const std::string& from, const std::string& tid, const json& payload, bool accepted) {
    auto it = ag.outgoing.find(tid);
    if (it == ag.outgoing.end() || it->second.to != from) return;
    Outgoing& o = it->second;
    if (accepted) {
        finish_outgoing(o, true, from + " verified the proof and accepted the payment");
        add_history("sent", "paid coin to " + from);
    } else {
        std::string reason = payload.value("reason", "rejected");
        finish_outgoing(o, false, from + " rejected the payment: " + reason);
        add_history("failed", "payment to " + from + " rejected: " + reason);
    }
}

void handle_message(const json& m) {
    std::string type = m.at("type").get<std::string>();
    std::string from = m.at("from").get<std::string>();
    std::string tid = m.at("transfer_id").get<std::string>();
    const json& payload = m.at("payload");
    if (type == "coin") on_coin(from, tid, payload);
    else if (type == "challenge") on_challenge(from, tid, payload);
    else if (type == "response") on_response(from, tid, payload);
    else if (type == "accepted") on_result(from, tid, payload, true);
    else if (type == "reject") on_result(from, tid, payload, false);
}

// Long-polls the app server's mailbox for as long as this login is current.
void inbox_loop(unsigned long generation, std::string token) {
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(ag.mu);
            if (generation != ag.generation) return;
        }
        httplib::Client cli(ag.app_host, ag.app_port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(45);
        httplib::Result r = cli.Get("/transfer/inbox?wait=20", httplib::Headers{{"X-Token", token}});
        if (!r) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        if (r->status == 401) return; // session no longer valid
        if (r->status != 200) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        json messages;
        try {
            messages = json::parse(r->body).at("messages");
        } catch (const std::exception&) {
            continue;
        }
        for (const auto& m : messages) {
            std::lock_guard<std::mutex> lock(ag.mu);
            if (generation != ag.generation) return;
            try {
                handle_message(m);
            } catch (const std::exception& e) {
                add_history("error", std::string("bad message: ") + e.what());
            }
        }
    }
}

// ---- login ------------------------------------------------------------------

// Caller holds ag.mu.
void start_session(const std::string& username, const std::string& token) {
    int status = 0;
    json params = app_call("GET", "/params", json(), status, /*with_token=*/false);
    if (status != 200) throw std::runtime_error("could not fetch bank parameters");

    ag.group = wire::group_from_json(params.at("group"));
    ag.ring = PublicKeyRing();
    wire::ring_from_json(ag.ring, params.at("denominations"));

    std::filesystem::create_directories(ag.data_dir);
    ag.db.reset();
    ag.db = std::make_unique<Db>(ag.data_dir + "/" + username + ".db");
    ag.wallet = std::make_unique<Wallet>(ag.group.p, ag.group.q, ag.group.g, Rng::instance());
    ag.merchant = std::make_unique<Merchant>(username, ag.group, ag.ring, Rng::instance());
    ag.incoming.clear();
    ag.outgoing.clear();

    ag.username = username;
    ag.token = token;
    unsigned long generation = ++ag.generation;
    std::thread(inbox_loop, generation, token).detach();
    add_history("login", "signed in as " + username);
}

json coin_row_json(const Db::Row& r) {
    return {{"id", std::stoll(r[0])}, {"denomination", std::stoi(r[1])}, {"serial", r[2]},
            {"spent", r[3] == "1"}, {"created", r[4]}};
}

} // namespace

int main(int argc, char** argv) {
    net::Args args(argc, argv);
    const int port = args.get_int("port", 8081);
    ag.app_host = args.get("app-host", "127.0.0.1");
    ag.app_port = args.get_int("app-port", 8000);
    ag.data_dir = args.get("data", "./wallet-data");
    const std::string ui_dir = args.get("ui", "./ui");

    httplib::Server svr;

    // Wraps an API handler: parse errors and bad input become 400, an
    // unreachable app server 502. `needs_login` handlers get the lock held.
    auto api = [&](bool needs_login, std::function<void(const httplib::Request&, httplib::Response&,
                                                       std::unique_lock<std::mutex>&)> fn) {
        return [&, needs_login, fn](const httplib::Request& req, httplib::Response& res) {
            std::unique_lock<std::mutex> lock(ag.mu);
            if (needs_login && ag.username.empty()) {
                fail(res, 401, "not logged in");
                return;
            }
            try {
                fn(req, res, lock);
            } catch (const std::runtime_error& e) {
                fail(res, 502, e.what());
            } catch (const std::exception& e) {
                fail(res, 400, e.what());
            }
        };
    };

    auto auth = [&](bool signup) {
        return api(false, [signup](const httplib::Request& req, httplib::Response& res, std::unique_lock<std::mutex>&) {
            json body = json::parse(req.body);
            int status = 0;
            json r = app_call("POST", signup ? "/signup" : "/login",
                              {{"username", body.at("username")}, {"password", body.at("password")}},
                              status, /*with_token=*/false);
            if (status != 200) {
                fail(res, status, r.value("error", "authentication failed"));
                return;
            }
            start_session(r.at("username").get<std::string>(), r.at("token").get<std::string>());
            reply(res, 200, json{{"ok", true}, {"username", ag.username}});
        });
    };
    svr.Post("/api/signup", auth(true));
    svr.Post("/api/login", auth(false));

    svr.Post("/api/logout", api(false, [](const httplib::Request&, httplib::Response& res, std::unique_lock<std::mutex>&) {
        ++ag.generation;
        ag.username.clear();
        ag.token.clear();
        ag.db.reset();
        ag.wallet.reset();
        ag.merchant.reset();
        reply(res, 200, json{{"ok", true}});
    }));

    svr.Get("/api/state", api(false, [](const httplib::Request&, httplib::Response& res, std::unique_lock<std::mutex>&) {
        if (ag.username.empty()) {
            reply(res, 200, json{{"logged_in", false}});
            return;
        }
        json balance = nullptr;
        try {
            int status = 0;
            json r = app_call("GET", "/balance", json(), status);
            if (status == 200) balance = r.at("balance");
        } catch (const std::exception&) {
        }

        json coins = json::array();
        for (const auto& r : ag.db->query("SELECT id, denom, serial, spent, created FROM coins ORDER BY id")) {
            coins.push_back(coin_row_json(r));
        }
        json received = json::array();
        for (const auto& r : ag.db->query(
                 "SELECT id, from_user, amount, status, note, created FROM transcripts ORDER BY id DESC LIMIT 50")) {
            received.push_back({{"id", std::stoll(r[0])}, {"from", r[1]}, {"amount", std::stoi(r[2])},
                                {"status", r[3]}, {"note", r[4]}, {"created", r[5]}});
        }
        json history = json::array();
        for (const auto& r : ag.db->query("SELECT ts, kind, detail FROM history ORDER BY id DESC LIMIT 40")) {
            history.push_back({{"ts", r[0]}, {"kind", r[1]}, {"detail", r[2]}});
        }
        json denoms = json::array();
        for (int d : ag.ring.denominations()) denoms.push_back(d);

        reply(res, 200, json{{"logged_in", true}, {"username", ag.username}, {"bank_balance", balance},
                             {"denominations", denoms}, {"coins", coins}, {"received", received},
                             {"history", history}});
    }));

    svr.Post("/api/generate", api(true, [](const httplib::Request& req, httplib::Response& res, std::unique_lock<std::mutex>&) {
        int denom = json::parse(req.body).at("denomination").get<int>();
        if (!ag.ring.has_denomination(denom)) {
            fail(res, 400, "unsupported denomination");
            return;
        }

        PendingWithdrawal pending;
        BigInt blinded = ag.wallet->prepare_withdrawal(denom, ag.ring, pending);

        int status = 0;
        json r = app_call("POST", "/withdraw",
                          {{"denomination", denom}, {"blinded_m", wire::hex(blinded)}, {"tag", wire::hex(pending.tag)}},
                          status);
        if (status != 200) {
            fail(res, status, r.value("error", "withdrawal failed"));
            return;
        }

        WalletCoin wc = ag.wallet->finish_withdrawal(ag.ring, pending, wire::from_hex(r.at("blind_signature")));
        BigInt m = HashUtils::coin_message(wc.coin.serial, wc.coin.A, wc.coin.S, ag.ring.public_modulus(denom));
        if (!ag.ring.verify(denom, m, wc.coin.signature)) {
            fail(res, 502, "the bank returned a signature that does not verify");
            return;
        }

        ag.db->query("INSERT INTO coins(serial, denom, coin_json, a, s, created) VALUES(?,?,?,?,?,?)",
                     {wc.coin.serial, std::to_string(denom), wire::coin_to_json(wc.coin).dump(),
                      wc.a.to_string(16), wc.s.to_string(16), net::now_iso()});
        add_history("generated", "withdrew a " + std::to_string(denom) + "-coin " + short_serial(wc.coin.serial));
        reply(res, 200, json{{"ok", true}, {"serial", wc.coin.serial}, {"denomination", denom}});
    }));

    svr.Post("/api/transfer", api(true, [](const httplib::Request& req, httplib::Response& res, std::unique_lock<std::mutex>& lock) {
        json body = json::parse(req.body);
        std::string to = body.at("to").get<std::string>();
        std::string coin_id = std::to_string(body.at("coin_id").get<long long>());
        bool force = body.value("force", false);

        if (to == ag.username) {
            fail(res, 400, "you cannot pay yourself");
            return;
        }
        auto rows = ag.db->query("SELECT id, coin_json, a, s, spent FROM coins WHERE id=?", {coin_id});
        if (rows.empty()) {
            fail(res, 404, "no such coin");
            return;
        }
        bool already_spent = rows[0][4] == "1";
        if (already_spent && !force) {
            fail(res, 400, "that coin is already spent");
            return;
        }
        for (const auto& kv : ag.outgoing) {
            if (kv.second.coin_id == std::stoll(coin_id) && kv.second.state != OutState::Done) {
                fail(res, 400, "that coin is already in a transfer");
                return;
            }
        }

        std::string tid = net::random_hex(8);
        Outgoing o;
        o.to = to;
        o.coin_id = std::stoll(coin_id);
        o.wc.coin = wire::coin_from_json(json::parse(rows[0][1]));
        o.wc.a = BigInt(rows[0][2], 16);
        o.wc.s = BigInt(rows[0][3], 16);
        o.wc.spent = false; // a forced re-spend deliberately ignores the wallet's own bookkeeping
        o.steps.push_back(std::string(already_spent ? "MALICIOUS: re-spending an already spent coin; " : "") +
                          "sent the coin to " + to);
        ag.outgoing[tid] = o;

        std::string err = send_message(to, "coin", tid, {{"coin", wire::coin_to_json(o.wc.coin)}});
        if (!err.empty()) {
            ag.outgoing.erase(tid);
            fail(res, 409, err);
            return;
        }

        ag.cv.wait_for(lock, std::chrono::seconds(30), [&] { return ag.outgoing[tid].state == OutState::Done; });
        Outgoing result = ag.outgoing[tid];
        ag.outgoing.erase(tid);
        if (result.state != OutState::Done) {
            result.message = "timed out waiting for " + to;
            result.steps.push_back(result.message);
        }
        reply(res, 200, json{{"ok", result.ok}, {"message", result.message}, {"steps", result.steps}});
    }));

    svr.Post("/api/redeem", api(true, [](const httplib::Request& req, httplib::Response& res, std::unique_lock<std::mutex>&) {
        json body = req.body.empty() ? json::object() : json::parse(req.body);
        std::vector<Db::Row> rows;
        if (body.contains("id")) {
            rows = ag.db->query("SELECT id, transcript_json, amount FROM transcripts WHERE status='pending' AND id=?",
                                {std::to_string(body.at("id").get<long long>())});
        } else {
            rows = ag.db->query("SELECT id, transcript_json, amount FROM transcripts WHERE status='pending' ORDER BY id");
        }

        json results = json::array();
        for (const auto& row : rows) {
            int status = 0;
            json r = app_call("POST", "/redeem", {{"transcript", json::parse(row[1])}}, status);
            std::string outcome = r.value("status", "error");
            std::string detail = r.value("detail", r.value("error", ""));

            std::string new_status;
            if (outcome == "accepted" || outcome == "duplicate") new_status = "redeemed";
            else if (outcome == "double_spend") new_status = "rejected";
            else if (outcome == "invalid") new_status = "rejected";
            else new_status = "pending"; // transport/other error: keep it to retry

            if (outcome == "double_spend") detail = "double spend detected: the bank rejected this payment";
            if (new_status != "pending") {
                ag.db->query("UPDATE transcripts SET status=?, note=? WHERE id=?", {new_status, detail, row[0]});
            }
            add_history("redeem", "redeem of " + row[2] + ": " + outcome + (detail.empty() ? "" : " (" + detail + ")"));
            results.push_back({{"id", std::stoll(row[0])}, {"amount", std::stoi(row[2])},
                               {"status", outcome}, {"detail", detail}});
        }
        reply(res, 200, json{{"results", results}});
    }));

    if (!svr.set_mount_point("/", ui_dir)) {
        std::cerr << "[wallet] warning: UI directory '" << ui_dir << "' not found\n";
    }

    std::cout << "[wallet] open http://127.0.0.1:" << port << "/  (app " << ag.app_host << ":" << ag.app_port
              << ", data " << ag.data_dir << ")\n" << std::flush;
    if (!svr.listen("127.0.0.1", port)) {
        std::cerr << "[wallet] could not listen on port " << port << "\n";
        return 1;
    }
    return 0;
}
