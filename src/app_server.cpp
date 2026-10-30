// app_server.cpp
//
// The GhostCash app server. It does three jobs and deliberately nothing else:
//
//   1. Accounts: signup/login. A user is a username + salted password hash;
//      the app maps that user to the bank account of the same name.
//   2. Gateway to the bank for the two operations that need an identity,
//      withdraw (debit) and redeem (credit). The account is taken from the
//      authenticated session, never from the request body.
//   3. Routing of transfer messages between logged-in users (a mailbox per
//      user, drained by long polling).
//
// It never sees coin secrets: wallets do all cryptography locally. During a
// transfer it does see the coin and who sent it to whom -- the honest-operator
// assumption in DESIGN.md. It stores no coin data: messages live in memory
// until delivered.
//
//   POST /signup {username, password}            -> {token, username}
//   POST /login  {username, password}            -> {token, username}
//   GET  /params                                 bank group + public keys
//   GET  /balance                       (token)  bank balance
//   POST /withdraw {denomination, blinded_m, tag} (token)
//   POST /redeem   {transcript}                  (token)
//   GET  /users/<name>                  (token)  {exists, online, username}
//
// Usernames may contain capital letters but are unique ignoring case, and
// login/lookup resolve any spelling to the registered one.
//   POST /transfer/send {to, type, transfer_id, payload} (token)
//   GET  /transfer/inbox?wait=<seconds> (token)  long poll
//
// Usage: app_server [--port 8000] [--bank-host 127.0.0.1] [--bank-port 9000]
//                   [--key dev-internal-key] [--users users.json]
//                   [--start-balance 100]

#include "net_common.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <condition_variable>
#include <deque>
#include <functional>
#include <iostream>
#include <mutex>
#include <regex>

using net::fail;
using net::json;
using net::reply;
using Clock = std::chrono::steady_clock;

namespace {

struct User {
    std::string salt_hex;
    std::string hash_hex;
};

std::string bytes_to_hex(const unsigned char* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 15]);
    }
    return out;
}

std::string hex_to_bytes(const std::string& hex) {
    std::string out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::string hash_password(const std::string& password, const std::string& salt_hex) {
    std::string salt = hex_to_bytes(salt_hex);
    unsigned char out[32];
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                      reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size()),
                      20000, EVP_sha256(), sizeof out, out);
    return bytes_to_hex(out, sizeof out);
}

bool same_hash(const std::string& a, const std::string& b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

const std::set<std::string> kMessageTypes = {"coin", "challenge", "response", "accepted", "reject"};
constexpr int kOnlineWindowSeconds = 30;
constexpr size_t kMaxQueued = 100;

} // namespace

int main(int argc, char** argv) {
    net::Args args(argc, argv);
    const int port = args.get_int("port", 8000);
    const std::string bank_host = args.get("bank-host", "127.0.0.1");
    const int bank_port = args.get_int("bank-port", 9000);
    const std::string internal_key = args.get("key", "dev-internal-key");
    const std::string users_path = args.get("users", "users.json");
    const int start_balance = args.get_int("start-balance", 100);

    std::mutex mu;
    std::condition_variable cv;
    std::map<std::string, User> users;
    std::map<std::string, std::string> sessions;               // token -> username
    std::map<std::string, std::deque<json>> inbox;             // username -> undelivered messages
    std::map<std::string, Clock::time_point> last_seen;        // username -> last inbox poll

    {
        std::string raw;
        if (net::read_file(users_path, raw)) {
            // Keep the parsed document alive for the whole loop: iterating
            // json::parse(raw).items() directly would dangle.
            json saved = json::parse(raw);
            for (auto& [name, u] : saved.items()) {
                users[name] = User{u.at("salt").get<std::string>(), u.at("hash").get<std::string>()};
            }
            std::cout << "[app] loaded " << users.size() << " users\n";
        }
    }

    // The registered spelling of `name` (case-insensitive match), or "".
    // Caller holds `mu`.
    auto find_ci = [&](const std::string& name) -> std::string {
        auto lower = [](std::string s) {
            for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return s;
        };
        const std::string want = lower(name);
        for (const auto& kv : users) {
            if (lower(kv.first) == want) return kv.first;
        }
        return "";
    };

    // Caller holds `mu`.
    auto save_users = [&]() {
        json j = json::object();
        for (const auto& [name, u] : users) j[name] = {{"salt", u.salt_hex}, {"hash", u.hash_hex}};
        net::write_file_atomic(users_path, j.dump());
    };

    // --- calls to the bank ------------------------------------------------
    auto bank_call = [&](const std::string& method, const std::string& path, const json& body,
                         int& status) -> json {
        httplib::Client cli(bank_host, bank_port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(60);
        httplib::Headers headers = {{"X-Internal-Key", internal_key}};
        httplib::Result r = (method == "POST") ? cli.Post(path.c_str(), headers, body.dump(), "application/json")
                                               : cli.Get(path.c_str(), headers);
        if (!r) throw std::runtime_error("bank unreachable");
        status = r->status;
        return json::parse(r->body);
    };

    // Returns the username for the request's X-Token, or "" if not logged in.
    auto session_user = [&](const httplib::Request& req) -> std::string {
        std::lock_guard<std::mutex> lock(mu);
        auto it = sessions.find(req.get_header_value("X-Token"));
        return it == sessions.end() ? "" : it->second;
    };

    // Wraps a handler: optional login requirement, and a catch-all that turns
    // any exception into a 400 (502 if the bank can't be reached).
    auto handler = [&](bool needs_login,
                       std::function<void(const httplib::Request&, httplib::Response&, const std::string&)> fn) {
        return [&, needs_login, fn](const httplib::Request& req, httplib::Response& res) {
            std::string user;
            if (needs_login) {
                user = session_user(req);
                if (user.empty()) {
                    fail(res, 401, "not logged in");
                    return;
                }
            }
            try {
                fn(req, res, user);
            } catch (const std::runtime_error& e) {
                fail(res, 502, e.what());
            } catch (const std::exception& e) {
                fail(res, 400, e.what());
            }
        };
    };

    auto new_session = [&](const std::string& username) {
        std::string token = net::random_hex(16);
        std::lock_guard<std::mutex> lock(mu);
        sessions[token] = username;
        return token;
    };

    httplib::Server svr;

    svr.Get("/health", handler(false, [&](const httplib::Request&, httplib::Response& res, const std::string&) {
        reply(res, 200, json{{"ok", true}});
    }));

    svr.Post("/signup", handler(false, [&](const httplib::Request& req, httplib::Response& res, const std::string&) {
        json body = json::parse(req.body);
        std::string username = body.at("username").get<std::string>();
        std::string password = body.at("password").get<std::string>();
        if (!std::regex_match(username, std::regex("[A-Za-z0-9_]{3,20}"))) {
            fail(res, 400, "username must be 3-20 characters: letters, digits or _");
            return;
        }
        if (password.size() < 4) {
            fail(res, 400, "password must be at least 4 characters");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(mu);
            if (!find_ci(username).empty()) {
                fail(res, 409, "username taken");
                return;
            }
            std::string salt = net::random_hex(16);
            users[username] = User{salt, hash_password(password, salt)};
        }

        // Open the bank account; undo the reservation if that fails.
        int status = 0;
        json r;
        try {
            r = bank_call("POST", "/accounts", {{"name", username}, {"balance", start_balance}}, status);
        } catch (...) {
            std::lock_guard<std::mutex> lock(mu);
            users.erase(username);
            throw;
        }
        if (status != 200) {
            std::lock_guard<std::mutex> lock(mu);
            users.erase(username);
            fail(res, status, r.value("error", "could not open bank account"));
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mu);
            save_users();
        }
        std::cout << "[app] signup: " << username << "\n";
        reply(res, 200, json{{"token", new_session(username)}, {"username", username}});
    }));

    svr.Post("/login", handler(false, [&](const httplib::Request& req, httplib::Response& res, const std::string&) {
        json body = json::parse(req.body);
        std::string username = body.at("username").get<std::string>();
        std::string password = body.at("password").get<std::string>();

        User u;
        std::string canonical;
        {
            std::lock_guard<std::mutex> lock(mu);
            canonical = find_ci(username);
            if (canonical.empty()) {
                fail(res, 401, "wrong username or password");
                return;
            }
            u = users[canonical];
        }
        if (!same_hash(hash_password(password, u.salt_hex), u.hash_hex)) {
            fail(res, 401, "wrong username or password");
            return;
        }
        std::cout << "[app] login: " << canonical << "\n";
        reply(res, 200, json{{"token", new_session(canonical)}, {"username", canonical}});
    }));

    svr.Get("/params", handler(false, [&](const httplib::Request&, httplib::Response& res, const std::string&) {
        int status = 0;
        json r = bank_call("GET", "/params", json(), status);
        reply(res, status, r);
    }));

    svr.Get("/balance", handler(true, [&](const httplib::Request&, httplib::Response& res, const std::string& user) {
        int status = 0;
        json r = bank_call("GET", "/accounts/" + user + "/balance", json(), status);
        reply(res, status, r);
    }));

    svr.Post("/withdraw", handler(true, [&](const httplib::Request& req, httplib::Response& res, const std::string& user) {
        json body = json::parse(req.body);
        int status = 0;
        json r = bank_call("POST", "/withdraw",
                           {{"account", user},
                            {"denomination", body.at("denomination")},
                            {"blinded_m", body.at("blinded_m")},
                            {"tag", body.at("tag")}},
                           status);
        reply(res, status, r);
    }));

    svr.Post("/redeem", handler(true, [&](const httplib::Request& req, httplib::Response& res, const std::string& user) {
        json body = json::parse(req.body);
        const json& transcript = body.at("transcript");
        if (transcript.at("receiver_id").get<std::string>() != user) {
            fail(res, 403, "transcript names a different receiver");
            return;
        }
        int status = 0;
        json r = bank_call("POST", "/deposit", {{"transcript", transcript}}, status);
        reply(res, status, r);
    }));

    svr.Get(R"(/users/([A-Za-z0-9_]+))", handler(true, [&](const httplib::Request& req, httplib::Response& res, const std::string&) {
        std::lock_guard<std::mutex> lock(mu);
        std::string name = find_ci(req.matches[1]);
        bool online = false;
        auto it = last_seen.find(name);
        if (it != last_seen.end()) {
            online = Clock::now() - it->second < std::chrono::seconds(kOnlineWindowSeconds);
        }
        reply(res, 200, json{{"exists", !name.empty()}, {"online", online}, {"username", name}});
    }));

    svr.Post("/transfer/send", handler(true, [&](const httplib::Request& req, httplib::Response& res, const std::string& user) {
        json body = json::parse(req.body);
        std::string to = body.at("to").get<std::string>();
        std::string type = body.at("type").get<std::string>();
        std::string transfer_id = body.at("transfer_id").get<std::string>();
        if (!kMessageTypes.count(type)) {
            fail(res, 400, "unknown message type");
            return;
        }

        std::lock_guard<std::mutex> lock(mu);
        const std::string target = find_ci(to);
        if (target.empty()) {
            fail(res, 404, "unknown user: " + to);
            return;
        }
        auto seen = last_seen.find(target);
        if (seen == last_seen.end() || Clock::now() - seen->second >= std::chrono::seconds(kOnlineWindowSeconds)) {
            fail(res, 409, target + " is offline");
            return;
        }
        auto& queue = inbox[target];
        if (queue.size() >= kMaxQueued) {
            fail(res, 429, "receiver inbox full");
            return;
        }
        queue.push_back({{"from", user}, {"type", type}, {"transfer_id", transfer_id},
                         {"payload", body.value("payload", json::object())}});
        cv.notify_all();
        reply(res, 200, json{{"ok", true}});
    }));

    svr.Get("/transfer/inbox", handler(true, [&](const httplib::Request& req, httplib::Response& res, const std::string& user) {
        int wait = 20;
        if (req.has_param("wait")) wait = std::max(0, std::min(30, std::atoi(req.get_param_value("wait").c_str())));

        std::unique_lock<std::mutex> lock(mu);
        last_seen[user] = Clock::now();
        cv.wait_for(lock, std::chrono::seconds(wait), [&] { return !inbox[user].empty(); });
        last_seen[user] = Clock::now();

        json messages = json::array();
        auto& queue = inbox[user];
        while (!queue.empty()) {
            messages.push_back(std::move(queue.front()));
            queue.pop_front();
        }
        reply(res, 200, json{{"messages", messages}});
    }));

    std::cout << "[app] listening on 127.0.0.1:" << port << " (bank " << bank_host << ":" << bank_port << ")\n"
              << std::flush;
    if (!svr.listen("127.0.0.1", port)) {
        std::cerr << "[app] could not listen on port " << port << "\n";
        return 1;
    }
    return 0;
}
