// bank_server.cpp
//
// The bank as a standalone HTTP server. It owns the RSA keys, the account
// ledger, the withdrawal tag log and the spent-coin database, and does the
// blind signing and the double-spend tracing. State is snapshotted to a JSON
// file after every change, so a restart picks up where it left off.
//
// It is meant to be reached only by the app server: every endpoint except
// /health and /params requires the shared X-Internal-Key header.
//
//   GET  /health
//   GET  /params                       group + public key per denomination
//   POST /accounts                     {name, balance}
//   GET  /accounts/<name>/balance
//   POST /withdraw                     {account, denomination, blinded_m, tag}
//   POST /deposit                      {transcript}
//   GET  /admin/state
//
// Usage: bank_server [--port 9000] [--state bank_state.json]
//                    [--key dev-internal-key] [--fast]
// --fast uses small group/RSA sizes (demos and tests); the default is the
// specified size (256-bit q, 3072-bit p, 2048-bit RSA).

#include "ghostcash/bank.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/rng.hpp"
#include "ghostcash/serialize.hpp"
#include "net_common.hpp"

#include <functional>
#include <iostream>
#include <mutex>

using net::fail;
using net::json;
using net::reply;

namespace {

const char* status_name(DepositStatus s) {
    switch (s) {
        case DepositStatus::Accepted:    return "accepted";
        case DepositStatus::Duplicate:   return "duplicate";
        case DepositStatus::DoubleSpend: return "double_spend";
        case DepositStatus::Invalid:     return "invalid";
    }
    return "invalid";
}

} // namespace

int main(int argc, char** argv) {
    net::Args args(argc, argv);
    const int port = args.get_int("port", 9000);
    const std::string state_path = args.get("state", "bank_state.json");
    const std::string internal_key = args.get("key", "dev-internal-key");
    const bool fast = args.has("fast");

    gmp_randstate_t& rng = Rng::instance();
    Bank bank;
    std::mutex mu;

    auto save = [&]() { net::write_file_atomic(state_path, BankPersistence::save(bank).dump()); };

    std::string raw;
    if (net::read_file(state_path, raw)) {
        BankPersistence::load(bank, json::parse(raw));
        std::cout << "[bank] loaded state from " << state_path << "\n";
    } else {
        const int q_bits = fast ? 128 : 256;
        const int p_bits = fast ? 512 : 3072;
        const int rsa_bits = fast ? 1024 : 2048;
        std::cout << "[bank] first start: generating group (q=" << q_bits << ", p=" << p_bits
                  << ") and RSA keys (" << rsa_bits << " bit)... " << std::flush;
        bank.set_group(GroupSetup::generate(q_bits, p_bits, rng));
        for (int d : {1, 5, 10}) bank.add_denomination(d, rsa_bits, rng);
        save();
        std::cout << "done\n";
    }

    httplib::Server svr;

    // Wraps a handler: optional internal-key check, bank lock, and a catch-all
    // that turns any exception (bad JSON, unknown account, ...) into a 400.
    auto handler = [&](bool internal, std::function<void(const httplib::Request&, httplib::Response&)> fn) {
        return [&, internal, fn](const httplib::Request& req, httplib::Response& res) {
            if (internal && req.get_header_value("X-Internal-Key") != internal_key) {
                fail(res, 403, "forbidden");
                return;
            }
            std::lock_guard<std::mutex> lock(mu);
            try {
                fn(req, res);
            } catch (const std::exception& e) {
                fail(res, 400, e.what());
            }
        };
    };

    svr.Get("/health", handler(false, [&](const httplib::Request&, httplib::Response& res) {
        reply(res, 200, json{{"ok", true}});
    }));

    svr.Get("/params", handler(false, [&](const httplib::Request&, httplib::Response& res) {
        reply(res, 200, wire::params_to_json(bank.group(), bank));
    }));

    svr.Post("/accounts", handler(true, [&](const httplib::Request& req, httplib::Response& res) {
        json body = json::parse(req.body);
        std::string name = body.at("name").get<std::string>();
        int balance = body.at("balance").get<int>();
        if (balance < 0) throw std::invalid_argument("negative balance");
        if (bank.has_account(name)) {
            fail(res, 409, "account exists");
            return;
        }
        bank.set_balance(name, balance);
        save();
        std::cout << "[bank] opened account " << name << " with " << balance << "\n";
        reply(res, 200, json{{"ok", true}});
    }));

    svr.Get(R"(/accounts/([A-Za-z0-9_]+)/balance)", handler(true, [&](const httplib::Request& req, httplib::Response& res) {
        reply(res, 200, json{{"balance", bank.balance(req.matches[1])}});
    }));

    svr.Post("/withdraw", handler(true, [&](const httplib::Request& req, httplib::Response& res) {
        json body = json::parse(req.body);
        std::string account = body.at("account").get<std::string>();
        int denomination = body.at("denomination").get<int>();
        BigInt blinded = wire::from_hex(body.at("blinded_m"));
        BigInt tag = wire::from_hex(body.at("tag"));

        BigInt sig = bank.withdraw(account, denomination, blinded, tag);
        save();
        std::cout << "[bank] " << account << " withdrew a " << denomination
                  << " (balance " << bank.balance(account) << ")\n";
        reply(res, 200, json{{"blind_signature", wire::hex(sig)}});
    }));

    svr.Post("/deposit", handler(true, [&](const httplib::Request& req, httplib::Response& res) {
        Transcript t = wire::transcript_from_json(json::parse(req.body).at("transcript"));
        DepositResult r = bank.deposit(t);
        if (r.status != DepositStatus::Invalid) save();

        std::cout << "[bank] deposit for " << t.receiver_id << ": " << status_name(r.status);
        if (!r.flagged_account.empty()) std::cout << " -> flagged " << r.flagged_account;
        if (!r.detail.empty()) std::cout << " (" << r.detail << ")";
        std::cout << "\n";

        reply(res, 200, json{{"status", status_name(r.status)},
                             {"detail", r.detail},
                             {"flagged_account", r.flagged_account},
                             {"amount", t.coin.denomination}});
    }));

    svr.Get("/admin/state", handler(true, [&](const httplib::Request&, httplib::Response& res) {
        json flagged = json::array();
        for (const auto& f : bank.flagged_accounts()) flagged.push_back(f);
        json state = BankPersistence::save(bank);
        reply(res, 200, json{{"balances", state.at("balances")},
                             {"flagged", flagged},
                             {"spent_count", bank.spent_count()}});
    }));

    std::cout << "[bank] listening on 127.0.0.1:" << port << "\n" << std::flush;
    if (!svr.listen("127.0.0.1", port)) {
        std::cerr << "[bank] could not listen on port " << port << "\n";
        return 1;
    }
    return 0;
}
