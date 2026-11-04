#pragma once

#include "ghostcash/bank.hpp"
#include "ghostcash/bigint.hpp"
#include "ghostcash/coin.hpp"
#include "ghostcash/cut_choose.hpp"
#include "ghostcash/group_setup.hpp"
#include "ghostcash/public_keys.hpp"
#include "ghostcash/transcript.hpp"
#include <nlohmann/json.hpp>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace wire {
using json = nlohmann::json;

inline json hex(const BigInt& x) { return x.to_string(16); }
inline BigInt from_hex(const json& j) { return BigInt(j.get<std::string>(), 16); }

inline json coin_to_json(const Coin& c) {
    return {{"serial", c.serial}, {"A", hex(c.A)}, {"S", hex(c.S)},
            {"signature", hex(c.signature)}, {"denomination", c.denomination}};
}

inline Coin coin_from_json(const json& j) {
    Coin c;
    c.serial = j.at("serial").get<std::string>();
    c.A = from_hex(j.at("A"));
    c.S = from_hex(j.at("S"));
    c.signature = from_hex(j.at("signature"));
    c.denomination = j.at("denomination").get<int>();
    return c;
}

inline json transcript_to_json(const Transcript& t) {
    return {{"coin", coin_to_json(t.coin)}, {"receiver_id", t.receiver_id},
            {"time", t.time}, {"nonce", t.nonce}, {"y", hex(t.y)}};
}

inline Transcript transcript_from_json(const json& j) {
    Transcript t;
    t.coin = coin_from_json(j.at("coin"));
    t.receiver_id = j.at("receiver_id").get<std::string>();
    t.time = j.at("time").get<std::string>();
    t.nonce = j.at("nonce").get<std::string>();
    t.y = from_hex(j.at("y"));
    return t;
}

inline json group_to_json(const GroupParams& g) {
    return {{"p", hex(g.p)}, {"q", hex(g.q)}, {"g", hex(g.g)}};
}

inline GroupParams group_from_json(const json& j) {
    return GroupParams{from_hex(j.at("p")), from_hex(j.at("q")), from_hex(j.at("g"))};
}

inline json params_to_json(const GroupParams& group, const Bank& bank) {
    json denoms = json::array();
    for (int d : bank.denominations()) {
        denoms.push_back({{"denomination", d},
                          {"n", hex(bank.public_modulus(d))},
                          {"e", hex(bank.public_exponent(d))}});
    }
    return {{"group", group_to_json(group)}, {"denominations", denoms},
            {"withdraw_candidates", bank.withdraw_candidates()}};
}

inline json candidates_to_json(const std::vector<WithdrawCandidate>& cs) {
    json arr = json::array();
    for (const auto& c : cs) arr.push_back({{"blinded_m", hex(c.blinded_m)}, {"tag", hex(c.tag)}});
    return arr;
}

inline std::vector<WithdrawCandidate> candidates_from_json(const json& arr) {
    std::vector<WithdrawCandidate> cs;
    for (const auto& c : arr) cs.push_back(WithdrawCandidate{from_hex(c.at("blinded_m")), from_hex(c.at("tag"))});
    return cs;
}

inline json openings_to_json(const std::vector<CandidateOpening>& os) {
    json arr = json::array();
    for (const auto& o : os) {
        arr.push_back({{"index", o.index}, {"serial", o.serial},
                       {"a", hex(o.a)}, {"s", hex(o.s)}, {"r", hex(o.r)}});
    }
    return arr;
}

inline std::vector<CandidateOpening> openings_from_json(const json& arr) {
    std::vector<CandidateOpening> os;
    for (const auto& o : arr) {
        os.push_back(CandidateOpening{o.at("index").get<size_t>(), o.at("serial").get<std::string>(),
                                      from_hex(o.at("a")), from_hex(o.at("s")), from_hex(o.at("r"))});
    }
    return os;
}

inline void ring_from_json(PublicKeyRing& ring, const json& denoms) {
    for (const auto& d : denoms) {
        ring.add(d.at("denomination").get<int>(), from_hex(d.at("n")), from_hex(d.at("e")));
    }
}
}

struct BankPersistence {
    static wire::json save(const Bank& b) {
        using namespace wire;
        json j;
        j["group"] = group_to_json(b.group_);

        json keys = json::array();
        for (const auto& kv : b.keys_) {
            const RSAKeyPair& k = kv.second;
            keys.push_back({{"denomination", kv.first}, {"n", hex(k.n)}, {"e", hex(k.e)},
                            {"d", hex(k.d)}, {"bits", k.modulus_bits}});
        }
        j["keys"] = keys;

        j["balances"] = b.balances_;
        j["tag_log"] = b.tag_log_;

        json spent = json::object();
        for (const auto& kv : b.spent_) spent[kv.first] = transcript_to_json(kv.second);
        j["spent"] = spent;

        j["flagged"] = b.flagged_;
        return j;
    }

    static void load(Bank& b, const wire::json& j) {
        using namespace wire;
        b.group_ = group_from_json(j.at("group"));
        b.has_group_ = true;

        b.keys_.clear();
        for (const auto& k : j.at("keys")) {
            RSAKeyPair kp{from_hex(k.at("n")), from_hex(k.at("e")), from_hex(k.at("d")),
                          k.at("bits").get<int>()};
            b.keys_.emplace(k.at("denomination").get<int>(), std::move(kp));
        }

        b.balances_ = j.at("balances").get<std::map<std::string, int>>();
        b.tag_log_ = j.at("tag_log").get<std::map<std::string, std::string>>();

        b.spent_.clear();
        for (auto it = j.at("spent").begin(); it != j.at("spent").end(); ++it) {
            b.spent_.emplace(it.key(), transcript_from_json(it.value()));
        }

        b.flagged_ = j.at("flagged").get<std::set<std::string>>();
    }
};
