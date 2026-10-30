// net_common.hpp
//
// Small helpers shared by the three programs that speak HTTP (bank server,
// app server, wallet agent): JSON replies, command-line parsing, atomic file
// writes, random hex from the OS, timestamps. Not part of the ghostcash
// library.

#pragma once

#include "httplib.h"
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>

namespace net {

using json = nlohmann::json;

inline void reply(httplib::Response& res, int status, const json& body) {
    res.status = status;
    res.set_content(body.dump(), "application/json");
}

inline void fail(httplib::Response& res, int status, const std::string& message) {
    reply(res, status, json{{"error", message}});
}

// --name value, or a bare --flag.
class Args {
public:
    Args(int argc, char** argv) {
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a.rfind("--", 0) != 0) continue;
            std::string key = a.substr(2);
            if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
                values_[key] = argv[++i];
            } else {
                flags_.insert(key);
            }
        }
    }

    std::string get(const std::string& key, const std::string& def) const {
        auto it = values_.find(key);
        return it == values_.end() ? def : it->second;
    }

    int get_int(const std::string& key, int def) const {
        auto it = values_.find(key);
        return it == values_.end() ? def : std::atoi(it->second.c_str());
    }

    bool has(const std::string& flag) const { return flags_.count(flag) != 0; }

private:
    std::map<std::string, std::string> values_;
    std::set<std::string> flags_;
};

inline bool read_file(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

// Writes to a temporary file and renames it over the target, so a crash
// mid-write never leaves a truncated state file.
inline void write_file_atomic(const std::string& path, const std::string& content) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot write " + tmp);
        out << content;
    }
    std::filesystem::rename(tmp, path);
}

inline std::string random_hex(size_t nbytes) {
    std::string bytes(nbytes, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&bytes[0]), static_cast<int>(nbytes)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (unsigned char c : bytes) {
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 15]);
    }
    return out;
}

inline std::string now_iso() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

} // namespace net
