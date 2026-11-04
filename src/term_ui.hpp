#pragma once

#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

namespace term {
inline bool colors_enabled() {
    static bool enabled = [] {
        if (std::getenv("NO_COLOR") != nullptr) return false;
        return isatty(fileno(stdout)) != 0;
    }();
    return enabled;
}

inline std::string wrap(const char* code, const std::string& s) {
    if (!colors_enabled()) return s;
    return std::string("\033[") + code + "m" + s + "\033[0m";
}

inline std::string bold(const std::string& s)   { return wrap("1", s); }
inline std::string dim(const std::string& s)     { return wrap("2", s); }
inline std::string cyan(const std::string& s)    { return wrap("36", s); }
inline std::string yellow(const std::string& s)  { return wrap("33", s); }
inline std::string magenta(const std::string& s) { return wrap("35", s); }
inline std::string green(const std::string& s)   { return wrap("32", s); }
inline std::string red(const std::string& s)     { return wrap("31", s); }

inline bool& interactive_mode() {
    static bool value = true;
    return value;
}

inline void init(int argc, char** argv) {
    interactive_mode() = (isatty(fileno(stdin)) != 0);
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--auto" || arg == "-y") interactive_mode() = false;
    }
}

inline void pause(const std::string& prompt = "Press Enter to continue...") {
    if (!interactive_mode()) return;
    std::cout << dim("    " + prompt) << std::flush;
    std::string discard;
    std::getline(std::cin, discard);
}

inline void banner(const std::string& title) {
    std::string bar(title.size() + 4, '=');
    std::cout << "\n" << bold(bar) << "\n";
    std::cout << bold("  " + title) << "\n";
    std::cout << bold(bar) << "\n\n";
}

inline std::string truncated(const std::string& numeral, size_t head = 24, size_t tail = 8) {
    if (numeral.size() <= head + tail + 3) return numeral;
    return numeral.substr(0, head) + "..." + numeral.substr(numeral.size() - tail);
}
}
