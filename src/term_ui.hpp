// term_ui.hpp
//
// Tiny terminal-formatting helper used only by demo_interactive.cpp. Not
// part of the ghostcash library proper -- this is presentation glue, kept
// out of include/ghostcash/ on purpose.
//
// Colors are used purely to make it visually obvious, at a glance, which
// "actor" a line of output belongs to (wallet-private data vs. what's
// actually sent over the wire vs. what the bank does). They're disabled
// automatically when stdout isn't a terminal (e.g. piped into a file or
// `less`) or when the NO_COLOR environment variable is set, per
// https://no-color.org/.

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
inline std::string cyan(const std::string& s)    { return wrap("36", s); }   // wallet-private
inline std::string yellow(const std::string& s)  { return wrap("33", s); }   // on the wire
inline std::string magenta(const std::string& s) { return wrap("35", s); }   // bank
inline std::string green(const std::string& s)   { return wrap("32", s); }   // success
inline std::string red(const std::string& s)     { return wrap("31", s); }   // failure

// Whether to actually pause for input between steps. Off when stdin isn't a
// terminal (piped input, CI, `./demo_interactive < /dev/null`) so the demo
// never hangs in a non-interactive context; also off if the user passed
// --auto on the command line.
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

// Prints a section banner and, in interactive mode, waits for Enter before
// returning -- so a presenter can talk through the previous step before the
// next one appears.
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

// Truncates a long decimal numeral for display purposes only (e.g. "12345...
// (2048 bits)") -- printing a full 2048-bit RSA value would just be visual
// noise and wouldn't help anyone confirm anything by eye.
inline std::string truncated(const std::string& numeral, size_t head = 24, size_t tail = 8) {
    if (numeral.size() <= head + tail + 3) return numeral;
    return numeral.substr(0, head) + "..." + numeral.substr(numeral.size() - tail);
}

} // namespace term
