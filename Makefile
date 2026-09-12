CXX          := g++
CXXSTD       := -std=c++17
WARN         := -Wall -Wextra
OPT          := -O2

# ---------------------------------------------------------------------------
# GMP / OpenSSL discovery
#
# The previous version of this Makefile hardcoded `-lgmp -lcrypto` and
# assumed both libraries' headers/libs live on the compiler's default search
# path. That's true on a lot of Linux setups (apt/dnf install into
# /usr/include, /usr/lib) but is NOT guaranteed in general:
#
#   - Homebrew on Apple Silicon installs into /opt/homebrew, on Intel Macs
#     into /usr/local -- neither is searched by g++/clang by default.
#   - Homebrew keeps OpenSSL "keg-only" (never symlinked into /usr/local),
#     so even -L/usr/local/lib alone won't find it.
#   - Some Linux distros/package managers put dev headers in nonstandard
#     prefixes (Nix, MacPorts, conda envs, custom --prefix installs).
#
# So: try pkg-config first (works out of the box on most Linux distros and
# for Homebrew's OpenSSL, which ships a .pc file). If pkg-config doesn't
# know about a library, fall back to `brew --prefix` when Homebrew is
# present. If neither source turns up anything, fall back to plain
# `-lgmp`/`-lcrypto` and let the system default search path try its luck
# (this preserves old behavior on systems where it already worked).
# ---------------------------------------------------------------------------

PKG_CONFIG   ?= pkg-config
HAVE_PKGCONFIG := $(shell command -v $(PKG_CONFIG) >/dev/null 2>&1 && echo yes)
HAVE_BREW       := $(shell command -v brew >/dev/null 2>&1 && echo yes)

# --- GMP ---------------------------------------------------------------
ifeq ($(HAVE_PKGCONFIG),yes)
  GMP_PC_OK := $(shell $(PKG_CONFIG) --exists gmp && echo yes)
endif

ifeq ($(GMP_PC_OK),yes)
  GMP_CFLAGS := $(shell $(PKG_CONFIG) --cflags gmp)
  GMP_LIBS   := $(shell $(PKG_CONFIG) --libs gmp)
else ifeq ($(HAVE_BREW),yes)
  GMP_PREFIX := $(shell brew --prefix gmp 2>/dev/null)
  ifneq ($(GMP_PREFIX),)
    GMP_CFLAGS := -I$(GMP_PREFIX)/include
    GMP_LIBS   := -L$(GMP_PREFIX)/lib -lgmp
  endif
endif

# Last-resort fallback: rely on the compiler's default search path.
GMP_CFLAGS ?=
GMP_LIBS   ?= -lgmp

# --- OpenSSL (only need libcrypto, for SHA-256) -------------------------
ifeq ($(HAVE_PKGCONFIG),yes)
  SSL_PC_OK := $(shell $(PKG_CONFIG) --exists libcrypto && echo yes)
endif

ifeq ($(SSL_PC_OK),yes)
  SSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto)
  SSL_LIBS   := $(shell $(PKG_CONFIG) --libs libcrypto)
else ifeq ($(HAVE_BREW),yes)
  # Homebrew's formula name varies across versions (openssl, openssl@1.1,
  # openssl@3); ask for the generic name first, then the versioned ones.
  SSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || brew --prefix openssl@3 2>/dev/null || brew --prefix openssl@1.1 2>/dev/null)
  ifneq ($(SSL_PREFIX),)
    SSL_CFLAGS := -I$(SSL_PREFIX)/include
    SSL_LIBS   := -L$(SSL_PREFIX)/lib -lcrypto
  endif
endif

SSL_CFLAGS ?=
SSL_LIBS   ?= -lcrypto

# ---------------------------------------------------------------------------

# Allow a user to override/extend discovery from the command line, e.g.:
#   make GMP_PREFIX=/opt/homebrew/opt/gmp SSL_PREFIX=/opt/homebrew/opt/openssl@3
# without having to edit this file.
ifdef GMP_PREFIX
  GMP_CFLAGS := -I$(GMP_PREFIX)/include
  GMP_LIBS   := -L$(GMP_PREFIX)/lib -lgmp
endif
ifdef SSL_PREFIX
  SSL_CFLAGS := -I$(SSL_PREFIX)/include
  SSL_LIBS   := -L$(SSL_PREFIX)/lib -lcrypto
endif

CXXFLAGS     := $(CXXSTD) $(OPT) $(WARN) -Iinclude $(GMP_CFLAGS) $(SSL_CFLAGS)
TEST_CXXFLAGS:= $(CXXFLAGS) -Itests
LDFLAGS      := $(GMP_LIBS) $(SSL_LIBS)

HEADERS      := $(wildcard include/ghostcash/*.hpp)

DEMO_SRC     := src/demo_issuance.cpp
DEMO_BIN     := build/demo_issuance

INTERACTIVE_SRC := src/demo_interactive.cpp
INTERACTIVE_BIN  := build/demo_interactive

TEST_SRCS    := tests/test_main.cpp \
                tests/test_bigint.cpp \
                tests/test_group_setup.cpp \
                tests/test_rsa_keygen.cpp \
                tests/test_hash_utils.cpp \
                tests/test_bank_wallet.cpp
TEST_BIN     := build/run_tests

.PHONY: all demo interactive test run run-interactive run-tests clean print-config

all: demo interactive test

demo: $(DEMO_BIN)

interactive: $(INTERACTIVE_BIN)

test: $(TEST_BIN)

$(DEMO_BIN): $(DEMO_SRC) $(HEADERS) | build
	$(CXX) $(CXXFLAGS) $(DEMO_SRC) -o $(DEMO_BIN) $(LDFLAGS)

# term_ui.hpp lives alongside demo_interactive.cpp (it's presentation-only
# glue, not part of the ghostcash library), so it's listed as an explicit
# prerequisite here rather than picked up by the $(HEADERS) glob.
$(INTERACTIVE_BIN): $(INTERACTIVE_SRC) src/term_ui.hpp $(HEADERS) | build
	$(CXX) $(CXXFLAGS) $(INTERACTIVE_SRC) -o $(INTERACTIVE_BIN) $(LDFLAGS)

# Catch2's single header is heavy to recompile, but it only needs to be
# compiled once per test source file; incremental rebuilds of just one test
# file stay fast since each .cpp here is compiled/linked in one shot.
$(TEST_BIN): $(TEST_SRCS) $(HEADERS) tests/third_party/catch.hpp | build
	$(CXX) $(TEST_CXXFLAGS) $(TEST_SRCS) -o $(TEST_BIN) $(LDFLAGS)

build:
	mkdir -p build

run: demo
	./$(DEMO_BIN)

run-interactive: interactive
	./$(INTERACTIVE_BIN)

run-tests: test
	./$(TEST_BIN)

# Handy for debugging a build failure on an unfamiliar machine: shows
# exactly which flags were auto-detected for GMP/OpenSSL.
print-config:
	@echo "CXX         = $(CXX)"
	@echo "GMP_CFLAGS  = $(GMP_CFLAGS)"
	@echo "GMP_LIBS    = $(GMP_LIBS)"
	@echo "SSL_CFLAGS  = $(SSL_CFLAGS)"
	@echo "SSL_LIBS    = $(SSL_LIBS)"
	@echo "CXXFLAGS    = $(CXXFLAGS)"
	@echo "LDFLAGS     = $(LDFLAGS)"

clean:
	rm -rf build
