CXX          := g++
CXXSTD       := -std=c++17
WARN         := -Wall -Wextra
OPT          := -O2

PKG_CONFIG   ?= pkg-config
HAVE_PKGCONFIG := $(shell command -v $(PKG_CONFIG) >/dev/null 2>&1 && echo yes)
HAVE_BREW       := $(shell command -v brew >/dev/null 2>&1 && echo yes)

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

GMP_CFLAGS ?=
GMP_LIBS   ?= -lgmp

ifeq ($(HAVE_PKGCONFIG),yes)
  SSL_PC_OK := $(shell $(PKG_CONFIG) --exists libcrypto && echo yes)
endif

ifeq ($(SSL_PC_OK),yes)
  SSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto)
  SSL_LIBS   := $(shell $(PKG_CONFIG) --libs libcrypto)
else ifeq ($(HAVE_BREW),yes)
  SSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || brew --prefix openssl@3 2>/dev/null || brew --prefix openssl@1.1 2>/dev/null)
  ifneq ($(SSL_PREFIX),)
    SSL_CFLAGS := -I$(SSL_PREFIX)/include
    SSL_LIBS   := -L$(SSL_PREFIX)/lib -lcrypto
  endif
endif

SSL_CFLAGS ?=
SSL_LIBS   ?= -lcrypto

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
                tests/test_bank_wallet.cpp \
                tests/test_zkp.cpp \
                tests/test_clearance.cpp
TEST_BIN     := build/run_tests

NET_CXXFLAGS := $(CXXFLAGS) -Ithird_party -pthread
NET_HEADERS  := $(HEADERS) src/net_common.hpp third_party/httplib.h third_party/nlohmann/json.hpp

BANK_BIN     := build/bank_server
APP_BIN      := build/app_server
WALLET_BIN   := build/wallet_agent

.PHONY: all demo interactive test servers run run-interactive run-tests e2e clean print-config

all: demo interactive test servers

servers: $(BANK_BIN) $(APP_BIN) $(WALLET_BIN)

demo: $(DEMO_BIN)

interactive: $(INTERACTIVE_BIN)

test: $(TEST_BIN)

$(DEMO_BIN): $(DEMO_SRC) $(HEADERS) | build
	$(CXX) $(CXXFLAGS) $(DEMO_SRC) -o $(DEMO_BIN) $(LDFLAGS)

$(INTERACTIVE_BIN): $(INTERACTIVE_SRC) src/term_ui.hpp $(HEADERS) | build
	$(CXX) $(CXXFLAGS) $(INTERACTIVE_SRC) -o $(INTERACTIVE_BIN) $(LDFLAGS)

$(TEST_BIN): $(TEST_SRCS) $(HEADERS) tests/third_party/catch.hpp | build
	$(CXX) $(TEST_CXXFLAGS) $(TEST_SRCS) -o $(TEST_BIN) $(LDFLAGS)

$(BANK_BIN): src/bank_server.cpp $(NET_HEADERS) | build
	$(CXX) $(NET_CXXFLAGS) src/bank_server.cpp -o $@ $(LDFLAGS)

$(APP_BIN): src/app_server.cpp $(NET_HEADERS) | build
	$(CXX) $(NET_CXXFLAGS) src/app_server.cpp -o $@ $(LDFLAGS)

$(WALLET_BIN): src/wallet_agent.cpp $(NET_HEADERS) | build
	$(CXX) $(NET_CXXFLAGS) src/wallet_agent.cpp -o $@ $(LDFLAGS) -lsqlite3

build:
	mkdir -p build

run: demo
	./$(DEMO_BIN)

run-interactive: interactive
	./$(INTERACTIVE_BIN)

run-tests: test
	./$(TEST_BIN)

e2e: servers
	python3 scripts/e2e.py

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
