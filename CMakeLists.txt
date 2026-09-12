cmake_minimum_required(VERSION 3.16)
project(ghostcash LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

# ---------------------------------------------------------------------------
# Dependencies: GMP and OpenSSL (libcrypto, for SHA-256).
#
# OpenSSL has an official CMake package (`find_package(OpenSSL)`) that
# already knows how to locate Homebrew/MacPorts/vcpkg/system installs.
#
# GMP has no upstream CMake config, so we locate it manually via
# find_path/find_library. On top of the usual system paths, we also hint
# CMake at Homebrew's install locations on macOS (both the Apple Silicon
# prefix /opt/homebrew and the Intel prefix /usr/local), since neither is
# on the compiler's default search path and Homebrew keeps some formulae
# (like OpenSSL) "keg-only". A user can always override with:
#   cmake -B build -DGMP_ROOT=/path/to/gmp
# ---------------------------------------------------------------------------

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_GMP QUIET gmp)
endif()

find_path(GMP_INCLUDE_DIR
  NAMES gmp.h
  HINTS ${GMP_ROOT} ${PC_GMP_INCLUDEDIR} ${PC_GMP_INCLUDE_DIRS}
  PATHS /opt/homebrew/opt/gmp/include /usr/local/opt/gmp/include
)
find_library(GMP_LIBRARY
  NAMES gmp
  HINTS ${GMP_ROOT} ${PC_GMP_LIBDIR} ${PC_GMP_LIBRARY_DIRS}
  PATHS /opt/homebrew/opt/gmp/lib /usr/local/opt/gmp/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP DEFAULT_MSG GMP_LIBRARY GMP_INCLUDE_DIR)

if(NOT GMP_FOUND)
  message(FATAL_ERROR
    "GMP not found. Install it first:\n"
    "  Debian/Ubuntu: sudo apt-get install libgmp-dev\n"
    "  Fedora/RHEL:   sudo dnf install gmp-devel\n"
    "  macOS:         brew install gmp\n"
    "Or point CMake at a custom install with -DGMP_ROOT=/path/to/gmp")
endif()

if(NOT TARGET GMP::GMP)
  add_library(GMP::GMP UNKNOWN IMPORTED)
  set_target_properties(GMP::GMP PROPERTIES
    IMPORTED_LOCATION "${GMP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIR}")
endif()

# Give Homebrew's keg-only OpenSSL a fighting chance of being found even
# without the user setting up their environment (Homebrew normally tells
# you to export these, but doesn't set them for you).
if(NOT OPENSSL_ROOT_DIR)
  if(EXISTS /opt/homebrew/opt/openssl@3)
    set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
  elseif(EXISTS /usr/local/opt/openssl@3)
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl@3)
  endif()
endif()

find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------------------------

file(GLOB GHOSTCASH_HEADERS CONFIGURE_DEPENDS include/ghostcash/*.hpp)

add_executable(demo_issuance src/demo_issuance.cpp ${GHOSTCASH_HEADERS})
target_include_directories(demo_issuance PRIVATE include)
target_link_libraries(demo_issuance PRIVATE GMP::GMP OpenSSL::Crypto)

add_executable(demo_interactive src/demo_interactive.cpp src/term_ui.hpp ${GHOSTCASH_HEADERS})
target_include_directories(demo_interactive PRIVATE include)
target_link_libraries(demo_interactive PRIVATE GMP::GMP OpenSSL::Crypto)

add_executable(run_tests
  tests/test_main.cpp
  tests/test_bigint.cpp
  tests/test_group_setup.cpp
  tests/test_rsa_keygen.cpp
  tests/test_hash_utils.cpp
  tests/test_bank_wallet.cpp
  ${GHOSTCASH_HEADERS}
)
target_include_directories(run_tests PRIVATE include tests)
target_link_libraries(run_tests PRIVATE GMP::GMP OpenSSL::Crypto)

enable_testing()
add_test(NAME ghostcash_unit_tests COMMAND run_tests)

# Place binaries in build/ (matching the Makefile's layout) instead of
# scattering them across CMake's default per-target directories.
set_target_properties(demo_issuance demo_interactive run_tests PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
