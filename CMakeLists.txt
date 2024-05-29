cmake_minimum_required(VERSION 3.8)

project(sha256)

# If the option ENABLE_LTO is enabled (e. g. via `cmake -DENABLE_LTO=ON`)
# during the build, then all binaries will use link-time optimization (LTO).
option(ENABLE_LTO "Enable link-time optimization" OFF)
# Not all compilers support LTO / IPO, so it has to be checked.
if (ENABLE_LTO)
  cmake_policy(SET CMP0069 NEW)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT HAS_LTO_SUPPORT OUTPUT LTO_FAIL_REASON
                      LANGUAGES C CXX)
  if (NOT HAS_LTO_SUPPORT)
    message(FATAL "IPO / LTO is not supported: ${LTO_FAIL_REASON}")
  else()
    message(STATUS "IPO / LTO is supported. Using it.")
  endif()
endif (ENABLE_LTO)

# If ENABLE_STATIC_LINKING is on (e. g. via `cmake -DENABLE_STATIC_LINKING=ON`),
# then all libraries are linked statically. The option is off by default.
#
# Static linking increases the size of the binaries, but those binaries do not
# need the libraries to be present on the system.
#
# WARNING: This option is still experimental and may not work completely.
option(ENABLE_STATIC_LINKING "Links all libraries statically" OFF)
if (ENABLE_STATIC_LINKING)
  set(CMAKE_LINK_SEARCH_START_STATIC 1)
  set(CMAKE_LINK_SEARCH_END_STATIC 1)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static")
endif ()

# Recurse into subdirectory for sha256 executable.
add_subdirectory (sha256)

# enable tests
enable_testing()
# Recurse into subdirectory for test cases.
add_subdirectory (tests)
