cmake_minimum_required (VERSION 3.8...3.31)

# binary for additional SHA-256 tests
project(test_additional_sha256)

set(test_additional_sha256_src
    ../../../libstriezel/common/StringUtils.cpp
    ../../../libstriezel/filesystem/directory.cpp
    ../../../libstriezel/filesystem/file.cpp
    ../../../libstriezel/hash/sha256/FileSource.cpp
    ../../../libstriezel/hash/sha256/FileSourceUtility.cpp
    ../../../libstriezel/hash/sha256/MessageSource.cpp
    ../../../libstriezel/hash/sha256/sha256.cpp
    main.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions(-Wall -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_additional_sha256 ${test_additional_sha256_src})

# add it as a test
add_test(NAME SHA-256-additional
         COMMAND $<TARGET_FILE:test_additional_sha256> ${CMAKE_CURRENT_SOURCE_DIR} --long)
