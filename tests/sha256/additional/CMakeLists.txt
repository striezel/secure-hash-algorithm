# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# binary for additional SHA-256 tests
project(test_additional_sha256)

set(test_additional_sha256_src
    ../../../libthoro/common/StringUtils.cpp
    ../../../libthoro/filesystem/DirectoryFunctions.cpp
    ../../../libthoro/filesystem/FileFunctions.cpp
    ../../../libthoro/hash/sha256/FileSource.cpp
    ../../../libthoro/hash/sha256/FileSourceUtility.cpp
    ../../../libthoro/hash/sha256/MessageSource.cpp
    ../../../libthoro/hash/sha256/sha256.cpp
    main.cpp)

# We use a C++11 feature in the code, so enable C++0x a.k.a. C++11.
add_definitions(-Wall -O2 -fexceptions -std=c++0x)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(test_additional_sha256 ${test_additional_sha256_src})

# add it as a test
add_test(NAME SHA-256-additional
         COMMAND $<TARGET_FILE:test_additional_sha256> ${CMAKE_CURRENT_SOURCE_DIR} --long)
