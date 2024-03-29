cmake_minimum_required (VERSION 3.8)

# binary for additional SHA-512 tests
project(test_additional_sha512)

set(test_additional_sha512_src
    ../../../libstriezel/common/StringUtils.cpp
    ../../../libstriezel/filesystem/file.cpp
    ../../../libstriezel/hash/sha512/FileSourceUtility.cpp
    ../../../libstriezel/hash/sha512/sha512.cpp
    ../../../libstriezel/hash/sha512/FileSource.cpp
    ../../../libstriezel/hash/sha512/MessageSource.cpp
    main.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions(-Wall -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_additional_sha512 ${test_additional_sha512_src})

# add it as a test
add_test(NAME SHA-512-additional
         COMMAND $<TARGET_FILE:test_additional_sha512> --long)
