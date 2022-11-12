cmake_minimum_required (VERSION 3.8)

# binary simple SHA-1 test
project(test_simple_sha1)

set(test_simple_sha1_src
    ../../../libstriezel/hash/sha1/BufferSourceUtility.cpp
    ../../../libstriezel/hash/sha256/BufferSource.cpp
    ../../../libstriezel/hash/sha256/MessageSource.cpp
    ../../../libstriezel/hash/sha1/sha1.cpp
    main.cpp)


if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions(-Wall -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_simple_sha1 ${test_simple_sha1_src})

# add it as a test
add_test(NAME SHA-160-simple
         COMMAND $<TARGET_FILE:test_simple_sha1>)
