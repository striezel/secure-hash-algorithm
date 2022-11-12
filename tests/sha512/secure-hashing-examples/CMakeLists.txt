cmake_minimum_required (VERSION 3.8)

# binary for simple SHA-512 test
project(test_simple_sha512)

set(test_simple_sha512_src
    ../../../libstriezel/hash/sha512/BufferSource.cpp
    ../../../libstriezel/hash/sha512/BufferSourceUtility.cpp
    ../../../libstriezel/hash/sha512/MessageSource.cpp
    ../../../libstriezel/hash/sha512/sha512.cpp
    main.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions(-Wall -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_simple_sha512 ${test_simple_sha512_src})

# add it as a test
add_test(NAME SHA-512-simple
         COMMAND $<TARGET_FILE:test_simple_sha512>)
