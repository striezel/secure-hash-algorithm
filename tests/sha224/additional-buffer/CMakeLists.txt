cmake_minimum_required (VERSION 3.8...3.31)

# binary for additional SHA-224 tests
project(test_additional_buffer_sha224)

set(test_additional_buffer_sha224_src
    ../../../libstriezel/hash/sha224/BufferSourceUtility.cpp
    ../../../libstriezel/hash/sha224/sha224.cpp
    ../../../libstriezel/hash/sha256/BufferSource.cpp
    ../../../libstriezel/hash/sha256/MessageSource.cpp
    main.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions(-Wall -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_additional_buffer_sha224 ${test_additional_buffer_sha224_src})

# add it as a test
add_test(NAME SHA-224-additional-buffer
         COMMAND $<TARGET_FILE:test_additional_buffer_sha224> --long)
