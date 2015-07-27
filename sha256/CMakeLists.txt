# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

project(sha256)

# add_definitions(-DDefNameHere)

set(sha256_sources
    ../libthoro/common/StringUtils.cpp
    ../libthoro/filesystem/FileFunctions.cpp
    ../libthoro/hash/sha-1.cpp
    ../libthoro/hash/sha-256.cpp
    ../libthoro/hash/sha-256_sources.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O3 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(sha256 ${sha256_sources})
