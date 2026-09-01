cmake_minimum_required(VERSION 3.22.1)
project(main)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Enable debug symbols for all build types
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fno-omit-frame-pointer")

# Keep debug symbols in release builds
string(REPLACE "-g0" "-g" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "-g0" "-g" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

add_library(main SHARED
        main.cpp
)

target_link_libraries(
        main
        PRIVATE
        android
        log
)

# Ensure debug symbols are preserved in the .so file
target_compile_options(main PRIVATE -g -fno-omit-frame-pointer)
