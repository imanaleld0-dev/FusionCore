cmake_minimum_required(VERSION 3.22.1)
project(fusion)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Enable debug symbols for all build types
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fno-omit-frame-pointer")

# Keep debug symbols in release builds
string(REPLACE "-g0" "-g" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "-g0" "-g" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

set(LIB_FOLDER ${CMAKE_SOURCE_DIR}/../jniLibs/${CMAKE_ANDROID_ARCH_ABI})

add_library(fusion SHARED
        src/fusion.cpp
        src/fusion_config.cpp
        src/dotnet.cpp
        src/exports.cpp
        src/logger.cpp
        src/hooking/allocator.cpp
        src/hooking/il2cpp.cpp
        src/hooking/safehook.cpp
        src/hooking/libunity.cpp
        src/hooking/eos_hooks.cpp
        src/utilities/asm.cpp
        src/utilities/elf.cpp
        src/utilities/library.cpp
        src/utilities/java.cpp
)

target_include_directories(fusion PUBLIC include)

# Ensure debug symbols are preserved in the .so file
target_compile_options(fusion PRIVATE -g -fno-omit-frame-pointer)

target_link_libraries(
        fusion
        PUBLIC
        main
        android
        log
        ${LIB_FOLDER}/libdobby.so
        ${LIB_FOLDER}/libcoreclr.so
)
