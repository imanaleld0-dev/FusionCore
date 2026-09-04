#pragma once

#include <cstdint>
#include <logger.h>
#include <external/dobby.h>
#include <dlfcn.h>

#define TAG "EOS_Hooks"

void install_eos_hooks();

struct CredentialsInternal {
    int32_t ApiVersion; // +0x00
    uint32_t padding;   // +0x04
    void* Token;        // +0x08
    int32_t Type;       // +0x10
};

struct LoginOptionsInternal {
    int32_t ApiVersion;      // +0x00
    uint32_t padding;        // +0x04
    void* Credentials;       // +0x08
    void* UserLoginInfo;     // +0x10
};
