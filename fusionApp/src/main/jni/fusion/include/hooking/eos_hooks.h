#pragma once

#include <cstdint>
#include <logger.h>
#include <external/dobby.h>
#include <dlfcn.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <android/log.h>

#define TAG "EOS_Hooks"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

struct CredentialsInternal {
    int32_t ApiVersion;
    uint32_t padding;
    void* Token;
    int32_t Type;
};

struct LoginOptionsInternal {
    int32_t ApiVersion;
    uint32_t padding;
    void* Credentials;
    void* UserLoginInfo;
};

typedef int (*EOS_Connect_Login_t)(void* options, void* clientData, void* completionDelegate);
extern EOS_Connect_Login_t original_EOS_Connect_Login = nullptr;

static void* g_allocated_token = nullptr;
static bool g_token_injected = false;

__attribute__((destructor))
void cleanup_eos_hooks() {
    if (g_allocated_token != nullptr) {
        free(g_allocated_token);
        g_allocated_token = nullptr;
    }
}

static std::string ReadTokenFromFile() {
    std::string path = "/storage/emulated/0/FusionCore/com.innersloth.spacemafia/BepInEx/config/Authfix-token.json";
    std::ifstream file(path);
    if (!file.is_open()) {
        path = "/sdcard/FusionCore/fusion_auth.json";
        file.open(path);
        if (!file.is_open()) {
            LOGE("Failed to open token file");
            return "";
        }
    }
    
    std::string json;
    std::stringstream buffer;
    buffer << file.rdbuf();
    json = buffer.str();
    file.close();
    
    size_t pos = json.find("\"idToken\":");
    if (pos == std::string::npos) {
        LOGE("idToken not found in JSON");
        return "";
    }
    
    size_t start = json.find("\"", pos + 10);
    if (start == std::string::npos) return "";
    
    size_t end = json.find("\"", start + 1);
    if (end == std::string::npos) return "";
    
    std::string token = json.substr(start + 1, end - start - 1);
    LOGI("Token loaded, length: %zu", token.length());
    return token;
}

int Hooked_EOS_Connect_Login(void* options, void* clientData, void* completionDelegate) {
    LOGI("=== HOOKED: EOS_Connect_Login ===");
    
    if (options != nullptr) {
        LoginOptionsInternal* loginOptions = (LoginOptionsInternal*)options;
        
        LOGI("Options: %p, Credentials: %p, UserLoginInfo: %p", 
             options, loginOptions->Credentials, loginOptions->UserLoginInfo);
        
        if (loginOptions->Credentials != nullptr) {
            CredentialsInternal* creds = (CredentialsInternal*)loginOptions->Credentials;
            LOGI("Credentials: ApiVersion=%d, Token=%p, Type=%d", 
                 creds->ApiVersion, creds->Token, creds->Type);
        }
        
        std::string token = ReadTokenFromFile();
        
        if (!token.empty()) {
            if (g_allocated_token != nullptr) {
                free(g_allocated_token);
                g_allocated_token = nullptr;
            }
            
            g_allocated_token = strdup(token.c_str());
            
            if (g_allocated_token != nullptr) {
                LOGI("Token allocated at: %p", g_allocated_token);
                LOGI("Token first 50 chars: %.50s...", (char*)g_allocated_token);
                
                if (loginOptions->Credentials != nullptr) {
                    CredentialsInternal* creds = (CredentialsInternal*)loginOptions->Credentials;
                    creds->Token = g_allocated_token;
                    creds->Type = 12;
                    LOGI("Token injected into existing Credentials");
                } else {
                    CredentialsInternal* newCreds = (CredentialsInternal*)calloc(1, sizeof(CredentialsInternal));
                    if (newCreds != nullptr) {
                        newCreds->ApiVersion = 1;
                        newCreds->Token = g_allocated_token;
                        newCreds->Type = 12;
                        
                        loginOptions->Credentials = newCreds;
                        LOGI("Created new Credentials with token");
                    } else {
                        LOGE("Failed to allocate Credentials");
                    }
                }
                
                g_token_injected = true;
            } else {
                LOGE("Failed to allocate token memory");
            }
        } else {
            LOGW("Token is empty, skipping injection");
        }
    }
    
    if (original_EOS_Connect_Login != nullptr) {
        int result = original_EOS_Connect_Login(options, clientData, completionDelegate);
        LOGI("EOS_Connect_Login returned: %d", result);
        return result;
    }
    
    LOGE("original_EOS_Connect_Login is null");
    return -1;
}

void install_eos_hooks() {
    LOGI("Installing EOS hooks...");
    
    void* eos_handle = dlopen("libEOSSDK.so", RTLD_LAZY);
    if (eos_handle == nullptr) {
        eos_handle = dlopen("/data/app/~~YbxYVA8dJMHirHj6j11SXQ==/com.innersloth.spacemafia-4k5B7521EUFKT3tZns8Feg==/lib/arm64/libEOSSDK.so", RTLD_LAZY);
        if (eos_handle == nullptr) {
            LOGE("libEOSSDK.so not found");
            return;
        }
    }
    
    LOGI("libEOSSDK.so loaded: %p", eos_handle);
    
    void* eos_connect_login = dlsym(eos_handle, "EOS_Connect_Login");
    if (eos_connect_login == nullptr) {
        LOGE("EOS_Connect_Login not found");
        return;
    }
    
    LOGI("EOS_Connect_Login found at: %p", eos_connect_login);
    
    original_EOS_Connect_Login = (EOS_Connect_Login_t)eos_connect_login;
    
    int hook_result = DobbyHook(eos_connect_login, (void*)Hooked_EOS_Connect_Login, (void**)&original_EOS_Connect_Login);
    
    if (hook_result == 0) {
        LOGI("EOS_Connect_Login hooked successfully");
    } else {
        LOGE("DobbyHook failed with code: %d", hook_result);
    }
}
