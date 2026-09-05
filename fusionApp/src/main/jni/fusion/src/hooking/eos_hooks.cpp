#include "hooking/eos_hooks.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include <dlfcn.h>
#include <android/log.h>
#include <external/dobby.h>

#define LOG_TAG "EOSHooks" 

#define TAG "EOS_Hooks"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

using EOS_Connect_Login_t =
    int32_t (*)(void* handle,
                void* options,
                void* clientData,
                void* completionDelegate);

static EOS_Connect_Login_t original_EOS_Connect_Login = nullptr;
static void* g_allocated_token = nullptr;
static void* g_allocated_credentials = nullptr;

static EOS_Connect_Login_t g_original_EOS_Connect_Login = nullptr;
static bool g_hookInstalled = false;

struct CredentialsInternal {
    int32_t ApiVersion;
    uint32_t Padding;
    void* Token;
    int32_t Type;
};

struct LoginOptionsInternal {
    int32_t ApiVersion;
    uint32_t Padding;
    void* Credentials;
    void* UserLoginInfo;
};

static std::string ReadTokenFromFile() {
    const char* paths[] = {
        "/storage/emulated/0/FusionCore/com.innersloth.spacemafia/BepInEx/config/Authfix-token.json",
    };

    std::ifstream file;
    for (const char* path : paths) {
        file.open(path);
        if (file.is_open()) {
            LOGI("Opened token file: %s", path);
            break;
        }
        file.clear();
    }

    if (!file.is_open()) {
        LOGE("Could not open token file");
        return {};
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    const std::string json = buffer.str();
    file.close();

    if (json.empty()) {
        LOGE("Token JSON is empty");
        return {};
    }

    size_t pos = json.find("\"idToken\"");
    if (pos == std::string::npos) {
        LOGE("idToken field not found");
        return {};
    }

    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        LOGE("Invalid idToken JSON field");
        return {};
    }

    size_t start = json.find('"', pos + 1);
    if (start == std::string::npos) {
        LOGE("idToken value start not found");
        return {};
    }

    size_t end = json.find('"', start + 1);
    if (end == std::string::npos) {
        LOGE("idToken value end not found");
        return {};
    }

    std::string token = json.substr(start + 1, end - start - 1);
    if (token.empty()) {
        LOGE("idToken is empty");
        return {};
    }

    LOGI("Token loaded, length=%zu", token.length());
    return token;
}



static int Hooked_EOS_Connect_Login(void* handle,void* options, void* clientData, void* completionDelegate) {
    LOGI("=== EOS_Connect_Login intercepted ===");
    LOGI("[AuthDiag][Native] === EOS_Connect_Login HOOKED ===");
    LOGI("[AuthDiag][Native] handle         = %p", handle);
    LOGI("[AuthDiag][Native] options        = %p", options);
    LOGI("[AuthDiag][Native] clientData     = %p", clientData);
    LOGI("[AuthDiag][Native] completionDelegate = %p", completionDelegate);

    if (options != nullptr)
    {
        uint8_t* opts = (uint8_t*)options;
        LOGI("[AuthDiag][Native] options bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
             opts[0], opts[1], opts[2], opts[3],
             opts[4], opts[5], opts[6], opts[7]);
    }

    LOGI("[AuthDiag][Native] >>> Calling original EOS_Connect_Login...");


    LOGI("[AuthDiag][Native] <<< Original returned: %d", result);
    LOGI("[AuthDiag][Native] === EOS_Connect_Login END ===");

    if (options != nullptr) {
        auto* login = reinterpret_cast<LoginOptionsInternal*>(options);
        std::string token = ReadTokenFromFile();

        if (!token.empty()) {
            if (g_allocated_token == nullptr) {
                g_allocated_token = std::malloc(token.size() + 1);
                if (g_allocated_token != nullptr) {
                    std::memcpy(g_allocated_token, token.c_str(), token.size() + 1);
                    LOGI("Token allocated at %p", g_allocated_token);
                }
            }

            if (g_allocated_token != nullptr) {
                if (login->Credentials != nullptr) {
                    auto* creds = reinterpret_cast<CredentialsInternal*>(login->Credentials);
                    creds->Token = g_allocated_token;
                    creds->Type = 12;
                    LOGI("Token injected into existing Credentials");
                } else {
                    auto* newCreds = reinterpret_cast<CredentialsInternal*>(
                        std::calloc(1, sizeof(CredentialsInternal))
                    );
                    if (newCreds != nullptr) {
                        newCreds->ApiVersion = 1;
                        newCreds->Token = g_allocated_token;
                        newCreds->Type = 12;
                        login->Credentials = newCreds;
                        g_allocated_credentials = newCreds;
                        LOGI("Created new Credentials with token");
                    }
                }
            }
        }
    }


    if (original_EOS_Connect_Login != nullptr) {
        int32_t result = g_original_EOS_Connect_Login(
        handle,
        options,
        clientData,
        completionDelegate
    );
        LOGI("EOS_Connect_Login returned: %d", result);
        return result;
    }

    return -1;
}

bool InstallEOSConnectLoginHook()
{
    if (g_hookInstalled)
    {
        LOGI("[AuthDiag][Native] Hook already installed");
        return true;
    }

    
    void* eosLib = dlopen("libEOSSDK.so", RTLD_NOW);
    if (!eosLib)
    {
        eosLib = dlopen("libEOSSDK-Mac-Shipping.dylib", RTLD_NOW);
    }
    if (!eosLib)
    {
        eosLib = dlopen("libEOSSDK-Linux-Shipping.so", RTLD_NOW);
    }
    if (!eosLib)
    {
        LOGE("[AuthDiag][Native] Failed to open EOS SDK library: %s", dlerror());
        return false;
    }   
}


void LogAuthDiag(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, args);
    va_end(args);
}

__attribute__((destructor))
static void cleanup_eos_hooks() {
    if (g_allocated_token != nullptr) {
        std::free(g_allocated_token);
        g_allocated_token = nullptr;
    }

    if (g_allocated_credentials != nullptr) {
        std::free(g_allocated_credentials);
        g_allocated_credentials = nullptr;
    }

    original_EOS_Connect_Login = nullptr;
}
    
extern int DobbyHook(void* address, void* replace_func, void** orig_func);
int ret = DobbyHook(origFunc, (void*)Hooked_EOS_Connect_Login, (void**)&g_original_EOS_Connect_Login);

    if (ret != 0)
    {
        LOGE("[AuthDiag][Native] DobbyHook failed with code: %d", ret);
        dlclose(eosLib);
        return false;
    }

    g_hookInstalled = true;
    LOGI("[AuthDiag][Native] Hook installed successfully");
    return true;

void RemoveEOSConnectLoginHook()
{
    if (!g_hookInstalled)
        return;
 
    extern int DobbyDestroy(void* address);

    LOGI("[AuthDiag][Native] Hook removal requested (not fully implemented)");
    g_hookInstalled = false;
}
void install_eos_hooks() {
    LOGI("Installing EOS hooks...");

    void* eos_handle = dlopen("libEOSSDK.so", RTLD_NOW);
    if (eos_handle == nullptr) {
        LOGE("dlopen(libEOSSDK.so) failed: %s", dlerror());
        return;
    }

    void* target = dlsym(eos_handle, "EOS_Connect_Login");
    if (target == nullptr) {
        LOGE("EOS_Connect_Login not found: %s", dlerror());
        return;
    }

    LOGI("EOS_Connect_Login address=%p", target);

    int hook_result = DobbyHook(
        target,
        reinterpret_cast<void*>(Hooked_EOS_Connect_Login),
        reinterpret_cast<void**>(&original_EOS_Connect_Login)
    );

    if (hook_result == 0) {
        LOGI("EOS_Connect_Login hooked successfully");
    } else {
        LOGE("DobbyHook failed: %d", hook_result);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_fusion_authdiag_EOSHooks_installHook(JNIEnv* env, jclass clazz)
{
    (void)env;
    (void)clazz;
    InstallEOSConnectLoginHook();
}
