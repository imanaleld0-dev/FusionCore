#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <dlfcn.h>
#include <android/log.h>

#include <external/dobby.h>

#define TAG "EOS_Hooks"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

using EOS_Connect_Login_t =
    int (*)(void* options, void* clientData, void* completionDelegate);

static EOS_Connect_Login_t original_EOS_Connect_Login = nullptr;

static void* g_allocated_token = nullptr;
static void* g_allocated_credentials = nullptr;


// ---------------------------------------------------------
// Structures used only for inspecting the incoming ABI.
// ---------------------------------------------------------

struct CredentialsInternal
{
    int32_t ApiVersion;
    uint32_t Padding;
    void* Token;
    int32_t Type;
};

struct LoginOptionsInternal
{
    int32_t ApiVersion;
    uint32_t Padding;
    void* Credentials;
    void* UserLoginInfo;
};


// ---------------------------------------------------------
// Token loader
// ---------------------------------------------------------

static std::string ReadTokenFromFile()
{
    const char* paths[] =
    {
        "/storage/emulated/0/FusionCore/com.innersloth.spacemafia/BepInEx/config/Authfix-token.json",
        "/sdcard/FusionCore/fusion_auth.json"
    };

    std::ifstream file;

    for (const char* path : paths)
    {
        file.open(path);

        if (file.is_open())
        {
            LOGI("Opened token file: %s", path);
            break;
        }

        file.clear();
    }

    if (!file.is_open())
    {
        LOGE("Could not open token file");
        return {};
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    const std::string json = buffer.str();

    file.close();

    if (json.empty())
    {
        LOGE("Token JSON is empty");
        return {};
    }

    size_t pos = json.find("\"idToken\"");

    if (pos == std::string::npos)
    {
        LOGE("idToken field not found");
        return {};
    }

    pos = json.find(':', pos);

    if (pos == std::string::npos)
    {
        LOGE("Invalid idToken JSON field");
        return {};
    }

    size_t start = json.find('"', pos + 1);

    if (start == std::string::npos)
    {
        LOGE("idToken value start not found");
        return {};
    }

    size_t end = json.find('"', start + 1);

    if (end == std::string::npos)
    {
        LOGE("idToken value end not found");
        return {};
    }

    std::string token =
        json.substr(start + 1, end - start - 1);

    if (token.empty())
    {
        LOGE("idToken is empty");
        return {};
    }

    LOGI("Token loaded, length=%zu", token.length());

    return token;
}


// ---------------------------------------------------------
// EOS Login hook
// ---------------------------------------------------------

static int Hooked_EOS_Connect_Login(
    void* options,
    void* clientData,
    void* completionDelegate)
{
    LOGI("========================================");
    LOGI("EOS_Connect_Login intercepted");
    LOGI("options=%p", options);
    LOGI("clientData=%p", clientData);
    LOGI("completionDelegate=%p", completionDelegate);

    if (options != nullptr)
    {
        auto* login =
            reinterpret_cast<LoginOptionsInternal*>(options);

        LOGI(
            "LoginOptions: ApiVersion=%d Credentials=%p UserLoginInfo=%p",
            login->ApiVersion,
            login->Credentials,
            login->UserLoginInfo
        );

        if (login->Credentials != nullptr)
        {
            auto* credentials =
                reinterpret_cast<CredentialsInternal*>(
                    login->Credentials
                );

            LOGI(
                "Credentials: ApiVersion=%d Token=%p Type=%d",
                credentials->ApiVersion,
                credentials->Token,
                credentials->Type
            );
        }
        else
        {
            LOGI("Credentials=NULL");
        }

        std::string token = ReadTokenFromFile();

        if (!token.empty())
        {
            LOGI(
                "Token successfully read, length=%zu",
                token.length()
            );

            if (g_allocated_token == nullptr)
            {
                g_allocated_token =
                    std::malloc(token.size() + 1);

                if (g_allocated_token != nullptr)
                {
                    std::memcpy(
                        g_allocated_token,
                        token.c_str(),
                        token.size() + 1
                    );

                    LOGI(
                        "Token allocated at %p",
                        g_allocated_token
                    );
                }
                else
                {
                    LOGE("Failed to allocate token");
                }
            }

            if (g_allocated_token != nullptr)
            {
                if (login->Credentials != nullptr)
                {
                    auto* credentials =
                        reinterpret_cast<CredentialsInternal*>(
                            login->Credentials
                        );

                    credentials->Token = g_allocated_token;
                    credentials->Type = 12;

                    LOGI(
                        "Token injected into existing Credentials"
                    );
                    LOGI(
                        "New Credentials: Token=%p Type=%d",
                        credentials->Token,
                        credentials->Type
                    );
                }
                else
                {
                    auto* new_credentials =
                        reinterpret_cast<CredentialsInternal*>(
                            std::calloc(1, sizeof(CredentialsInternal))
                        );

                    if (new_credentials != nullptr)
                    {
                        new_credentials->ApiVersion = 1;
                        new_credentials->Token = g_allocated_token;
                        new_credentials->Type = 12;

                        login->Credentials = new_credentials;

                        LOGI(
                            "Created new Credentials with token"
                        );
                        LOGI(
                            "New Credentials: ApiVersion=%d Token=%p Type=%d",
                            new_credentials->ApiVersion,
                            new_credentials->Token,
                            new_credentials->Type
                        );
                    }
                    else
                    {
                        LOGE("Failed to allocate Credentials");
                    }
                }
            }
        }
        else
        {
            LOGW("No token available");
        }
    }
    else
    {
        LOGW("EOS_Connect_Login received NULL options");
    }

    if (original_EOS_Connect_Login == nullptr)
    {
        LOGE("Original EOS_Connect_Login is NULL");
        return -1;
    }

    LOGI("Calling original EOS_Connect_Login...");

    int result =
        original_EOS_Connect_Login(
            options,
            clientData,
            completionDelegate
        );

    LOGI(
        "Original EOS_Connect_Login returned %d",
        result
    );

    return result;
}


// ---------------------------------------------------------
// Cleanup
// ---------------------------------------------------------

__attribute__((destructor))
static void cleanup_eos_hooks()
{
    if (g_allocated_token != nullptr)
    {
        std::free(g_allocated_token);
        g_allocated_token = nullptr;
    }

    if (g_allocated_credentials != nullptr)
    {
        std::free(g_allocated_credentials);
        g_allocated_credentials = nullptr;
    }

    original_EOS_Connect_Login = nullptr;
}


// ---------------------------------------------------------
// Hook installation
// ---------------------------------------------------------

void install_eos_hooks()
{
    LOGI("Installing EOS hooks...");

    void* eos_handle =
        dlopen("libEOSSDK.so", RTLD_NOW);

    if (eos_handle == nullptr)
    {
        LOGE(
            "dlopen(libEOSSDK.so) failed: %s",
            dlerror()
        );

        return;
    }

    LOGI(
        "libEOSSDK.so handle=%p",
        eos_handle
    );

    void* target =
        dlsym(
            eos_handle,
            "EOS_Connect_Login"
        );

    if (target == nullptr)
    {
        LOGE(
            "EOS_Connect_Login not found: %s",
            dlerror()
        );

        return;
    }

    LOGI(
        "EOS_Connect_Login address=%p",
        target
    );

    auto hook_result =
        DobbyHook(
            target,
            reinterpret_cast<void*>(
                Hooked_EOS_Connect_Login
            ),
            reinterpret_cast<void**>(
                &original_EOS_Connect_Login
            )
        );

    if (hook_result == 0)
    {
        LOGI(
            "EOS_Connect_Login hooked successfully"
        );
    }
    else
    {
        LOGE(
            "DobbyHook failed: %d",
            hook_result
        );
    }
}
