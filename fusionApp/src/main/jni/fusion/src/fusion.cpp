#include <unistd.h>
#include <jni.h>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <sstream>
#include <string>
#include <cstdint>
#include <dlfcn.h>

#include <logger.h>
#include <libmain.h>
#include <fusion_config.h>
#include <hooking/il2cpp.h>
#include <hooking/safehook.h>
#include <hooking/allocator.h>
#include <hooking/libunity.h>
#include <dotnet.h>
#include <external/dobby.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <android/log.h>
#include <external/dobby.h>

#define TAG "Hooks_EOS"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_OG_WARN, TAG, __VA_ARGS__)

static void* g_allocated_token = nullptr;
static void* g_allocated_credentials = nullptr;

namespace fs = std::filesystem;

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

static std::string ReadTokenFromFile()
{
    const char* paths[] =
    {
        "/storage/emulated/0/FusionCore/com.innersloth.spacemafia/BepInEx/config/Authfix-token.json"
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






// =========================================================
// EOS hook
// =========================================================
using EOS_Connect_Login_t =
    int (*)(void* options,
            void* clientData,
            void* completionDelegate);

static EOS_Connect_Login_t original_EOS_Connect_Login = nullptr;

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
                g_allocated_token =  std::malloc(token.size() + 1);

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


// =========================================================
// FusionCore state
// =========================================================

static FusionConfig runtimeConfig;
static FusionConfig stagedConfig;

static std::string stagedPatchedIl2CppPath;

static std::mutex stageMutex;
static bool hasStagedConfig = false;


// =========================================================
// Config parser
// =========================================================

static std::unordered_map<std::string, std::string>
read_key_value_file(const char* configPath)
{
    std::unordered_map<std::string, std::string> values;

    std::ifstream input(configPath);
    std::string line;

    while (std::getline(input, line))
    {
        if (line.empty())
            continue;

        size_t split = line.find('=');

        if (split == std::string::npos)
            continue;

        std::string key = line.substr(0, split);
        std::string value = line.substr(split + 1);

        values[key] = value;
    }

    return values;
}


static bool parse_bool_value(const std::string& value)
{
    return value == "1" ||
           value == "true" ||
           value == "TRUE";
}


static bool parse_fusion_config_from_file(
    const char* configPath,
    FusionConfig* config)
{
    auto values = read_key_value_file(configPath);

    if (values.empty())
    {
        log_format(
            LogLevel::ERROR,
            TAG,
            "Config file is empty or unreadable: {}",
            configPath
        );

        return false;
    }

    config->gameLibraryDirectory =
        values["gameLibraryDirectory"];

    config->appLibraryDirectory =
        values["appLibraryDirectory"];

    config->appDataDirectory =
        values["appDataDirectory"];

    config->bepInExDirectory =
        values["bepInExDirectory"];

    config->dotnetDirectory =
        values["dotnetDirectory"];

    config->unityDataDirectory =
        values["unityDataDirectory"];

    config->unityVersion =
        values["unityVersion"];

    config->useOriginalLibUnity =
        parse_bool_value(
            values["useOriginalLibUnity"]
        );

    if (config->gameLibraryDirectory.empty() ||
        config->appDataDirectory.empty())
    {
        log_format(
            LogLevel::ERROR,
            TAG,
            "Invalid config file (missing required fields): {}",
            configPath
        );

        return false;
    }

    config->initialized = true;

    return true;
}


// =========================================================
// Stage FusionCore
// =========================================================

static bool stage_fusion_config(
    const FusionConfig& parsedConfig)
{
    fusion_print_config(parsedConfig);

    fs::path gameLibsPath(
        parsedConfig.gameLibraryDirectory
    );

    fs::path appDataPath(
        parsedConfig.appDataDirectory
    );

    fs::path libIl2Cpp =
        gameLibsPath / "libil2cpp.so";

    fs::path libUnity;

    if (parsedConfig.useOriginalLibUnity)
    {
        libUnity =
            gameLibsPath / "libunity.so";
    }
    else
    {
        libUnity =
            appDataPath / "libunity.so";
    }

    std::string libUnityPath =
        libUnity.string();

    try_hook_libunity(
        libUnityPath,
        (gameLibsPath / "libunity.so").string()
    );

    fs::path patchedLibIl2Cpp =
        appDataPath / "libil2cpp.so";

    allocate_setup_injected(
        libIl2Cpp.c_str(),
        patchedLibIl2Cpp.c_str(),
        1024 * 1024
    );

    std::string patchedPath =
        patchedLibIl2Cpp.string();

    libmain_set_override_il2cpp_path(
        patchedPath.c_str()
    );

    libmain_set_override_unity_path(
        libUnityPath.c_str()
    );

    {
        std::lock_guard<std::mutex> guard(stageMutex);

        stagedConfig = parsedConfig;
        stagedPatchedIl2CppPath =
            patchedPath;

        hasStagedConfig = true;
    }

    log(
        LogLevel::INFO,
        TAG,
        "FusionCore config staged successfully."
    );

    return true;
}

int il2cpp_init_hook(char* domain_name)
{
    log_format(
        LogLevel::INFO,
        TAG,
        "il2cpp_init called with domain: {}",
        domain_name
    );

     il2cpp_destroy_init_hook();

     install_eos_hooks();


    // -----------------------------------------------------
    // Original il2cpp_init
    // -----------------------------------------------------

    int result =
        il2cpp_init(domain_name);

    

    if (runtimeConfig.initialized)
    {
        setenv(
            "BEPINEX_GAME_ASSEMBLY_PATH",
            libmain_get_override_il2cpp_path(),
            1
        );

        setenv(
            "FUSION_BEPINEX_PATH",
            runtimeConfig.bepInExDirectory.c_str(),
        );

        setenv(
            "FUSION_GAME_BINARY",
            libmain_get_override_il2cpp_path(),
            1
        );

        setenv(
            "FUSION_GAME_DATA_DIR",
            runtimeConfig.unityDataDirectory.c_str(),
            1
        );

        setenv(
            "FUSION_APP_DATA_DIR",
            runtimeConfig.appDataDirectory.c_str(),
            1
        );

        setenv(
            "FUSION_UNITY_VERSION",
            runtimeConfig.unityVersion.c_str(),
            1
        );


        // -------------------------------------------------
        // SSL certificates
        // -------------------------------------------------

        const char* ssl_cert_path =
            "/apex/com.android.conscrypt/cacerts";

        const char* backup_cert_path =
            "/system/etc/security/cacerts";

        if (access(ssl_cert_path, R_OK) == 0)
        {
            setenv(
                "SSL_CERT_DIR",
                ssl_cert_path,
                1
            );
        }
        else if (access(backup_cert_path, R_OK) == 0)
        {
            setenv(
                "SSL_CERT_DIR",
                backup_cert_path,
                1
            );
        }
        else
        {
            log(
                LogLevel::WARN,
                TAG,
                "No readable SSL cert file found; "
                "HTTPS requests may fail."
            );
        }

        const char* certDir =
            getenv("SSL_CERT_DIR");

        if (certDir != nullptr)
        {
            log_format(
                LogLevel::INFO,
                TAG,
                "Using {} for SSL certificates",
                certDir
            );
        }


        // -------------------------------------------------
        // BepInEx
        // -------------------------------------------------

        fs::path bepInExCoreDirectory =
            fs::path(
                runtimeConfig.bepInExDirectory
            ) / "core";


        DotNetConfig dotNetConfig;

        dotNetConfig.runtimeDir =
            runtimeConfig.dotnetDirectory;

        dotNetConfig.managedLibsDir =
            bepInExCoreDirectory.string();

        dotNetConfig.entryPointAssembly =
            "BepInEx.Unity.IL2CPP";

        dotNetConfig.entryPointType =
            "BepInEx.Unity.IL2CPP.FusionCoreEntrypoint";

        dotNetConfig.entryPointMethod =
            "Start";


        // -------------------------------------------------
        // MonoMod temp
        // -------------------------------------------------

        setenv(
            "TMPDIR",
            runtimeConfig.appDataDirectory.c_str(),
            1
        );


        // -------------------------------------------------
        // Execute managed bootstrap
        // -------------------------------------------------

        dotnet_execute_assembly(
            dotNetConfig
        );
    }
    else
    {
        log(
            LogLevel::WARN,
            TAG,
            "FusionConfig not initialized. "
            "Skipping modloader initialization."
        );
    }


    log_format(
        LogLevel::INFO,
        TAG,
        "il2cpp_init returned: {}",
        result
    );

    return result;
}


    if (options != nullptr)
    {
        auto* loginOptions =
            reinterpret_cast<EOS_LoginOptions*>(
                options
            );

        log_format(
            LogLevel::INFO,
            TAG,
            "LoginOptions ApiVersion={}",
            loginOptions->ApiVersion
        );

        log_format(
            LogLevel::INFO,
            TAG,
            "LoginOptions Credentials={}",
            reinterpret_cast<uintptr_t>(
                loginOptions->Credentials
            )
        );

        log_format(
            LogLevel::INFO,
            TAG,
            "LoginOptions UserLoginInfo={}",
            reinterpret_cast<uintptr_t>(
                loginOptions->UserLoginInfo
            )
        );

        if (loginOptions->Credentials != nullptr)
        {
            auto* credentials =
                loginOptions->Credentials;

            log_format(
                LogLevel::INFO,
                TAG,
                "Credentials Token={}",
                reinterpret_cast<uintptr_t>(
                    credentials->Token
                )
            );

            log_format(
                LogLevel::INFO,
                TAG,
                "Credentials Type={}",
                credentials->Type
            );
        }
        else
        {
            log(
                LogLevel::INFO,
                TAG,
                "Credentials=NULL"
            );
        }
    }
    else
    {
        log(
            LogLevel::WARN,
            TAG,
            "EOS_Connect_Login received NULL options"
        );
    }


    // -----------------------------------------------------
    // Call original
    // -----------------------------------------------------

    if (original_EOS_Connect_Login == nullptr)
    {
        log(
            LogLevel::ERROR,
            TAG,
            "Original EOS_Connect_Login is NULL"
        );

        return -1;
    }

    int result =
        original_EOS_Connect_Login(
            options,
            clientData,
            completionDelegate
        );

    log_format(
        LogLevel::INFO,
        TAG,
        "Original EOS_Connect_Login returned {}",
        result
    );

    return result;
}


// =========================================================
// Install EOS hook
// =========================================================

void install_eos_hooks()
{
    LOGI("Installing EOS hooks...");

    void* eos_handle = dlopen("libEOSSDK.so", RTLD_NOW);
    if (eos_handle == nullptr)
    {
        LOGE("dlopen(libEOSSDK.so) failed: %s", dlerror());
        return;
    }

    void* target = dlsym(eos_handle, "EOS_Connect_Login");
    if (target == nullptr)
    {
        LOGE("EOS_Connect_Login not found: %s", dlerror());
        return;
    }

    LOGI("EOS_Connect_Login address=%p", target);

    int hook_result = DobbyHook(
        target,
        reinterpret_cast<void*>(Hooked_EOS_Connect_Login),
        reinterpret_cast<void**>(&original_EOS_Connect_Login)
    );

    if (hook_result == 0)
    {
        LOGI("EOS_Connect_Login hooked successfully");
    }
    else
    {
        LOGE("DobbyHook failed: %d", hook_result);
    }
}


    void* eos_connect_login =
        dlsym(
            eos_handle,
            "EOS_Connect_Login"
        );


    if (eos_connect_login == nullptr)
    {
        log(
            LogLevel::WARN,
            TAG,
            "EOS_Connect_Login not exported "
            "by libEOSSDK.so"
        );
        
        return;
    }


    log_format(
        LogLevel::INFO,
        TAG,
        "EOS_Connect_Login address={}",
        reinterpret_cast<uintptr_t>(
            eos_connect_login
        )
    );


    auto hook_result =
        DobbyHook(
            eos_connect_login,
            reinterpret_cast<void*>(
                Hooked_EOS_Connect_Login
            ),
            reinterpret_cast<void**>(
                &original_EOS_Connect_Login
            )
        );


    if (hook_result == 0)
    {
        log(
            LogLevel::INFO,
            TAG,
            "EOS_Connect_Login hooked successfully!"
        );
    }
    else
    {
        log_format(
            LogLevel::ERROR,
            TAG,
            "DobbyHook failed: {}",
            hook_result
        );
    }
}

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


static void* g_allocated_token = nullptr;


struct CredentialsInternal {
    int32_t ApiVersion;
    uint32_t padding;
    void* Token;
    int32_t Type;
};
namespace fs = std::filesystem;

// =========================================================
// Stage API
// =========================================================

extern "C"
bool fusion_stage_from_config_path(
    const char* configPath)
{
    if (!configPath)
    {
        log(
            LogLevel::ERROR,
            TAG,
            "fusion_stage_from_config_path "
            "called with null path"
        );

        return false;
    }

    log_format(
        LogLevel::INFO,
        TAG,
        "Staging FusionCore config from {}",
        configPath
    );

    FusionConfig parsedConfig{};

    if (!parse_fusion_config_from_file(
            configPath,
            &parsedConfig))
    {
        return false;
    }

    return stage_fusion_config(
        parsedConfig
    );
}


// =========================================================
// Bootstrap API
// =========================================================

extern "C"
bool fusion_bootstrap_from_libmain(
    JNIEnv* env)
{
    (void)env;

    FusionConfig configToRun;
    std::string patchedIl2CppPath;


    {
        std::lock_guard<std::mutex> guard(
            stageMutex
        );

        if (!hasStagedConfig)
        {
            log(
                LogLevel::ERROR,
                TAG,
                "No staged FusionConfig available; "
                "cannot bootstrap from libmain namespace."
            );

            return false;
        }

        configToRun =
            stagedConfig;

        patchedIl2CppPath =
            stagedPatchedIl2CppPath;
    }


    runtimeConfig =
        configToRun;


    log(
        LogLevel::INFO,
        TAG,
        "Executing Fusion bootstrap "
        "from libmain namespace..."
    );


    // -----------------------------------------------------
    // Initialize IL2CPP
    // -----------------------------------------------------

    if (!il2cpp_initialize(
            patchedIl2CppPath.c_str()))
    {
        log_format(
            LogLevel::ERROR,
            TAG,
            "Failed to initialize il2cpp with path: {}",
            patchedIl2CppPath
        );

        return false;
    }


    // -----------------------------------------------------
    // SafeHook
    // -----------------------------------------------------

    auto library_size =
        reinterpret_cast<size_t>(
            get_injected_pool_base() -
            il2cpp_get_library_base()
        );


    if (!safehook_initialize(
            il2cpp_get_handle(),
            il2cpp_get_library_base(),
            library_size,
            allocate_injected))
    {
        log(
            LogLevel::ERROR,
            TAG,
            "Failed to initialize SafeHook"
        );

        return false;
    }


    // -----------------------------------------------------
    // IL2CPP hooks
    // -----------------------------------------------------

    log(
        LogLevel::INFO,
        TAG,
        "Installing il2cpp hooks..."
    );

    il2cpp_install_init_hook(
        il2cpp_init_hook
    );

    log(
        LogLevel::INFO,
        TAG,
        "il2cpp hooks installed successfully!"
    );


    log(
        LogLevel::INFO,
        TAG,
        "FusionCore bootstrap finished successfully."
    );

    return true;
}
