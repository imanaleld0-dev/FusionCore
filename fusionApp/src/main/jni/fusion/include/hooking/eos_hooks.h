#ifndef EOS_HOOKS_H
#define EOS_HOOKS_H
#include <stdint.h>
#include <jni.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*EOS_Connect_Login_t)(
    void* handle,           
    void* options,
    void* clientData,       
    void* completionDelegate
);


bool InstallEOSConnectLoginHook();
void RemoveEOSConnectLoginHook();
void install_eos_hooks();
void LogAuthDiag(const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
