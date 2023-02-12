#pragma once

#include <jni.h>
#include <string>
#include <string_view>

namespace art {
    class MethodCallback {
    public:
        virtual ~MethodCallback() {}

        virtual void RegisterNativeMethod(void* method, void* original_implementation, void** new_implementation) = 0;
    };
}

using register_listener_t = void (*)(const char* clazz, const char* name, const char* signature, void* fn, bool replace);

class ZygiskCallback : public art::MethodCallback {
public:
    struct Item {
        std::string className;
        const int nativeMethodCount;
        const JNINativeMethod* nativeMethods;
        void** pOriginalMethod;
    };

    inline void AddCallback(std::string clazz, int cnt, const JNINativeMethod* methods, void** origin) {
        mItems.emplace_back(Item{clazz, cnt, methods, origin});
    }

    ZygiskCallback();

    ~ZygiskCallback();

    void SetOnRegisterListener(register_listener_t);

    void RegisterNativeMethod(void* method, void* original_implementation, void** new_implementation) override;

    static bool InitSymbols();

private:
    std::vector<Item> mItems;
    register_listener_t mOnRegisterListener = nullptr;
};
