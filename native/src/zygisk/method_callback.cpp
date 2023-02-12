#include "elf_util.h"
#include "method_callback.h"
#include "zygisk.hpp"

#include <base.hpp>

struct {
    void** kRuntime_instance = nullptr;

    void* (* kRuntime_GetRuntimeCallbacks)(void*) = nullptr;

    void (* kRuntimeCallbacks_AddMethodCallback)(void*, art::MethodCallback*) = nullptr;

    void (* kRuntimeCallbacks_RemoveMethodCallback)(void*, art::MethodCallback*) = nullptr;

    std::string (* kArtMethod_PrettyMethod)(void*, bool) = nullptr;
} symbols;

struct MethodInfo {
    std::string clazz;
    std::string method;
    std::string signature;
};

void* kArtRuntime = nullptr;

std::string ParseType(std::string_view type, bool with_pre_suf = true) {
    auto name = type.substr(0, type.find_first_of('['));
    auto arrays = std::count(type.begin(), type.end(), '[');
    auto res = std::string(arrays, '[');
    if (name == "void") {
        res += "V";
    } else if (name == "boolean") {
        res += "Z";
    } else if (name == "byte") {
        res += "B";
    } else if (name == "char") {
        res += "C";
    } else if (name == "short") {
        res += "S";
    } else if (name == "int") {
        res += "I";
    } else if (name == "long") {
        res += "J";
    } else if (name == "float") {
        res += "F";
    } else if (name == "double") {
        res += "D";
    } else {
        auto n = std::string(name);
        std::replace(n.begin(), n.end(), '.', '/');
        res += with_pre_suf ? "L" + n + ";" : n;
    }
    return res;
}

MethodInfo PrettyToJNISignature(std::string_view pretty) {
    auto space = pretty.find_first_of(' ');
    auto left_bracelet = pretty.find('(');
    auto right_bracelet = pretty.find(')');

    auto ret = ParseType(pretty.substr(0, space));
    auto clazz_method = pretty.substr(space + 1, left_bracelet - space - 1);
    auto clazz_dot = clazz_method.find_last_of('.');
    auto args = pretty.substr(left_bracelet + 1, right_bracelet - left_bracelet - 1);

    auto clazz = ParseType(clazz_method.substr(0, clazz_dot), false);
    auto method = std::string(clazz_method.substr(clazz_dot + 1));
    std::string signature = "(";
    while (true) {
        auto comma = args.find_first_of(", ");
        if (comma == std::string_view::npos) {
            signature += ParseType(args);
            break;
        }
        std::string sub(args.substr(0, comma));
        auto parsed = ParseType(sub);
        signature += ParseType(args.substr(0, comma));
        args = args.substr(comma + 2);
    }
    signature += ")";
    signature += ret;
    return {clazz, method, signature};
}

void ZygiskCallback::RegisterNativeMethod(void* method, void* original_implementation, void** new_implementation) {
    auto name = symbols.kArtMethod_PrettyMethod(method, true);
    auto [c, m, s] = PrettyToJNISignature(name);
    for (auto& item: mItems) {
        if (c != item.className) continue;
        for (int i = 0; i < item.nativeMethodCount; i++) {
            auto& n = item.nativeMethods[i];
            if (n.name && s == n.signature) {
                LOGI("replaced %s\n", m.data());
                *item.pOriginalMethod = original_implementation;
                *new_implementation = item.nativeMethods[i].fnPtr;
                mOnRegisterListener(item.className.data(), n.name, n.signature, original_implementation, true);
                return;
            }
        }
    }
    mOnRegisterListener(c.data(), m.data(), s.data(), original_implementation, false);
}

ZygiskCallback::ZygiskCallback() {
    ZLOGD("Instantiate MethodCallback\n");
    auto callbacks = symbols.kRuntime_GetRuntimeCallbacks(kArtRuntime);
    symbols.kRuntimeCallbacks_AddMethodCallback(callbacks, this);
}

ZygiskCallback::~ZygiskCallback() {
    ZLOGD("Drop MethodCallback\n");
    auto callbacks = symbols.kRuntime_GetRuntimeCallbacks(kArtRuntime);
    symbols.kRuntimeCallbacks_RemoveMethodCallback(callbacks, this);
}

void ZygiskCallback::SetOnRegisterListener(register_listener_t listener) {
    mOnRegisterListener = listener;
}

#define INIT_SYMBOL(NAME, SYMBOL) NAME = art.getSymbAddress<decltype(NAME)>(SYMBOL); if (!NAME) return false

bool ZygiskCallback::InitSymbols() {
    auto art = SandHook::ElfImg("/libart.so");
    if (!art.isValid()) return false;
    INIT_SYMBOL(symbols.kRuntime_instance, "_ZN3art7Runtime9instance_E");
    INIT_SYMBOL(symbols.kRuntime_GetRuntimeCallbacks, "_ZN3art7Runtime19GetRuntimeCallbacksEv");
    INIT_SYMBOL(symbols.kRuntimeCallbacks_AddMethodCallback, "_ZN3art16RuntimeCallbacks17AddMethodCallbackEPNS_14MethodCallbackE");
    INIT_SYMBOL(symbols.kRuntimeCallbacks_RemoveMethodCallback, "_ZN3art16RuntimeCallbacks20RemoveMethodCallbackEPNS_14MethodCallbackE");
    INIT_SYMBOL(symbols.kArtMethod_PrettyMethod, "_ZN3art9ArtMethod12PrettyMethodEb");
    kArtRuntime = *symbols.kRuntime_instance;
    return true;
}

#undef INIT_SYMBOL
