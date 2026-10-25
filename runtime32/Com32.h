// The reference's COM objects (com32gen.py says why): a proxy in each native object's place, its
// 4-byte vtable the generated thunks of Com32Gen.cpp. Com32.cpp keeps the proxies and has the
// methods whose structures need converting.
#pragma once
#include <windows.h>

#include <cstdint>
#include <cstring>

namespace com32 {

template <typename T>
T* At(uint32_t address) {
    return reinterpret_cast<T*>(static_cast<uintptr_t>(address));
}
inline uint32_t Low(const void* p) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p));
}

// an interface: its methods' thunks in vtable order, its base (a proxy of a derived interface
// serves a base's caller), its IID (QueryInterface's); the 4-byte vtable made on first use
struct Type32 {
    const char* name;
    const GUID* iid;
    Type32* base;
    void* const* thunks;
    unsigned count;
    uint32_t vtbl;
};

// what the reference holds: its first word the vtable it calls through
struct Proxy32 {
    uint32_t vtbl;
    uint32_t magic;
    void* native;
    Type32* type;
};
constexpr uint32_t kProxyMagic = 0x32334f43;   // "CO32"

// the proxy of a native object (the one it already has: the reference compares the pointers it is
// handed), 0 for none. It takes no reference of its own
uint32_t Wrap(void* native, Type32* type);
// the native object of a proxy the reference passes (0 for 0)
void* Unwrap(uint32_t proxy);
// the type of an IID, IUnknown's for one without a proxy of its own
Type32* TypeOf(uint32_t riid);
// a native method by vtable index
inline void* Slot(void* native, unsigned k) {
    return (*static_cast<void***>(native))[k];
}
// a method not given to the reference yet: logged, E_NOTIMPL
unsigned int Unsupported(const char* what);

// a float argument as the translation passes it: a double where the call's argument was a float
// (an unprototyped call promotes it; the integer register holds it too), the float's own bits where
// it was a 32-bit word. A promoted float's low 29 mantissa bits are 0; a 32-bit word's upper half
// in a stack slot is whatever was there
inline float Float32(uint64_t raw) {
    float f;
    if ((raw >> 32) && (raw & 0x1fffffffu) == 0) {
        double d;
        memcpy(&d, &raw, 8);
        f = static_cast<float>(d);
    } else {
        uint32_t bits = static_cast<uint32_t>(raw);
        memcpy(&f, &bits, 4);
    }
    return f;
}
// a handle the reference holds, sign-extended (INVALID_HANDLE_VALUE, the pseudo-handles)
inline void* Handle32(uint32_t h) {
    return reinterpret_cast<void*>(static_cast<intptr_t>(static_cast<int32_t>(h)));
}
// a module the reference names: its own image is the port's executable to Windows
void* Instance32(uint32_t h);

extern Type32* const kTypes[];

}  // namespace com32
