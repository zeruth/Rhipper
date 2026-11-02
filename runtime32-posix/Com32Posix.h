// COM objects for the reference, implemented natively: the posix counterpart of runtime32/Com32.h.
// On Windows the reference's COM objects are the system's (Direct3D 9, DirectInput 8, XAudio2)
// behind proxies; here there is no system to wrap, so each object is the runtime's or the project's
// own C++ object, given to the reference as an x86 COM object:
//
//     the object, below 2 GB:  { vtbl (4 bytes), magic, native (8 bytes) }
//     its vtable, below 2 GB:  4-byte slots, each a method taking the reference's words, `this` first
//
// The reference calls slot k as `((code *)vtbl[k])(this, args...)`: a method is a plain function
// `uint32_t (uint32_t self, uint32_t a1, ...)` (the port's .so is below 2 GB, so its address fits a
// slot; a function above goes through a low island). A float argument arrives as its 32-bit pattern
// in an integer word, counted among the others: the translation passes it gen_fl2bits(x) (Clear's Z,
// SetNPatchMode, XAudio2's SetVolume and SetFrequencyRatio), so declare it uint32_t and read it back
// with a memcpy (d3d9vk's AsFloat, xaudio2's Bits); never `double`, which AArch64 would take from a
// floating-point register the caller never set, and every word after it one off. A float result is
// read as the gen's gen_fcode, a double in d0: a method returning one would be declared `double`
// (none the reference calls does).
//
// The seam for a project's renderer: rhipper_com_set_factory("Direct3DCreate9", fn) before the run
// (from the project's own code in the port's library, a static constructor for one) replaces the
// runtime's null renderer, d3d9_null.cpp. The same for "DirectInput8Create" and any import the
// runtime makes objects for.
#pragma once

#include <cstdint>
#include <type_traits>

#include "Runtime.h"

extern "C" {
// a factory for an import that makes COM objects, by the import's name; called with the import's own
// words, returning its own result (Direct3DCreate9: uint32_t (*)(uint32_t sdk) -> the IDirect3D9)
void rhipper_com_set_factory(const char* import, const void* fn);
const void* rhipper_com_factory(const char* import);
// the host's surface for a renderer: an ANativeWindow* and its size, held until rhipper_window_done
// (the host's surface change waits for it). NULL while there is none
void* rhipper_window_use(int* width, int* height);
void rhipper_window_done(void* window);
}

namespace rh::com {

constexpr uint32_t kMagic = 0x58494f43;   // "COIX"

struct Object32 {
    uint32_t vtbl;
    uint32_t magic;
    void* native;
};
static_assert(sizeof(Object32) == 16, "a COM object's head");

// a vtable of `n` methods, below 2 GB, made once per interface
uint32_t Vtable(const void* const* methods, unsigned n);
// an object the reference holds: its head below 2 GB, its native C++ object anywhere
uint32_t NewObject(uint32_t vtbl, void* native);
void FreeObject(uint32_t obj);
// the native object behind one (nullptr for 0 or one that is not the runtime's)
void* NativeOf(uint32_t obj);
template <typename T>
T* As(uint32_t obj) {
    return static_cast<T*>(NativeOf(obj));
}

// Method<&C::M>: a vtable entry calling member M of the native object, each word as the member's
// parameter type (uint32_t, int32_t, or double for a float), its result as the reference's word
template <auto M>
struct Method;
template <class C, class R, class... A, R (C::*M)(A...)>
struct Method<M> {
    static uint32_t Call(uint32_t self, A... a) {
        C* o = As<C>(self);
        if constexpr (std::is_void_v<R>) {
            (o->*M)(a...);
            return 0;
        } else {
            return static_cast<uint32_t>((o->*M)(a...));
        }
    }
};
template <auto M>
inline const void* M_() {
    return reinterpret_cast<const void*>(&Method<M>::Call);
}

// (Runtime.h's: whether the reference's function at fn is a __thiscall one in the gen)
using rh::GenThiscall;

// a reference object's method, slot k of its 4-byte vtable, `this` first (__stdcall, as COM calls it:
// an object the reference implements and hands over, a callback interface). One the gen has as
// __thiscall, a method that leaves ecx alone and reads its object from the stack, takes ecx first:
// the object there too, and on the stack as COM puts it (runtime32's Com32.cpp the same; without it
// XAudio2's voice callbacks read their object from the next word, FFXIV's 0xcf6ee0 through 0)
template <typename... A>
uint32_t CallMethod(uint32_t obj, unsigned k, A... args) {
    uint32_t fn = At<uint32_t>(U32(obj))[k];
    if (GenThiscall(fn)) return CallRef(fn, obj, obj, args...);
    return CallRef(fn, obj, args...);
}

// IUnknown's three for an object whose native side is refcounted by the runtime (a Refcounted)
struct Refcounted {
    uint32_t self = 0;
    volatile int refs = 1;
    virtual ~Refcounted() = default;
    uint32_t AddRef() { return static_cast<uint32_t>(__atomic_add_fetch(&refs, 1, __ATOMIC_SEQ_CST)); }
    uint32_t Release() {
        int r = __atomic_sub_fetch(&refs, 1, __ATOMIC_SEQ_CST);
        if (r == 0) {
            FreeObject(self);
            delete this;
        }
        return static_cast<uint32_t>(r < 0 ? 0 : r);
    }
};
// a GUID the reference passed equals one of ours
bool SameGuid(uint32_t guid, const uint8_t (&bytes)[16]);

}  // namespace rh::com
