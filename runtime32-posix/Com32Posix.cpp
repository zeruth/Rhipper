// COM for the reference (Com32Posix.h): the objects' heads and vtables below 2 GB, the factories a
// project registers, and ole32's, oleaut32's and shell32's functions: COM's lifetime calls, the
// task allocator, BSTRs and VARIANTs at their x86 layouts, the shell's known folders.
#include <sys/stat.h>

#include <map>
#include <mutex>
#include <string>

#include "Com32Posix.h"

namespace rh::com {

namespace {
std::mutex g_lock;
std::map<std::string, const void*>& Factories() {
    static std::map<std::string, const void*> f;
    return f;
}
}  // namespace

uint32_t Vtable(const void* const* methods, unsigned n) {
    auto v = static_cast<uint32_t*>(LowNew(n * 4));
    for (unsigned k = 0; k < n; k++) v[k] = Island(methods[k]);
    return Low(v);
}

uint32_t NewObject(uint32_t vtbl, void* native) {
    auto o = static_cast<Object32*>(LowNew(sizeof(Object32)));
    o->vtbl = vtbl;
    o->magic = kMagic;
    o->native = native;
    return Low(o);
}

// (the head kept but marked dead: a reference that calls a released object finds no native one)
void FreeObject(uint32_t obj) {
    if (!obj) return;
    auto o = At<Object32>(obj);
    o->magic = 0;
    o->native = nullptr;
}

void* NativeOf(uint32_t obj) {
    if (!obj) return nullptr;
    auto o = At<Object32>(obj);
    if (o->magic != kMagic) {
        LogOnce("com-foreign", "COM: %08x is no object of the runtime's (vtable %08x)", obj, o->vtbl);
        return nullptr;
    }
    return o->native;
}

bool SameGuid(uint32_t guid, const uint8_t (&bytes)[16]) { return guid && memcmp(At(guid), bytes, 16) == 0; }

}  // namespace rh::com

using namespace rh;
using namespace rh::com;

extern "C" {

void rhipper_com_set_factory(const char* import, const void* fn) {
    std::lock_guard<std::mutex> hold(g_lock);
    Factories()[import] = fn;
}
const void* rhipper_com_factory(const char* import) {
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = Factories().find(import);
    return it == Factories().end() ? nullptr : it->second;
}

}  // extern "C"

// ---- the runtime's built-in objects (d3d9_null.cpp, dinput8.cpp) and the imports that make them ----
namespace rh {
uint32_t NullDirect3DCreate9(uint32_t sdk);
uint32_t DinputCreate(uint32_t version, uint32_t riid, uint32_t out);
bool IsDirectInput8Class(uint32_t clsid);
}  // namespace rh

extern "C" {

unsigned int gen_imp_Direct3DCreate9(uint32_t sdk) {
    if (auto f = reinterpret_cast<uint32_t (*)(uint32_t)>(const_cast<void*>(rhipper_com_factory("Direct3DCreate9")))) return f(sdk);
    return NullDirect3DCreate9(sdk);
}

unsigned int gen_imp_DirectInput8Create(uint32_t inst, uint32_t version, uint32_t riid, uint32_t out, uint32_t outer) {
    if (auto f = reinterpret_cast<uint32_t (*)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)>(
            const_cast<void*>(rhipper_com_factory("DirectInput8Create"))))
        return f(inst, version, riid, out, outer);
    return DinputCreate(version, riid, out);
}

// CoCreateInstance: DirectInput 8's class (the same object DirectInput8Create makes), or a project's
// factory "CoCreateInstance"; any other class refused, as on a system without it
unsigned int gen_imp_CoCreateInstance(uint32_t clsid, uint32_t outer, uint32_t context, uint32_t riid, uint32_t out) {
    if (auto f = reinterpret_cast<uint32_t (*)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)>(
            const_cast<void*>(rhipper_com_factory("CoCreateInstance")))) {
        uint32_t hr = f(clsid, outer, context, riid, out);
        if (hr != win::REGDB_E_CLASSNOTREG) return hr;
    }
    if (IsDirectInput8Class(clsid)) return DinputCreate(0x800, riid, out);
    Log("COM: CoCreateInstance of %s refused (no such class here)", HexGuid(clsid).c_str());
    if (out) *At<uint32_t>(out) = 0;
    return win::REGDB_E_CLASSNOTREG;
}
unsigned int gen_imp_CoGetClassObject(uint32_t clsid, uint32_t, uint32_t, uint32_t, uint32_t out) {
    Log("COM: CoGetClassObject of %s refused", HexGuid(clsid).c_str());
    if (out) *At<uint32_t>(out) = 0;
    return win::REGDB_E_CLASSNOTREG;
}

// ---- VARIANT, x86's 16 bytes: vt, three reserved words, the 8-byte value -----------------------
unsigned int gen_imp_VariantInit(uint32_t p) {
    if (p) memset(At(p), 0, 16);
    return 0;
}
unsigned int gen_imp_VariantClear(uint32_t p) {
    if (!p) return win::E_INVALIDARG;
    uint16_t vt = *At<uint16_t>(p);
    uint32_t v = U32(p + 8);
    if (vt == 8 /* VT_BSTR */ && v) HeapFreeIn(ProcessHeap(), 0, v - 4);
    if ((vt == 13 || vt == 9) && v) CallMethod(v, 2);   // VT_UNKNOWN, VT_DISPATCH: Release
    memset(At(p), 0, 16);
    return win::S_OK;
}

// ---- the shell's allocator (IMalloc) and known folders --------------------------------------------
}  // extern "C"

namespace {
uint32_t Malloc_QueryInterface(uint32_t, uint32_t, uint32_t out) {
    if (out) *At<uint32_t>(out) = 0;
    return win::E_NOINTERFACE;
}
uint32_t Malloc_AddRef(uint32_t) { return 1; }
uint32_t Malloc_Release(uint32_t) { return 1; }
uint32_t Malloc_Alloc(uint32_t, uint32_t cb) { return HeapAllocIn(ProcessHeap(), 0, cb); }
uint32_t Malloc_Realloc(uint32_t, uint32_t pv, uint32_t cb) {
    const ApiEntry* re = FindApi("HeapReAlloc");
    return static_cast<uint32_t>(re->real(ProcessHeap(), 0, pv, cb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}
uint32_t Malloc_Free(uint32_t, uint32_t pv) { return HeapFreeIn(ProcessHeap(), 0, pv), 0; }
uint32_t Malloc_GetSize(uint32_t, uint32_t pv) {
    const ApiEntry* size = FindApi("HeapSize");
    return static_cast<uint32_t>(size->real(ProcessHeap(), 0, pv, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}
uint32_t Malloc_DidAlloc(uint32_t, uint32_t) { return 0xFFFFFFFFu; }
uint32_t Malloc_HeapMinimize(uint32_t) { return 0; }

uint32_t ShellMalloc() {
    static uint32_t obj = 0;
    static std::once_flag once;
    std::call_once(once, [] {
        const void* fns[] = {reinterpret_cast<const void*>(Malloc_QueryInterface), reinterpret_cast<const void*>(Malloc_AddRef),
                             reinterpret_cast<const void*>(Malloc_Release), reinterpret_cast<const void*>(Malloc_Alloc),
                             reinterpret_cast<const void*>(Malloc_Realloc), reinterpret_cast<const void*>(Malloc_Free),
                             reinterpret_cast<const void*>(Malloc_GetSize), reinterpret_cast<const void*>(Malloc_DidAlloc),
                             reinterpret_cast<const void*>(Malloc_HeapMinimize)};
        obj = NewObject(Vtable(fns, 9), nullptr);
    });
    return obj;
}

// A known folder's item list: the shell's opaque PIDL, here {cb, "RHPL", the UTF-16 path} then a
// zero cb, which SHGetPathFromIDListW reads back
const char* FolderPath(uint32_t csidl) {
    switch (csidl & 0xFF) {
        case 0x00: case 0x10: return "C:\\Users\\Player\\Desktop";
        case 0x05: return "C:\\Users\\Player\\Documents";                 // CSIDL_PERSONAL
        case 0x1a: return "C:\\Users\\Player\\AppData\\Roaming";          // CSIDL_APPDATA
        case 0x1c: return "C:\\Users\\Player\\AppData\\Local";            // CSIDL_LOCAL_APPDATA
        case 0x23: return "C:\\ProgramData";                              // CSIDL_COMMON_APPDATA
        case 0x2e: return "C:\\Users\\Public\\Documents";                 // CSIDL_COMMON_DOCUMENTS
        case 0x24: return "C:\\Windows";
        case 0x25: case 0x29: return "C:\\Windows\\system32";
        case 0x26: case 0x2a: return "C:\\Program Files (x86)";
        case 0x28: return "C:\\Users\\Player";
        case 0x14: return "C:\\Windows\\Fonts";
        default: return nullptr;
    }
}
}  // namespace

extern "C" {

unsigned int gen_imp_SHGetMalloc(uint32_t out) {
    *At<uint32_t>(out) = ShellMalloc();
    return win::S_OK;
}

unsigned int gen_imp_SHGetSpecialFolderLocation(uint32_t, uint32_t folder, uint32_t out) {
    const char* path = FolderPath(folder);
    if (!path) {
        Log("SHGetSpecialFolderLocation(%#x): not known", folder);
        if (out) *At<uint32_t>(out) = 0;
        return win::E_INVALIDARG;
    }
    std::u16string w = Widen(path);
    uint32_t cb = static_cast<uint32_t>(2 + 4 + (w.size() + 1) * 2);
    uint32_t p = HeapAllocIn(ProcessHeap(), 8, cb + 2);
    *At<uint16_t>(p) = static_cast<uint16_t>(cb);
    memcpy(At(p + 2), "RHPL", 4);
    memcpy(At(p + 6), w.c_str(), (w.size() + 1) * 2);
    // (the folder made in the game directory, as a user's profile has it)
    std::string host = HostPath(path, true);
    for (size_t k = GameRoot().size() + 1; k <= host.size(); k++)
        if (k == host.size() || host[k] == '/') mkdir(host.substr(0, k).c_str(), 0755);
    *At<uint32_t>(out) = p;
    return win::S_OK;
}

}  // extern "C"

static uint32_t SHGetPathFromIDListW_(uint32_t pidl, uint32_t out) {
    if (!pidl || memcmp(At(pidl + 2), "RHPL", 4) != 0) return 0;
    const char16_t* p = At<char16_t>(pidl + 6);
    memcpy(At(out), p, (Len16(p) + 1) * 2);
    return 1;
}
RH_REG(SHELL32, SHGetPathFromIDListW, SHGetPathFromIDListW_)

// ---- COM's lifetime: one apartment, nothing to load or unload ----------------------------------------
static uint32_t CoInitialize_(uint32_t) { return win::S_OK; }
RH_REG(ole32, CoInitialize, CoInitialize_)
static uint32_t CoInitializeEx_(uint32_t, uint32_t) { return win::S_OK; }
RH_REG(ole32, CoInitializeEx, CoInitializeEx_)
static uint32_t CoUninitialize_() { return 0; }
RH_REG(ole32, CoUninitialize, CoUninitialize_)
static uint32_t CoFreeUnusedLibraries_() { return 0; }
RH_REG(ole32, CoFreeUnusedLibraries, CoFreeUnusedLibraries_)
static uint32_t CoSetProxyBlanket_(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {
    return win::S_OK;
}
RH_REG(ole32, CoSetProxyBlanket, CoSetProxyBlanket_)
static uint32_t OleInitialize_(uint32_t) { return win::S_OK; }
RH_REG(ole32, OleInitialize, OleInitialize_)
static uint32_t OleUninitialize_() { return 0; }
RH_REG(ole32, OleUninitialize, OleUninitialize_)

// ---- BSTR: a 4-byte byte length before the UTF-16, zero-terminated, in the process heap ---------------
static uint32_t SysAllocString_(uint32_t s) {
    if (!s) return 0;
    size_t n = Len16(At<char16_t>(s));
    uint32_t p = HeapAllocIn(ProcessHeap(), 0, static_cast<uint32_t>(4 + n * 2 + 2));
    if (!p) return 0;
    *At<uint32_t>(p) = static_cast<uint32_t>(n * 2);
    memcpy(At(p + 4), At(s), n * 2 + 2);
    return p + 4;
}
RH_REG(OLEAUT32, SysAllocString, SysAllocString_)
static uint32_t SysFreeString_(uint32_t b) { return b ? HeapFreeIn(ProcessHeap(), 0, b - 4), 0 : 0; }
RH_REG(OLEAUT32, SysFreeString, SysFreeString_)
static uint32_t SysStringLen_(uint32_t b) { return b ? U32(b - 4) / 2 : 0; }
RH_REG(OLEAUT32, SysStringLen, SysStringLen_)
