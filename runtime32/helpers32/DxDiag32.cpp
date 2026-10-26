// The 32-bit DxDiag helper: DirectX's system information as a 32-bit reference sees it, for its x64
// port. The 64-bit DxDiag provider answers otherwise (the video memory past 4 GB, the 64-bit driver
// files), so the port's DxDiag objects (DxDiagBridge.cpp) ask this process, which makes each call
// on the 32-bit provider when it is asked, as the reference would. See DxDiagWire.h.
// Built as x86 (runtime32/helpers32/build32.bat), next to the port's executable.
#include <windows.h>
#include <initguid.h>   // (DxDiag's CLSID and IIDs defined here)
#include <dxdiag.h>

#include <cstdint>
#include <map>
#include <string>

#include "DxDiagWire.h"

using namespace dxdiagwire;

namespace {

HANDLE g_in, g_out;

bool Read(void* p, DWORD n) {
    auto b = static_cast<char*>(p);
    while (n) {
        DWORD got = 0;
        if (!ReadFile(g_in, b, n, &got, nullptr) || got == 0) return false;
        b += got;
        n -= got;
    }
    return true;
}

bool ReadStr(std::wstring& s) {
    uint32_t n;
    if (!Read(&n, 4)) return false;
    s.resize(n);
    return n == 0 || Read(&s[0], n * 2);
}

void Write(const void* p, DWORD n) {
    DWORD wrote;
    WriteFile(g_out, p, n, &wrote, nullptr);
}

void Reply(HRESULT hr, uint32_t count, uint16_t vt, uint64_t value, const wchar_t* s, uint32_t len) {
    char head[4 + 4 + 2 + 8 + 4];
    memcpy(head, &hr, 4);
    memcpy(head + 4, &count, 4);
    memcpy(head + 8, &vt, 2);
    memcpy(head + 10, &value, 8);
    memcpy(head + 18, &len, 4);
    Write(head, sizeof head);
    if (len) Write(s, len * 2);
}

void Reply(HRESULT hr, uint32_t count = 0) { Reply(hr, count, 0, 0, nullptr, 0); }

IDxDiagProvider* g_provider = nullptr;
std::map<std::wstring, IDxDiagContainer*> g_containers;   // by path; "" the root

}  // namespace

int wmain() {
    g_in = GetStdHandle(STD_INPUT_HANDLE);
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    HRESULT made = CoCreateInstance(CLSID_DxDiagProvider, nullptr, CLSCTX_INPROC_SERVER, IID_IDxDiagProvider,
                                    reinterpret_cast<void**>(&g_provider));
    // (the first reply: how CoCreateInstance went)
    Reply(made);
    if (FAILED(made)) return 1;
    for (;;) {
        uint32_t op, a, b;
        std::wstring path, name;
        if (!Read(&op, 4) || !Read(&a, 4) || !Read(&b, 4) || !ReadStr(path) || !ReadStr(name)) break;
        if (op == kInitialize) {
            DXDIAG_INIT_PARAMS p = {};
            p.dwSize = sizeof p;
            p.dwDxDiagHeaderVersion = a;
            p.bAllowWHQLChecks = b;
            Reply(g_provider->Initialize(&p));
            continue;
        }
        if (op == kChild && path.empty() && name.empty()) {
            IDxDiagContainer* root = nullptr;
            HRESULT hr = g_provider->GetRootContainer(&root);
            if (SUCCEEDED(hr)) {
                if (g_containers[L""]) g_containers[L""]->Release();
                g_containers[L""] = root;
            }
            Reply(hr);
            continue;
        }
        auto it = g_containers.find(path);
        if (it == g_containers.end()) {
            Reply(E_UNEXPECTED);
            continue;
        }
        IDxDiagContainer* c = it->second;
        switch (op) {
            case kChild: {
                IDxDiagContainer* child = nullptr;
                HRESULT hr = c->GetChildContainer(name.c_str(), &child);
                if (SUCCEEDED(hr)) {
                    std::wstring key = path + kSep + name;
                    if (g_containers[key]) g_containers[key]->Release();
                    g_containers[key] = child;
                }
                Reply(hr);
                break;
            }
            case kNumChildren:
            case kNumProps: {
                DWORD n = 0;
                HRESULT hr = op == kNumChildren ? c->GetNumberOfChildContainers(&n) : c->GetNumberOfProps(&n);
                Reply(hr, n);
                break;
            }
            case kEnumChild:
            case kEnumProp: {
                std::wstring buf(b ? b : 1, L'\0');
                HRESULT hr = op == kEnumChild ? c->EnumChildContainerNames(a, &buf[0], b)
                                              : c->EnumPropNames(a, &buf[0], b);
                // (the buffer as DxDiag left it, up to the caller's length: its text and terminator)
                uint32_t len = static_cast<uint32_t>(wcsnlen(buf.c_str(), b));
                Reply(hr, 0, 0, 0, buf.c_str(), b ? (len < b ? len + 1 : len) : 0);
                break;
            }
            case kGetProp: {
                VARIANT v;
                VariantInit(&v);
                HRESULT hr = c->GetProp(name.c_str(), &v);
                if (SUCCEEDED(hr) && v.vt == VT_BSTR) {
                    Reply(hr, 0, v.vt, 0, v.bstrVal ? v.bstrVal : L"", v.bstrVal ? SysStringLen(v.bstrVal) : 0);
                } else {
                    uint64_t raw = 0;
                    memcpy(&raw, &v.llVal, 8);
                    Reply(hr, 0, v.vt, raw, nullptr, 0);
                }
                VariantClear(&v);
                break;
            }
            default:
                Reply(E_NOTIMPL);
        }
    }
    for (auto& kv : g_containers)
        if (kv.second) kv.second->Release();
    g_provider->Release();
    CoUninitialize();
    return 0;
}
