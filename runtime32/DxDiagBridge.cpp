// DxDiag (DirectX's system information) as the 32-bit reference sees it. The 64-bit provider
// answers otherwise than the 32-bit one the reference loads: its video memory past 4 GB (12228 MB
// where the reference reads 4095), the 64-bit driver files. So the port's provider and containers
// are the objects below, each call made by the 32-bit helper (helpers32/DxDiag32.cpp, next to the
// executable) on its own 32-bit objects, when the reference makes it. Com32.cpp hands them to the
// reference through its DxDiag proxies like any native object.
#include <windows.h>
#include <dxdiag.h>
#include <oleauto.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>

#include "RefImage.hpp"
#include "helpers32/DxDiagWire.h"

using namespace dxdiagwire;

namespace {

const GUID kIIDProvider = {0x9c6b4cb0, 0x23f8, 0x49cc, {0xa3, 0xed, 0x45, 0xa5, 0x50, 0x00, 0xa6, 0xd2}};
const GUID kIIDContainer = {0x7d0f462f, 0x4064, 0x4862, {0xbc, 0x7f, 0x93, 0x3e, 0x50, 0x58, 0xc1, 0x0f}};

struct Answer {
    HRESULT hr = E_FAIL;
    uint32_t count = 0;
    uint16_t vt = 0;
    uint64_t value = 0;
    std::wstring text;
};

// the helper process and its two pipes; one per provider
struct Link {
    HANDLE proc = nullptr, to = nullptr, from = nullptr;
    std::mutex lock;
    bool dead = false;

    ~Link() {
        if (to) CloseHandle(to);   // (its input closed: the helper ends)
        if (from) CloseHandle(from);
        if (proc) {
            WaitForSingleObject(proc, 2000);
            CloseHandle(proc);
        }
    }

    bool Read(void* p, DWORD n) {
        auto b = static_cast<char*>(p);
        while (n) {
            DWORD got = 0;
            if (!ReadFile(from, b, n, &got, nullptr) || got == 0) return false;
            b += got;
            n -= got;
        }
        return true;
    }

    bool Receive(Answer& a) {
        char head[22];
        if (!Read(head, sizeof head)) return false;
        uint32_t len;
        memcpy(&a.hr, head, 4);
        memcpy(&a.count, head + 4, 4);
        memcpy(&a.vt, head + 8, 2);
        memcpy(&a.value, head + 10, 8);
        memcpy(&len, head + 18, 4);
        a.text.assign(len, L'\0');
        return len == 0 || Read(&a.text[0], len * 2);
    }

    Answer Ask(Op op, uint32_t x, uint32_t y, const std::wstring& path, const wchar_t* name) {
        std::lock_guard<std::mutex> hold(lock);
        Answer a;
        if (dead) return a;
        std::string msg(12, '\0');
        memcpy(&msg[0], &op, 4);
        memcpy(&msg[4], &x, 4);
        memcpy(&msg[8], &y, 4);
        for (const wchar_t* s : {path.c_str(), name ? name : L""}) {
            uint32_t n = static_cast<uint32_t>(wcslen(s));
            msg.append(reinterpret_cast<const char*>(&n), 4);
            msg.append(reinterpret_cast<const char*>(s), n * 2);
        }
        DWORD wrote;
        if (!WriteFile(to, msg.data(), static_cast<DWORD>(msg.size()), &wrote, nullptr) || !Receive(a)) {
            dead = true;
            a = Answer();
        }
        return a;
    }
};

// the helper started: its first answer how its CoCreateInstance went
HRESULT Start(Link& l) {
    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    while (n && exe[n - 1] != L'\\') n--;
    exe[n] = 0;
    wcscat_s(exe, L"DxDiag32.exe");
    SECURITY_ATTRIBUTES sa = {sizeof sa, nullptr, TRUE};
    HANDLE inR, inW, outR, outW;
    if (!CreatePipe(&inR, &inW, &sa, 0)) return E_FAIL;
    if (!CreatePipe(&outR, &outW, &sa, 0)) {
        CloseHandle(inR);
        CloseHandle(inW);
        return E_FAIL;
    }
    SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = {sizeof si};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = inR;
    si.hStdOutput = outW;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(exe, nullptr, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(inR);
    CloseHandle(outW);
    if (!ok) {
        fprintf(stderr, "%s: DxDiag: cannot start %ls (%lu)\n", RHIPPER_NAME, exe, GetLastError());
        CloseHandle(inW);
        CloseHandle(outR);
        return REGDB_E_CLASSNOTREG;
    }
    CloseHandle(pi.hThread);
    l.proc = pi.hProcess;
    l.to = inW;
    l.from = outR;
    Answer a;
    if (!l.Receive(a)) {
        l.dead = true;
        return E_FAIL;
    }
    return a.hr;
}

template <class I>
class Unknown : public I {
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG n = --refs_;
        if (n == 0) delete this;
        return n;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (IsEqualGUID(riid, IID_IUnknown) || IsEqualGUID(riid, iid_)) {
            *out = static_cast<I*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }

protected:
    explicit Unknown(const GUID& iid) : iid_(iid) {}
    virtual ~Unknown() = default;

private:
    std::atomic<ULONG> refs_{1};
    GUID iid_;
};

// the text DxDiag wrote into a caller's buffer, copied into the caller's
HRESULT Names(const Answer& a, LPWSTR buf, DWORD len) {
    if (buf && len) {
        size_t n = a.text.size() < len ? a.text.size() : len;
        if (n) memcpy(buf, a.text.data(), n * 2);
    }
    return a.hr;
}

class Container : public Unknown<IDxDiagContainer> {
public:
    Container(std::shared_ptr<Link> link, std::wstring path) : Unknown(kIIDContainer), link_(std::move(link)),
                                                               path_(std::move(path)) {}

    HRESULT STDMETHODCALLTYPE GetNumberOfChildContainers(DWORD* n) override {
        Answer a = link_->Ask(kNumChildren, 0, 0, path_, nullptr);
        if (n && SUCCEEDED(a.hr)) *n = a.count;
        return a.hr;
    }
    HRESULT STDMETHODCALLTYPE EnumChildContainerNames(DWORD index, LPWSTR buf, DWORD len) override {
        return Names(link_->Ask(kEnumChild, index, len, path_, nullptr), buf, len);
    }
    HRESULT STDMETHODCALLTYPE GetChildContainer(LPCWSTR name, IDxDiagContainer** out) override {
        if (!out) return E_INVALIDARG;
        *out = nullptr;
        if (!name) return E_INVALIDARG;
        Answer a = link_->Ask(kChild, 0, 0, path_, name);
        if (SUCCEEDED(a.hr)) *out = new Container(link_, path_ + kSep + name);
        return a.hr;
    }
    HRESULT STDMETHODCALLTYPE GetNumberOfProps(DWORD* n) override {
        Answer a = link_->Ask(kNumProps, 0, 0, path_, nullptr);
        if (n && SUCCEEDED(a.hr)) *n = a.count;
        return a.hr;
    }
    HRESULT STDMETHODCALLTYPE EnumPropNames(DWORD index, LPWSTR buf, DWORD len) override {
        return Names(link_->Ask(kEnumProp, index, len, path_, nullptr), buf, len);
    }
    HRESULT STDMETHODCALLTYPE GetProp(LPCWSTR name, VARIANT* out) override {
        if (!out || !name) return E_INVALIDARG;
        Answer a = link_->Ask(kGetProp, 0, 0, path_, name);
        if (SUCCEEDED(a.hr)) {
            VariantClear(out);
            out->vt = a.vt;
            if (a.vt == VT_BSTR) {
                out->bstrVal = SysAllocStringLen(a.text.data(), static_cast<UINT>(a.text.size()));
            } else {
                memcpy(&out->llVal, &a.value, 8);
            }
        }
        return a.hr;
    }

private:
    std::shared_ptr<Link> link_;
    std::wstring path_;
};

class Provider : public Unknown<IDxDiagProvider> {
public:
    Provider() : Unknown(kIIDProvider), link_(std::make_shared<Link>()) {}
    HRESULT Begin() { return Start(*link_); }

    HRESULT STDMETHODCALLTYPE Initialize(DXDIAG_INIT_PARAMS* p) override {
        if (!p) return E_POINTER;
        return link_->Ask(kInitialize, p->dwDxDiagHeaderVersion, p->bAllowWHQLChecks, L"", nullptr).hr;
    }
    HRESULT STDMETHODCALLTYPE GetRootContainer(IDxDiagContainer** out) override {
        if (!out) return E_INVALIDARG;
        *out = nullptr;
        Answer a = link_->Ask(kChild, 0, 0, L"", nullptr);
        if (SUCCEEDED(a.hr)) *out = new Container(link_, L"");
        return a.hr;
    }

private:
    std::shared_ptr<Link> link_;
};

}  // namespace

// CLSID_DxDiagProvider's object, interface riid of it: the 32-bit helper's, through the objects above
HRESULT DxDiagBridgeCreate(REFIID riid, void** out) {
    *out = nullptr;
    auto* p = new Provider();
    HRESULT hr = p->Begin();
    if (SUCCEEDED(hr)) hr = p->QueryInterface(riid, out);
    p->Release();
    return hr;
}

bool DxDiagBridgeClass(REFCLSID clsid) {
    static const GUID provider = {0xa65b8071, 0x3bfe, 0x4213, {0x9a, 0x5b, 0x49, 0x1d, 0xa4, 0x46, 0x1c, 0xa7}};
    return IsEqualGUID(clsid, provider) != 0;
}
