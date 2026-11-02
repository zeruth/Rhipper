// dshow32/dshow.cpp's filter graph hosted on Windows x64 (dshow32/dshow_host.h). runtime32 gives the
// reference the system's COM objects behind proxies (Com32.h), but DirectShow's would take the
// reference's own renderer filter in, and a 4-byte-vtable filter is nothing quartz can call: the
// graph is the runtime's own here too, CoCreateInstance's (Com32.cpp) for CLSID_FilterGraph and
// CLSID_DMOWrapperFilter. Its heads are as Adapters.cpp's IMalloc (a 4-byte vtable of the
// runtime's functions, the port linked below 2 GB), the reference's methods called as Com32.cpp
// calls them, the movie decoded by Media Foundation (DShowMediaFoundation.cpp), the audio on a
// WASAPI shared-mode stream.
#include <windows.h>
#include <audioclient.h>
#include <mmdeviceapi.h>
#include <mmreg.h>

#include <algorithm>
#include <cstdarg>
#include <mutex>

#include "../dshow32/dshow_host.h"

extern "C" const unsigned int g_genThiscall[];   // jumps.c, sorted
extern "C" const unsigned int g_genThiscallCount;

namespace rh::dshow {

std::unique_ptr<MovieDecoder> OpenMediaFoundation(const std::wstring& path);   // DShowMediaFoundation.cpp

namespace {

constexpr uint32_t kMagic = 0x57485344;   // "DSHW"

struct Head {
    uint32_t vtbl;
    uint32_t magic;
    void* native;
};

uint32_t Low(const void* p) { return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p)); }

std::wstring Wide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}
std::string Utf8(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n > 0 ? n - 1 : 0), '\0');
    if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

struct ThreadStart {
    void (*fn)(void*);
    void* arg;
};
// (the multithreaded apartment, as quartz's streaming threads: Media Foundation's reader is read there)
DWORD WINAPI ThreadMain(LPVOID p) {
    ThreadStart s = *static_cast<ThreadStart*>(p);
    delete static_cast<ThreadStart*>(p);
    HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    s.fn(s.arg);
    if (SUCCEEDED(co)) CoUninitialize();
    return 0;
}

}  // namespace

// a vtable of 4-byte slots for the runtime's functions (Adapters.cpp's Vtable32)
uint32_t Vtable(const void* const* methods, unsigned n) {
    auto v = static_cast<uint32_t*>(HeapAlloc(GetProcessHeap(), 0, n * 4));
    for (unsigned k = 0; k < n; k++) v[k] = Low(methods[k]);
    return Low(v);
}
uint32_t NewObject(uint32_t vtbl, void* native) {
    auto o = static_cast<Head*>(HeapAlloc(GetProcessHeap(), 0, sizeof(Head)));
    o->vtbl = vtbl;
    o->magic = kMagic;
    o->native = native;
    return Low(o);
}
void FreeObject(uint32_t obj) {
    if (!obj) return;
    auto o = At<Head>(obj);
    o->magic = 0;
    o->native = nullptr;
}
void* Native(uint32_t obj) {
    if (!obj) return nullptr;
    auto o = At<Head>(obj);
    return o->magic == kMagic ? o->native : nullptr;
}

// (the reference's entry points jump to their translations: Main.cpp, Com32.cpp's CallRef)
void* Code(uint32_t fn) { return At(fn); }
bool Thiscall(uint32_t fn) { return std::binary_search(g_genThiscall, g_genThiscall + g_genThiscallCount, fn); }

// (at least 4 MB reserved, as the reference's own threads: Adapters.cpp's CreateThread)
bool StartThread(void (*fn)(void*), void* arg) {
    auto s = new ThreadStart{fn, arg};
    HANDLE h = CreateThread(nullptr, 8u << 20, ThreadMain, s, STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    if (!h) {
        delete s;
        return false;
    }
    CloseHandle(h);
    return true;
}
// (a window handle the reference holds, sign-extended as Com32.h's Handle32)
void PostToWindow(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    PostMessageW(reinterpret_cast<HWND>(static_cast<intptr_t>(static_cast<int32_t>(hwnd))), msg, wp, lp);
}

uint32_t TaskAlloc(uint32_t n) { return Low(CoTaskMemAlloc(n)); }
uint32_t LowAlloc(uint32_t size) { return Low(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)); }
void LowFree(uint32_t at, uint32_t) {
    if (at) VirtualFree(At(at), 0, MEM_RELEASE);
}
uint32_t LowNew(uint32_t size) { return Low(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)); }

// (the reference's paths are Windows' own: made absolute against the current directory it set)
std::string HostFile(const char16_t* windows) {
    auto w = reinterpret_cast<const wchar_t*>(windows);
    wchar_t full[MAX_PATH * 2];
    DWORD n = GetFullPathNameW(w, MAX_PATH * 2, full, nullptr);
    return Utf8(n && n < MAX_PATH * 2 ? full : w);
}
FILE* OpenFile(const std::string& hostPath) {
    FILE* f = nullptr;
    return _wfopen_s(&f, Wide(hostPath).c_str(), L"rb") == 0 ? f : nullptr;
}
std::unique_ptr<MovieDecoder> OpenDecoder(const std::string& hostPath) {
    if (auto d = OpenMediaFoundation(Wide(hostPath))) return d;
    return OpenFfmpeg(hostPath);
}

// (the runtime's log: stderr, the project's name first, a line at once)
void Log(const char* fmt, ...) {
    char line[1024];
    int k = snprintf(line, sizeof line, "%s: ", RHIPPER_NAME);
    va_list a;
    va_start(a, fmt);
    vsnprintf(line + k, sizeof line - static_cast<size_t>(k) - 1, fmt, a);
    va_end(a);
    fprintf(stderr, "%s\n", line);
    fflush(stderr);
}

namespace {

// a WASAPI shared-mode stream of float stereo at kAudioRate (the engine converting to its mix format),
// opened on the graph's audio thread, its own apartment there
class WasapiOut : public AudioOut {
public:
    ~WasapiOut() override { Close(); }
    bool Open() override {
        std::lock_guard<std::mutex> hold(lock);
        if (client) return true;
        HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        IMMDeviceEnumerator* en = nullptr;
        IMMDevice* dev = nullptr;
        HRESULT hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator),
                                      reinterpret_cast<void**>(&en));
        if (SUCCEEDED(hr)) hr = en->GetDefaultAudioEndpoint(eRender, eConsole, &dev);
        if (SUCCEEDED(hr)) hr = dev->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, reinterpret_cast<void**>(&client));
        if (dev) dev->Release();
        if (en) en->Release();
        if (SUCCEEDED(hr)) {
            // KSDATAFORMAT_SUBTYPE_IEEE_FLOAT
            static const GUID kFloat = {0x00000003, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71}};
            WAVEFORMATEXTENSIBLE f = {};
            f.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
            f.Format.nChannels = 2;
            f.Format.nSamplesPerSec = kAudioRate;
            f.Format.wBitsPerSample = 32;
            f.Format.nBlockAlign = 8;
            f.Format.nAvgBytesPerSec = kAudioRate * 8;
            f.Format.cbSize = sizeof f - sizeof f.Format;
            f.Samples.wValidBitsPerSample = 32;
            f.dwChannelMask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT;
            f.SubFormat = kFloat;
            hr = client->Initialize(AUDCLNT_SHAREMODE_SHARED,
                                    AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
                                    2000000 /* 200 ms */, 0, &f.Format, nullptr);
        }
        if (SUCCEEDED(hr)) hr = client->GetBufferSize(&frames);
        if (SUCCEEDED(hr)) hr = client->GetService(__uuidof(IAudioRenderClient), reinterpret_cast<void**>(&render));
        if (FAILED(hr)) {
            Log("DirectShow: no audio stream (WASAPI %#lx)", static_cast<unsigned long>(hr));
            if (client) client->Release();
            client = nullptr;
            if (SUCCEEDED(co)) CoUninitialize();
            return false;
        }
        apartment = SUCCEEDED(co);
        if (!paused) client->Start();
        return true;
    }
    void Close() override {
        std::lock_guard<std::mutex> hold(lock);
        if (!client) return;
        client->Stop();
        render->Release();
        client->Release();
        render = nullptr;
        client = nullptr;
        if (apartment) CoUninitialize();
        apartment = false;
    }
    // (as AAudio's write with its timeout: 200 ms without room, the rest dropped, so a paused
    // stream never holds the audio thread past a Stop)
    void Write(const float* f, uint32_t n) override {
        DWORD stalled = 0;
        while (n) {
            UINT32 room = 0;
            {
                std::lock_guard<std::mutex> hold(lock);
                if (!client) return;
                UINT32 padding = 0;
                if (FAILED(client->GetCurrentPadding(&padding))) return;
                room = std::min<UINT32>(frames - padding, n);
                BYTE* d = nullptr;
                if (room && SUCCEEDED(render->GetBuffer(room, &d))) {
                    memcpy(d, f, room * 8u);
                    render->ReleaseBuffer(room, 0);
                    f += room * 2;
                    n -= room;
                } else {
                    room = 0;
                }
            }
            if (room) {
                stalled = 0;
            } else {
                if ((stalled += 5) > 200) return;
                Sleep(5);
            }
        }
    }
    void Pause(bool p) override {
        std::lock_guard<std::mutex> hold(lock);
        paused = p;
        if (!client) return;
        if (p) client->Stop();
        else client->Start();
    }

private:
    std::mutex lock;
    IAudioClient* client = nullptr;
    IAudioRenderClient* render = nullptr;
    UINT32 frames = 0;
    bool paused = false, apartment = false;
};

}  // namespace

std::unique_ptr<AudioOut> NewAudioOut() { return std::make_unique<WasapiOut>(); }

}  // namespace rh::dshow
