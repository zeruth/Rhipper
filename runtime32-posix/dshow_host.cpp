// dshow32/dshow.cpp's filter graph hosted here (dshow32/dshow_host.h): its objects the runtime's COM
// heads (Com32Posix.h), the reference's methods called through their translations, the streaming
// thread a low thread, the movie decoded by FFmpeg when the build has it, the audio on AAudio.
#include <aaudio/AAudio.h>

#include <cstdarg>

#include "../dshow32/dshow_host.h"
#include "Com32Posix.h"

namespace rh {

bool PostMessage32(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp);   // user32.cpp

namespace dshow {

uint32_t Vtable(const void* const* methods, unsigned n) { return com::Vtable(methods, n); }
uint32_t NewObject(uint32_t vtbl, void* native) { return com::NewObject(vtbl, native); }
void FreeObject(uint32_t obj) { com::FreeObject(obj); }
// (not com::NativeOf, which logs a foreign object: the graph asks of the reference's own filters)
void* Native(uint32_t obj) {
    if (!obj) return nullptr;
    auto o = At<com::Object32>(obj);
    return o->magic == com::kMagic ? o->native : nullptr;
}

void* Code(uint32_t fn) {
    void* port = PortOf(fn);
    return port ? port : At(fn);
}
bool Thiscall(uint32_t fn) { return GenThiscall(fn); }

bool StartThread(void (*fn)(void*), void* arg) {
    uint32_t tid = 0;
    uint32_t h = StartLowThread(fn, arg, 8u << 20, false, &tid);
    if (!h) return false;
    CloseHandle32(h);
    return true;
}
void PostToWindow(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) { PostMessage32(hwnd, msg, wp, lp); }

uint32_t TaskAlloc(uint32_t n) { return HeapAllocIn(ProcessHeap(), 0, n); }
uint32_t LowAlloc(uint32_t size) { return rh::LowAlloc(size); }
void LowFree(uint32_t at, uint32_t size) { rh::LowFree(at, size); }
uint32_t LowNew(uint32_t size) { return Low(rh::LowNew(size)); }

std::string HostFile(const char16_t* windows) { return HostPath16(windows); }
FILE* OpenFile(const std::string& hostPath) { return fopen(hostPath.c_str(), "rb"); }
std::unique_ptr<MovieDecoder> OpenDecoder(const std::string& hostPath) { return OpenFfmpeg(hostPath); }

void Log(const char* fmt, ...) {
    char line[1024];
    va_list a;
    va_start(a, fmt);
    vsnprintf(line, sizeof line, fmt, a);
    va_end(a);
    rh::Log("%s", line);
}

namespace {

// an AAudio stream of float stereo at kAudioRate
class AAudioOut : public AudioOut {
public:
    ~AAudioOut() override { Close(); }
    bool Open() override {
        std::lock_guard<std::mutex> hold(lock);
        if (stream) return true;
        AAudioStreamBuilder* b = nullptr;
        if (AAudio_createStreamBuilder(&b) != AAUDIO_OK) return false;
        AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_FLOAT);
        AAudioStreamBuilder_setChannelCount(b, 2);
        AAudioStreamBuilder_setSampleRate(b, static_cast<int32_t>(kAudioRate));
        AAudioStreamBuilder_setPerformanceMode(b, AAUDIO_PERFORMANCE_MODE_NONE);
        aaudio_result_t r = AAudioStreamBuilder_openStream(b, &stream);
        AAudioStreamBuilder_delete(b);
        if (r != AAUDIO_OK) {
            Log("DirectShow: no audio stream (AAudio %d)", r);
            stream = nullptr;
            return false;
        }
        if (!paused) AAudioStream_requestStart(stream);
        return true;
    }
    void Close() override {
        std::lock_guard<std::mutex> hold(lock);
        if (!stream) return;
        AAudioStream_requestStop(stream);
        AAudioStream_close(stream);
        stream = nullptr;
    }
    // (the stream only closed on this thread, Write's: no lock across the blocking write)
    void Write(const float* f, uint32_t frames) override {
        if (stream) AAudioStream_write(stream, f, static_cast<int32_t>(frames), 200000000);
    }
    void Pause(bool p) override {
        std::lock_guard<std::mutex> hold(lock);
        paused = p;
        if (!stream) return;
        if (p) AAudioStream_requestPause(stream);
        else AAudioStream_requestStart(stream);
    }

private:
    std::mutex lock;
    AAudioStream* stream = nullptr;
    bool paused = false;
};

}  // namespace

std::unique_ptr<AudioOut> NewAudioOut() { return std::make_unique<AAudioOut>(); }

}  // namespace dshow
}  // namespace rh
