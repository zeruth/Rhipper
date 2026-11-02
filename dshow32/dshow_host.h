// What dshow.cpp's filter graph needs of the runtime that hosts it: one header, each runtime its own
// implementation of it (runtime32/DShowHost.cpp on Windows x64, runtime32-posix/dshow_host.cpp on
// Android). The graph is the runtime's own on both: runtime32 proxies the system's COM objects, but
// the reference's renderer filter would need a native face for every DirectShow interface it hands
// the system (IBaseFilter, IPin, IMemInputPin, IMediaSample...), so DirectShow is emulated there too.
//
// The memory model is both runtimes': everything the reference is handed below 2 GB, a 4-byte slot
// holding any address of it.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

#include "dshow_decoder.h"

#if defined(__GNUC__) || defined(__clang__)
#define RH_DSHOW_PRINTF(f, a) __attribute__((format(printf, f, a)))
#else
#define RH_DSHOW_PRINTF(f, a)
#endif

namespace rh::dshow {

// ---- addresses ----------------------------------------------------------------------------------
template <typename T = void>
inline T* At(uint32_t address) {
    return reinterpret_cast<T*>(static_cast<uintptr_t>(address));
}
inline uint32_t U32(uint32_t a) { return *At<uint32_t>(a); }

// ---- objects the reference holds: { vtbl, magic, native } below 2 GB --------------------------------
// a vtable of `n` methods (each `uint32_t (uint32_t self, uint32_t...)`, the reference's words), below
// 2 GB, made once per interface
uint32_t Vtable(const void* const* methods, unsigned n);
uint32_t NewObject(uint32_t vtbl, void* native);
// (the head kept, marked dead: a call through it after finds no native object)
void FreeObject(uint32_t obj);
// the native object behind a head of ours; nullptr for 0, a freed head, or the reference's own object
void* Native(uint32_t obj);

// ---- the reference's code -----------------------------------------------------------------------
// the native code a reference function's address runs (its translation)
void* Code(uint32_t fn);
// whether the reference's function at fn is a __thiscall one in the gen (translate32's g_genThiscall)
bool Thiscall(uint32_t fn);
// a method of an object of the reference's, slot k of its 4-byte vtable, `this` first (__stdcall, as
// COM calls it). One the gen has as __thiscall, a method that leaves ecx alone and reads its object
// from the stack, takes ecx first: the object there too, and on the stack as COM puts it (both
// runtimes' CallMethod the same)
template <typename... A>
uint32_t CallMethod(uint32_t obj, unsigned k, A... args) {
    const uint32_t fn = At<uint32_t>(U32(obj))[k];
    auto call = [fn](auto... w) {
        using F = uint32_t (*)(decltype(static_cast<uint32_t>(w))...);
        return reinterpret_cast<F>(Code(fn))(static_cast<uint32_t>(w)...);
    };
    if (Thiscall(fn)) return call(obj, obj, args...);
    return call(obj, args...);
}

// a thread that may run the reference's code (the streaming thread: the renderer's Receive); false
// when not started. Its handle the runtime's to close
bool StartThread(void (*fn)(void*), void* arg);
// PostMessage to a window of the reference's (IMediaEventEx::SetNotifyWindow's)
void PostToWindow(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp);

// ---- memory -------------------------------------------------------------------------------------
// the task allocator's (CoTaskMemAlloc: the reference frees an AM_MEDIA_TYPE's pbFormat so)
uint32_t TaskAlloc(uint32_t n);
// pages below 2 GB, zeroed (a sample's buffer, a call's out-parameters); 0 when spent
uint32_t LowAlloc(uint32_t size);
void LowFree(uint32_t at, uint32_t size);
// a small structure below 2 GB the reference reads (our AM_MEDIA_TYPE, its VIDEOINFOHEADER)
uint32_t LowNew(uint32_t size);

// ---- files and the log --------------------------------------------------------------------------
// the host's file for a Windows path the reference names (UTF-16), as UTF-8
std::string HostFile(const char16_t* windows);
// that file opened for reading ("rb")
FILE* OpenFile(const std::string& hostPath);
// the runtime's best decoder for the file (FFmpeg's, Media Foundation's), nullptr for none: the
// graph falls back on the probe's (dshow.cpp)
std::unique_ptr<MovieDecoder> OpenDecoder(const std::string& hostPath);
// a line of the runtime's log
void Log(const char* fmt, ...) RH_DSHOW_PRINTF(1, 2);

// ---- the audio out: float stereo at kAudioRate --------------------------------------------------
// Open, Write and Close on the graph's audio thread; Pause from any
class AudioOut {
public:
    virtual ~AudioOut() = default;
    virtual bool Open() = 0;
    virtual void Close() = 0;
    // blocks while the device's buffer is full
    virtual void Write(const float* stereo, uint32_t frames) = 0;
    virtual void Pause(bool paused) = 0;
};
std::unique_ptr<AudioOut> NewAudioOut();

}  // namespace rh::dshow
