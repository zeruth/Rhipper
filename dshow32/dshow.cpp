// DirectShow for the reference: the filter graph CoCreateInstance makes for CLSID_FilterGraph and the
// DMO wrapper for CLSID_DMOWrapperFilter, so a reference that plays a movie through its own video
// renderer filter (a baseclasses CBaseVideoRenderer: FFXIV's Streaming::TextureRenderer) sees it play
// and end. The graph is the runtime's own, on Windows as on Android (dshow_host.h says why), the
// runtime's part of it behind dshow_host.h:
//
//   IGraphBuilder::AddFilter joins the reference's filters (JoinFilterGraph, its event sink ours);
//   RenderFile opens the file with a MovieDecoder (dshow_decoder.h: the runtime's, FFmpeg's or Media
//   Foundation's, else the probe's, which knows the file's size and length and decodes nothing) and
//   connects our source's output pin to the reference renderer's input pin (ReceiveConnection,
//   RGB32 bottom-up VIDEOINFOHEADER at the movie's size) with our allocator (NotifyAllocator);
//   IMediaControl's Pause / Run / Stop drive the renderer (IMediaFilter's) and our streaming thread, a
//   thread the reference's code may run on, which decodes each frame into one of our samples and
//   hands it to the renderer's IMemInputPin::Receive when the stream clock reaches it (the renderer
//   has no clock: it draws a sample as it comes), then EndOfStream: the renderer's EC_COMPLETE
//   reaches our IMediaEventSink, IMediaEventEx's queue, and the reference's window (SetNotifyWindow);
//   IMediaSeeking keeps the stream time (media time only): the position runs with the wall clock
//   while running, seeks flush the renderer and restart the stream;
//   the audio (a decoder's that decodes) plays on the runtime's AudioOut from a thread of its own,
//   IBasicAudio's volume applied here.
//   The DMO wrapper ("WMA Filter": the reference adds the audio decoder itself) is a filter with no
//   pins: our decoder does the audio.
//
// Without a decoder the movie still opens at its size and runs to its end at once: the reference
// waits on EC_COMPLETE (FFXIV's first-run opening, Global::PlayMovie, hung the lobby without it).
//
// Interfaces at their x86 vtables (strmif.h / control.h order), structures at x86 layouts:
// AM_MEDIA_TYPE 0x48 bytes (majortype, subtype, fixed, temporal, sample size, formattype at 0x2c,
// pUnk 0x3c, cbFormat 0x40, pbFormat 0x44), VIDEOINFOHEADER 88 (bmiHeader at 0x30), PIN_INFO 0x108.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdarg>
#include <deque>
#include <mutex>
#include <set>
#include <thread>
#include <type_traits>
#include <vector>

#include "dshow_host.h"

namespace rh {

namespace dshow {

namespace {

constexpr uint32_t S_OK = 0, S_FALSE = 1, E_NOTIMPL = 0x80004001u, E_NOINTERFACE = 0x80004002u,
                   E_POINTER = 0x80004003u, E_FAIL = 0x80004005u, E_INVALIDARG = 0x80070057u,
                   E_UNEXPECTED = 0x8000FFFFu, E_ABORT = 0x80004004u, VFW_E_NOT_CONNECTED = 0x80040209u,
                   VFW_E_NOT_FOUND = 0x80040216u, VFW_E_SAMPLE_TIME_NOT_SET = 0x80040249u,
                   VFW_E_MEDIA_TIME_NOT_SET = 0x80040251u, VFW_E_WRONG_STATE = 0x80040227u,
                   VFW_E_ALREADY_CONNECTED = 0x80040204u, CLASS_E_NOAGGREGATION = 0x80040110u;
constexpr uint32_t EC_COMPLETE = 1, EC_PAUSED = 0xe;
constexpr uint32_t kInfinite = 0xFFFFFFFFu;

// ---- GUIDs, as their bytes in memory ----------------------------------------------------------
struct Guid {
    uint8_t b[16];
};
constexpr int HexDigit(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }
constexpr Guid G(const char (&s)[37]) {
    Guid g{};
    const int at[16] = {6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34};
    for (int k = 0; k < 16; k++) g.b[k] = static_cast<uint8_t>(HexDigit(s[at[k]]) * 16 + HexDigit(s[at[k] + 1]));
    return g;
}
bool Is(uint32_t p, const Guid& g) { return p && memcmp(At(p), g.b, 16) == 0; }

constexpr Guid kClsidFilterGraph = G("e436ebb3-524f-11ce-9f53-0020af0ba770");
constexpr Guid kClsidFilterGraphNoThread = G("e436ebb8-524f-11ce-9f53-0020af0ba770");
constexpr Guid kClsidDmoWrapper = G("94297043-bd82-4dfd-b0de-8177739c6d20");
constexpr Guid kIidUnknown = G("00000000-0000-0000-c000-000000000046");
constexpr Guid kIidPersist = G("0000010c-0000-0000-c000-000000000046");
constexpr Guid kIidFilterGraph = G("56a8689f-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidGraphBuilder = G("56a868a9-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidFilterGraph2 = G("36b73882-c2c8-11cf-8b46-00805f6cef60");
constexpr Guid kIidMediaControl = G("56a868b1-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidMediaEvent = G("56a868b6-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidMediaEventEx = G("56a868c0-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidMediaSeeking = G("36b73880-c2c8-11cf-8b46-00805f6cef60");
constexpr Guid kIidBasicAudio = G("56a868b3-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidBasicVideo = G("56a868b5-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidMediaEventSink = G("56a868a2-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidMediaFilter = G("56a86899-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidBaseFilter = G("56a86895-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidPin = G("56a86891-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidMemInputPin = G("56a8689d-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidMemAllocator = G("56a8689c-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidMediaSample = G("56a8689a-0ad4-11ce-b03a-0020af0ba770");
constexpr Guid kIidDmoWrapperFilter = G("52d6f586-9f0f-4824-8fc8-e32ca04930c2");
constexpr Guid kIidPropertyBag = G("55272a00-42cb-11ce-8135-00aa004bb851");
constexpr Guid kTimeFormatMediaTime = G("7b785574-8c82-11cf-bc0c-00aa00ac74f6");
constexpr Guid kMediaTypeVideo = G("73646976-0000-0010-8000-00aa00389b71");
constexpr Guid kSubtypeRgb32 = G("e436eb7e-524f-11ce-9f53-0020af0ba770");
constexpr Guid kFormatVideoInfo = G("05589f80-c356-11ce-bf01-00aa0055595a");

int64_t Now100ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count() / 100;
}
void Put64(uint32_t p, int64_t v) {
    if (p) memcpy(At(p), &v, 8);
}
int64_t Get64(uint32_t p) {
    int64_t v = 0;
    if (p) memcpy(&v, At(p), 8);
    return v;
}
uint32_t Lo(int64_t v) { return static_cast<uint32_t>(static_cast<uint64_t>(v)); }
uint32_t Hi(int64_t v) { return static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32); }

// a UTF-16 string of the reference's as UTF-8, for the log
std::string NameOf(uint32_t wide) {
    if (!wide) return "(none)";
    std::string s;
    for (const char16_t* p = At<char16_t>(wide); *p; p++) {
        uint32_t c = *p;
        if (c >= 0xd800 && c < 0xdc00 && p[1] >= 0xdc00 && p[1] < 0xe000) c = 0x10000 + ((c - 0xd800) << 10) + (*++p - 0xdc00);
        if (c < 0x80) {
            s += static_cast<char>(c);
        } else if (c < 0x800) {
            s += static_cast<char>(0xc0 | (c >> 6));
            s += static_cast<char>(0x80 | (c & 0x3f));
        } else if (c < 0x10000) {
            s += static_cast<char>(0xe0 | (c >> 12));
            s += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
            s += static_cast<char>(0x80 | (c & 0x3f));
        } else {
            s += static_cast<char>(0xf0 | (c >> 18));
            s += static_cast<char>(0x80 | ((c >> 12) & 0x3f));
            s += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
            s += static_cast<char>(0x80 | (c & 0x3f));
        }
    }
    return s;
}
// an ASCII name written as UTF-16 at `at`, its terminator too
void PutWide(uint32_t at, const char* ascii) {
    char16_t* d = At<char16_t>(at);
    do *d++ = static_cast<char16_t>(*ascii);
    while (*ascii++);
}
std::string HexGuid(uint32_t p) {
    if (!p) return "(null)";
    const uint8_t* b = At<uint8_t>(p);
    char s[40];
    snprintf(s, sizeof s, "{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}", b[3], b[2], b[1], b[0],
             b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return s;
}
// once per distinct key
void LogOnce(const std::string& key, const char* fmt, ...) RH_DSHOW_PRINTF(2, 3);
void LogOnce(const std::string& key, const char* fmt, ...) {
    static std::mutex m;
    static std::set<std::string> seen;
    {
        std::lock_guard<std::mutex> hold(m);
        if (!seen.insert(key).second) return;
    }
    char line[512];
    va_list a;
    va_start(a, fmt);
    vsnprintf(line, sizeof line, fmt, a);
    va_end(a);
    Log("%s", line);
}

// a released object's call answered (E_UNEXPECTED), not made. A method takes the head it was called
// through first (the graph's interfaces are heads of one native object)
template <auto M>
struct Thunk;
template <class C, class R, class... A, R (C::*M)(uint32_t, A...)>
struct Thunk<M> {
    static uint32_t Call(uint32_t self, A... a) {
        C* o = static_cast<C*>(Native(self));
        if (!o) {
            LogOnce("dshow-released", "DirectShow: a call on %08x, an object already released", self);
            return E_UNEXPECTED;
        }
        if constexpr (std::is_void_v<R>) {
            (o->*M)(self, a...);
            return 0;
        } else {
            return static_cast<uint32_t>((o->*M)(self, a...));
        }
    }
};
template <auto M>
const void* T_() {
    return reinterpret_cast<const void*>(&Thunk<M>::Call);
}
uint32_t NotImpl(uint32_t) { return E_NOTIMPL; }
const void* const kNotImpl = reinterpret_cast<const void*>(&NotImpl);

// ---- the probe: an ASF header's size and length, nothing decoded ---------------------------------
class Probe : public MovieDecoder {
public:
    static std::unique_ptr<MovieDecoder> Open(const std::string& path) {
        FILE* f = OpenFile(path);
        if (!f) return nullptr;
        std::vector<uint8_t> d(1 << 16);
        d.resize(fread(d.data(), 1, d.size(), f));
        fclose(f);
        auto p = std::make_unique<Probe>();
        MovieInfo& i = p->info;
        i.decoder = "nothing (the probe's: it runs to its end at once)";
        constexpr Guid kHeader = G("75b22630-668e-11cf-a6d9-00aa0062ce6c");
        constexpr Guid kFileProps = G("8cabdca1-a947-11cf-8ee4-00c00c205365");
        constexpr Guid kStreamProps = G("b7dc0791-a9b7-11cf-8ee6-00c00c205365");
        constexpr Guid kVideo = G("bc19efc0-5b4d-11cf-a8fd-00805f5c442b");
        constexpr Guid kAudio = G("f8699e40-5b4d-11cf-a8fd-00805f5c442b");
        auto is = [&](size_t o, const Guid& g) { return o + 16 <= d.size() && memcmp(&d[o], g.b, 16) == 0; };
        auto u32 = [&](size_t o) { uint32_t v = 0; if (o + 4 <= d.size()) memcpy(&v, &d[o], 4); return v; };
        auto u64 = [&](size_t o) { uint64_t v = 0; if (o + 8 <= d.size()) memcpy(&v, &d[o], 8); return v; };
        if (!is(0, kHeader)) {
            i.codecs = "not ASF";
        } else {
            uint32_t count = u32(24);
            size_t o = 30;
            for (uint32_t k = 0; k < count && o + 24 <= d.size(); k++) {
                uint64_t size = u64(o + 16);
                if (size < 24) break;
                if (is(o, kFileProps)) {
                    // play duration (100 ns) less the preroll (ms)
                    int64_t play = static_cast<int64_t>(u64(o + 64)), preroll = static_cast<int64_t>(u64(o + 80));
                    i.duration = std::max<int64_t>(0, play - preroll * 10000);
                } else if (is(o, kStreamProps)) {
                    const size_t t = o + 78;
                    if (is(o + 24, kVideo)) {
                        i.hasVideo = true;
                        i.width = u32(t);
                        i.height = u32(t + 4);
                        char cc[5] = {};
                        memcpy(cc, d.data() + std::min(d.size() - 4, t + 11 + 16), 4);
                        i.codecs += std::string(i.codecs.empty() ? "" : ", ") + "video " + cc;
                    } else if (is(o + 24, kAudio)) {
                        i.hasAudio = true;
                        char buf[32];
                        snprintf(buf, sizeof buf, "audio tag %#x", u32(t) & 0xffff);
                        i.codecs += std::string(i.codecs.empty() ? "" : ", ") + buf;
                    }
                }
                o += static_cast<size_t>(size);
            }
        }
        if (!i.width || !i.height) {
            i.width = 1280;
            i.height = 720;
        }
        return p;
    }
    const MovieInfo& Info() const override { return info; }
    bool NextVideo(uint8_t*, uint32_t, int64_t*) override { return false; }
    uint32_t NextAudio(float*, uint32_t) override { return 0; }
    bool Seek(int64_t) override { return true; }

    MovieInfo info;
};

struct Graph;

// ---- a sample: a frame's buffer below 2 GB, refcounted; free again when its count is 0 --------------
struct Sample {
    Graph* graph = nullptr;
    uint32_t self = 0;
    std::atomic<int> refs{0};
    uint32_t buffer = 0, size = 0, actual = 0;
    int64_t start = 0, stop = 0;
    bool timed = false, sync = true, discontinuity = false, preroll = false;

    uint32_t QueryInterface(uint32_t, uint32_t riid, uint32_t out);
    uint32_t AddRef(uint32_t) { return static_cast<uint32_t>(++refs); }
    uint32_t Release(uint32_t);
    uint32_t GetPointer(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        *At<uint32_t>(out) = buffer;
        return S_OK;
    }
    uint32_t GetSize(uint32_t) { return size; }
    uint32_t GetTime(uint32_t, uint32_t pStart, uint32_t pEnd) {
        if (!timed) return VFW_E_SAMPLE_TIME_NOT_SET;
        Put64(pStart, start);
        Put64(pEnd, stop);
        return S_OK;
    }
    uint32_t SetTime(uint32_t, uint32_t pStart, uint32_t pEnd) {
        timed = pStart != 0;
        if (pStart) start = Get64(pStart);
        stop = pEnd ? Get64(pEnd) : start + 1;
        return S_OK;
    }
    uint32_t IsSyncPoint(uint32_t) { return sync ? S_OK : S_FALSE; }
    uint32_t SetSyncPoint(uint32_t, uint32_t b) { return sync = b != 0, S_OK; }
    uint32_t IsPreroll(uint32_t) { return preroll ? S_OK : S_FALSE; }
    uint32_t SetPreroll(uint32_t, uint32_t b) { return preroll = b != 0, S_OK; }
    uint32_t GetActualDataLength(uint32_t) { return actual; }
    uint32_t SetActualDataLength(uint32_t, uint32_t n) {
        if (n > size) return E_INVALIDARG;
        actual = n;
        return S_OK;
    }
    // (the type never changes mid-stream: S_FALSE, no type)
    uint32_t GetMediaType(uint32_t, uint32_t out) {
        if (out) *At<uint32_t>(out) = 0;
        return S_FALSE;
    }
    uint32_t SetMediaType(uint32_t, uint32_t) { return E_NOTIMPL; }
    uint32_t IsDiscontinuity(uint32_t) { return discontinuity ? S_OK : S_FALSE; }
    uint32_t SetDiscontinuity(uint32_t, uint32_t b) { return discontinuity = b != 0, S_OK; }
    uint32_t GetMediaTime(uint32_t, uint32_t, uint32_t) { return VFW_E_MEDIA_TIME_NOT_SET; }
    uint32_t SetMediaTime(uint32_t, uint32_t, uint32_t) { return S_OK; }
};

uint32_t SampleVtable() {
    static uint32_t v = 0;
    if (!v) {
        const void* m[19] = {T_<&Sample::QueryInterface>(), T_<&Sample::AddRef>(), T_<&Sample::Release>(),
                             T_<&Sample::GetPointer>(), T_<&Sample::GetSize>(), T_<&Sample::GetTime>(),
                             T_<&Sample::SetTime>(), T_<&Sample::IsSyncPoint>(), T_<&Sample::SetSyncPoint>(),
                             T_<&Sample::IsPreroll>(), T_<&Sample::SetPreroll>(),
                             T_<&Sample::GetActualDataLength>(), T_<&Sample::SetActualDataLength>(),
                             T_<&Sample::GetMediaType>(), T_<&Sample::SetMediaType>(),
                             T_<&Sample::IsDiscontinuity>(), T_<&Sample::SetDiscontinuity>(),
                             T_<&Sample::GetMediaTime>(), T_<&Sample::SetMediaTime>()};
        v = Vtable(m, 19);
    }
    return v;
}

// ---- the DMO wrapper: a filter without pins (our decoder does the audio) ---------------------------
struct Dmo {
    uint32_t filter = 0, wrapper = 0, bag = 0;
    std::atomic<int> refs{1};
    uint32_t graph = 0;
    int state = 0;

    uint32_t QueryInterface(uint32_t, uint32_t riid, uint32_t out) {
        if (!out) return E_POINTER;
        uint32_t h = 0;
        if (Is(riid, kIidUnknown) || Is(riid, kIidBaseFilter) || Is(riid, kIidMediaFilter) || Is(riid, kIidPersist))
            h = filter;
        else if (Is(riid, kIidDmoWrapperFilter)) h = wrapper;
        else if (Is(riid, kIidPropertyBag)) h = bag;
        *At<uint32_t>(out) = h;
        if (!h) return E_NOINTERFACE;
        ++refs;
        return S_OK;
    }
    uint32_t AddRef(uint32_t) { return static_cast<uint32_t>(++refs); }
    uint32_t Release(uint32_t) {
        int r = --refs;
        if (r == 0) {
            FreeObject(filter);
            FreeObject(wrapper);
            FreeObject(bag);
            delete this;
        }
        return static_cast<uint32_t>(r < 0 ? 0 : r);
    }
    uint32_t GetClassID(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        memcpy(At(out), kClsidDmoWrapper.b, 16);
        return S_OK;
    }
    uint32_t Stop(uint32_t) { return state = 0, S_OK; }
    uint32_t Pause(uint32_t) { return state = 1, S_OK; }
    uint32_t Run(uint32_t, uint32_t, uint32_t) { return state = 2, S_OK; }
    uint32_t GetState(uint32_t, uint32_t, uint32_t out) {
        if (out) *At<uint32_t>(out) = static_cast<uint32_t>(state);
        return S_OK;
    }
    uint32_t SetSyncSource(uint32_t, uint32_t) { return S_OK; }
    uint32_t GetSyncSource(uint32_t, uint32_t out) {
        if (out) *At<uint32_t>(out) = 0;
        return S_OK;
    }
    uint32_t QueryFilterInfo(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        memset(At(out), 0, 0x104);
        PutWide(out, "WMA Filter");
        *At<uint32_t>(out + 0x100) = 0;   // pGraph (would be AddRef'd)
        return S_OK;
    }
    uint32_t JoinFilterGraph(uint32_t, uint32_t g, uint32_t) { return graph = g, S_OK; }
    uint32_t Init(uint32_t, uint32_t clsid, uint32_t category) {
        Log("DirectShow: DMO wrapper for %s (category %s): our decoder does the audio", HexGuid(clsid).c_str(),
            HexGuid(category).c_str());
        return S_OK;
    }
    uint32_t Read(uint32_t, uint32_t, uint32_t, uint32_t) { return E_FAIL; }
    uint32_t Write(uint32_t, uint32_t name, uint32_t) { return Log("DirectShow: DMO property %s", NameOf(name).c_str()), S_OK; }

    static uint32_t Create(uint32_t riid, uint32_t out) {
        static uint32_t vf = 0, vw = 0, vb = 0;
        if (!vf) {
            const void* f[15] = {T_<&Dmo::QueryInterface>(), T_<&Dmo::AddRef>(), T_<&Dmo::Release>(),
                                 T_<&Dmo::GetClassID>(), T_<&Dmo::Stop>(), T_<&Dmo::Pause>(), T_<&Dmo::Run>(),
                                 T_<&Dmo::GetState>(), T_<&Dmo::SetSyncSource>(), T_<&Dmo::GetSyncSource>(),
                                 kNotImpl /* EnumPins */, kNotImpl /* FindPin */, T_<&Dmo::QueryFilterInfo>(),
                                 T_<&Dmo::JoinFilterGraph>(), kNotImpl /* QueryVendorInfo */};
            vf = Vtable(f, 15);
            const void* w[4] = {T_<&Dmo::QueryInterface>(), T_<&Dmo::AddRef>(), T_<&Dmo::Release>(), T_<&Dmo::Init>()};
            vw = Vtable(w, 4);
            const void* b[5] = {T_<&Dmo::QueryInterface>(), T_<&Dmo::AddRef>(), T_<&Dmo::Release>(), T_<&Dmo::Read>(),
                                T_<&Dmo::Write>()};
            vb = Vtable(b, 5);
        }
        auto d = new Dmo;
        d->filter = NewObject(vf, d);
        d->wrapper = NewObject(vw, d);
        d->bag = NewObject(vb, d);
        uint32_t hr = d->QueryInterface(0, riid, out);
        d->Release(0);
        return hr;
    }
};

// ---- the graph: its interfaces, our source's pin and allocator, the stream --------------------------
struct Event {
    uint32_t code, p1, p2;
};

struct Graph {
    // heads: one object per interface, all this native one
    uint32_t builder = 0, control = 0, seeking = 0, events = 0, audio = 0, video = 0, sink = 0;
    uint32_t source = 0, pin = 0, allocator = 0;
    std::atomic<int> refs{1};
    bool dying = false;

    std::mutex lock;
    std::condition_variable cv;
    std::vector<uint32_t> filters;   // AddRef'd

    // the movie and the connection to the reference's renderer
    std::unique_ptr<MovieDecoder> dec;
    MovieInfo info;
    std::string file;
    uint32_t renderer = 0, inPin = 0, memIn = 0;   // the renderer's IBaseFilter, its IPin, its IMemInputPin
    uint32_t mediaType = 0;                        // our AM_MEDIA_TYPE, below 2 GB
    std::vector<Sample*> samples;

    // the stream: state 0 stopped, 1 paused, 2 running; the stream time is segStart + elapsed, where
    // elapsed runs while running (runSince: when Run started it)
    int state = 0;
    int64_t segStart = 0, elapsed = 0, runSince = 0;
    int64_t presented = -1;   // the last frame's time the renderer took (-1: none yet this stream)
    bool ended = false;
    bool streaming = false, audioRunning = false;   // the threads alive
    std::atomic<bool> stop{false};
    int32_t volume = 0;   // IBasicAudio's, 1/100 dB
    std::unique_ptr<AudioOut> out = NewAudioOut();

    // the events
    std::deque<Event> queue;
    uint32_t notifyWindow = 0, notifyMessage = 0, notifyParam = 0;

    // ---- IUnknown (every head) ----
    uint32_t QueryInterface(uint32_t, uint32_t riid, uint32_t out) {
        if (!out) return E_POINTER;
        uint32_t h = 0;
        if (Is(riid, kIidUnknown) || Is(riid, kIidGraphBuilder) || Is(riid, kIidFilterGraph)) h = builder;
        else if (Is(riid, kIidMediaControl)) h = control;
        else if (Is(riid, kIidMediaSeeking)) h = seeking;
        else if (Is(riid, kIidMediaEventEx) || Is(riid, kIidMediaEvent)) h = events;
        else if (Is(riid, kIidBasicAudio)) h = audio;
        else if (Is(riid, kIidBasicVideo)) h = video;
        else if (Is(riid, kIidMediaEventSink)) h = sink;
        *At<uint32_t>(out) = h;
        if (!h) {
            if (!Is(riid, kIidFilterGraph2))
                LogOnce("dshow-qi-" + HexGuid(riid), "DirectShow: the graph has no %s", HexGuid(riid).c_str());
            return E_NOINTERFACE;
        }
        AddRef(0);
        return S_OK;
    }
    uint32_t AddRef(uint32_t) { return dying ? 1 : static_cast<uint32_t>(++refs); }
    uint32_t Release(uint32_t) {
        if (dying) return 1;
        int r = --refs;
        if (r == 0) Destroy();
        return static_cast<uint32_t>(r < 0 ? 0 : r);
    }
    void Destroy();

    // ---- IFilterGraph / IGraphBuilder ----
    uint32_t AddFilter(uint32_t, uint32_t filter, uint32_t name) {
        if (!filter) return E_POINTER;
        CallMethod(filter, 1);   // AddRef
        {
            std::lock_guard<std::mutex> hold(lock);
            filters.push_back(filter);
        }
        uint32_t hr = CallMethod(filter, 13, builder, name);   // JoinFilterGraph
        Log("DirectShow: graph %08x: filter %08x \"%s\" added (%#x)", builder, filter, NameOf(name).c_str(), hr);
        return S_OK;
    }
    uint32_t RemoveFilter(uint32_t, uint32_t filter) {
        {
            std::lock_guard<std::mutex> hold(lock);
            auto it = std::find(filters.begin(), filters.end(), filter);
            if (it == filters.end()) return VFW_E_NOT_FOUND;
            filters.erase(it);
        }
        if (filter == renderer) Disconnect();
        CallMethod(filter, 13, 0u, 0u);
        CallMethod(filter, 2);
        return S_OK;
    }
    uint32_t FindFilterByName(uint32_t, uint32_t, uint32_t out) {
        if (out) *At<uint32_t>(out) = 0;
        return VFW_E_NOT_FOUND;
    }
    uint32_t Ok(uint32_t) { return S_OK; }
    uint32_t RenderFile(uint32_t, uint32_t name, uint32_t playlist);

    // ---- IMediaControl ----
    uint32_t Run(uint32_t);
    uint32_t Pause(uint32_t);
    uint32_t Stop(uint32_t);
    uint32_t GetState(uint32_t, uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        std::lock_guard<std::mutex> hold(lock);
        *At<uint32_t>(out) = static_cast<uint32_t>(state);
        return S_OK;
    }
    uint32_t ControlRenderFile(uint32_t self, uint32_t bstr) { return RenderFile(self, bstr, 0); }
    uint32_t StopWhenReady(uint32_t self) {
        Pause(self);
        return Stop(self);
    }

    // ---- IMediaEventEx ----
    uint32_t GetEvent(uint32_t, uint32_t pCode, uint32_t p1, uint32_t p2, uint32_t) {
        std::lock_guard<std::mutex> hold(lock);
        if (queue.empty()) return E_ABORT;
        Event e = queue.front();
        queue.pop_front();
        if (pCode) *At<uint32_t>(pCode) = e.code;
        if (p1) *At<uint32_t>(p1) = e.p1;
        if (p2) *At<uint32_t>(p2) = e.p2;
        return S_OK;
    }
    uint32_t WaitForCompletion(uint32_t, uint32_t ms, uint32_t pCode) {
        std::unique_lock<std::mutex> lk(lock);
        cv.wait_for(lk, std::chrono::milliseconds(ms == kInfinite ? 24 * 3600 * 1000 : ms), [&] { return ended; });
        if (pCode) *At<uint32_t>(pCode) = ended ? EC_COMPLETE : 0;
        return ended ? S_OK : E_ABORT;
    }
    uint32_t FreeEventParams(uint32_t, uint32_t, uint32_t, uint32_t) { return S_OK; }
    uint32_t SetNotifyWindow(uint32_t, uint32_t hwnd, uint32_t msg, uint32_t param) {
        std::lock_guard<std::mutex> hold(lock);
        notifyWindow = hwnd;
        notifyMessage = msg;
        notifyParam = param;
        if (hwnd && !queue.empty()) PostToWindow(hwnd, msg, 0, param);
        return S_OK;
    }
    uint32_t SetNotifyFlags(uint32_t, uint32_t) { return S_OK; }
    uint32_t GetNotifyFlags(uint32_t, uint32_t out) {
        if (out) *At<uint32_t>(out) = 0;
        return S_OK;
    }
    // (IMediaEventSink::Notify: the renderer's events)
    uint32_t Notify(uint32_t, uint32_t code, uint32_t p1, uint32_t p2) {
        Log("DirectShow: event %#x (%#x, %#x)", code, p1, p2);
        std::lock_guard<std::mutex> hold(lock);
        if (code == EC_COMPLETE) {
            ended = true;
            cv.notify_all();
        }
        Queue(code, p1, p2);
        return S_OK;
    }
    void Queue(uint32_t code, uint32_t p1, uint32_t p2) {   // (the lock held)
        queue.push_back({code, p1, p2});
        if (notifyWindow) PostToWindow(notifyWindow, notifyMessage, 0, notifyParam);
    }

    // ---- IMediaSeeking (media time only) ----
    uint32_t GetCapabilities(uint32_t, uint32_t out) {
        // CanSeekAbsolute, Forwards, Backwards, GetCurrentPos, GetStopPos, GetDuration
        if (out) *At<uint32_t>(out) = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x100;
        return S_OK;
    }
    uint32_t CheckCapabilities(uint32_t, uint32_t p) {
        if (!p) return E_POINTER;
        uint32_t want = *At<uint32_t>(p), have = 0x11f;
        *At<uint32_t>(p) = want & have;
        return (want & have) == want ? S_OK : S_FALSE;
    }
    uint32_t IsFormatSupported(uint32_t, uint32_t f) { return Is(f, kTimeFormatMediaTime) ? S_OK : S_FALSE; }
    uint32_t GetTimeFormat(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        memcpy(At(out), kTimeFormatMediaTime.b, 16);
        return S_OK;
    }
    uint32_t SetTimeFormat(uint32_t, uint32_t f) { return Is(f, kTimeFormatMediaTime) ? S_OK : E_NOTIMPL; }
    uint32_t GetDuration(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        Put64(out, info.duration);
        return S_OK;
    }
    uint32_t GetCurrentPosition(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        std::lock_guard<std::mutex> hold(lock);
        Put64(out, Position());
        return S_OK;
    }
    uint32_t ConvertTimeFormat(uint32_t, uint32_t out, uint32_t outFmt, uint32_t src, uint32_t inFmt) {
        if ((outFmt && !Is(outFmt, kTimeFormatMediaTime)) || (inFmt && !Is(inFmt, kTimeFormatMediaTime))) return E_NOTIMPL;
        Put64(out, Get64(src));
        return S_OK;
    }
    uint32_t SetPositions(uint32_t, uint32_t pCur, uint32_t curFlags, uint32_t pStop, uint32_t stopFlags);
    uint32_t GetPositions(uint32_t, uint32_t pCur, uint32_t pStop) {
        std::lock_guard<std::mutex> hold(lock);
        const int64_t p = Position();
        Put64(pCur, p);
        Put64(pStop, info.duration);
        // (the position the reference reads, every 2 s of its asking, against the stream's own state)
        const int64_t now = Now100ns();
        if (now - lastPositionLog >= 20000000) {
            lastPositionLog = now;
            Log("DirectShow: position %.3f s (state %d, presented %.3f s, streaming %d)", p / 1e7, state,
                presented / 1e7, streaming);
        }
        return S_OK;
    }
    int64_t lastPositionLog = 0;
    uint32_t GetAvailable(uint32_t, uint32_t early, uint32_t late) {
        Put64(early, 0);
        Put64(late, info.duration);
        return S_OK;
    }
    // (a double, as the two words the reference pushed)
    uint32_t SetRate(uint32_t, uint32_t lo, uint32_t hi) {
        uint64_t b = (static_cast<uint64_t>(hi) << 32) | lo;
        double r;
        memcpy(&r, &b, 8);
        if (r != 1.0) LogOnce("dshow-rate", "DirectShow: SetRate(%g): only 1.0 here", r);
        return r == 1.0 ? S_OK : E_NOTIMPL;
    }
    uint32_t GetRate(uint32_t, uint32_t out) {
        double r = 1.0;
        if (out) memcpy(At(out), &r, 8);
        return S_OK;
    }
    uint32_t GetPreroll(uint32_t, uint32_t out) {
        Put64(out, 0);
        return S_OK;
    }
    int64_t Position() const {   // (the lock held)
        if (ended) return info.duration;
        int64_t e = elapsed + (state == 2 ? Now100ns() - runSince : 0);
        int64_t p = std::min(info.duration, segStart + e);
        // while frames come, no further than the last one the renderer has (+ its own length): a
        // decoder slower than the clock, or a first frame late, would have the reference's subtitles
        // (timed by this position) run ahead of the picture
        if (info.decodes && streaming) p = std::min(p, presented < 0 ? segStart : presented + info.frameTime);
        return p;
    }

    // ---- IBasicAudio ----
    uint32_t PutVolume(uint32_t, uint32_t v) {
        volume = std::clamp(static_cast<int32_t>(v), -10000, 0);
        return S_OK;
    }
    uint32_t GetVolume(uint32_t, uint32_t out) {
        if (out) *At<int32_t>(out) = volume;
        return S_OK;
    }
    uint32_t PutBalance(uint32_t, uint32_t) { return S_OK; }
    uint32_t GetBalance(uint32_t, uint32_t out) {
        if (out) *At<uint32_t>(out) = 0;
        return S_OK;
    }

    // ---- our source filter (IBaseFilter: only what a pin's QueryPinInfo hands out) ----
    uint32_t SourceClassID(uint32_t, uint32_t out) {
        if (out) memset(At(out), 0, 16);
        return S_OK;
    }
    uint32_t SourceState(uint32_t, uint32_t, uint32_t out) {
        if (out) *At<uint32_t>(out) = static_cast<uint32_t>(state);
        return S_OK;
    }
    uint32_t SourceInfo(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        memset(At(out), 0, 0x104);
        PutWide(out, "Movie source");
        *At<uint32_t>(out + 0x100) = builder;
        AddRef(0);
        return S_OK;
    }
    uint32_t SourceNoClock(uint32_t, uint32_t out) {
        if (out) *At<uint32_t>(out) = 0;
        return S_OK;
    }

    // ---- our output pin ----
    // (the pin, the allocator and the source are the graph's parts, counted apart from it: the renderer
    // holds our pin and allocator until it is disconnected, which the graph does as it dies; had they
    // counted on the graph it never died, and its stream ran on into a renderer the reference deleted)
    uint32_t PartAddRef(uint32_t) { return 2; }
    uint32_t PartRelease(uint32_t) { return 1; }
    uint32_t PinQueryInterface(uint32_t self, uint32_t riid, uint32_t out) {
        if (!out) return E_POINTER;
        if (Is(riid, kIidUnknown) || Is(riid, kIidPin)) {
            *At<uint32_t>(out) = self;
            return S_OK;
        }
        *At<uint32_t>(out) = 0;
        return E_NOINTERFACE;
    }
    uint32_t PinConnectedTo(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        *At<uint32_t>(out) = inPin;
        if (!inPin) return VFW_E_NOT_CONNECTED;
        CallMethod(inPin, 1);
        return S_OK;
    }
    uint32_t PinConnectionMediaType(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        if (!inPin) return VFW_E_NOT_CONNECTED;
        CopyType(out);
        return S_OK;
    }
    uint32_t PinInfo(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        memset(At(out), 0, 0x108);
        *At<uint32_t>(out) = source;   // pFilter (a part: its count is not the graph's)
        *At<uint32_t>(out + 4) = 1;   // PINDIR_OUTPUT
        PutWide(out + 8, "Video");
        return S_OK;
    }
    uint32_t PinDirection(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        *At<uint32_t>(out) = 1;
        return S_OK;
    }
    uint32_t PinId(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        uint32_t s = TaskAlloc(12);
        if (s) PutWide(s, "Video");
        *At<uint32_t>(out) = s;
        return s ? S_OK : E_FAIL;
    }
    uint32_t PinDisconnect(uint32_t) { return S_FALSE; }
    uint32_t PinUnexpected(uint32_t) { return E_UNEXPECTED; }

    // ---- our allocator (the samples are ours; the renderer only holds it) ----
    uint32_t AllocQueryInterface(uint32_t self, uint32_t riid, uint32_t out) {
        if (!out) return E_POINTER;
        if (Is(riid, kIidUnknown) || Is(riid, kIidMemAllocator)) {
            *At<uint32_t>(out) = self;
            return S_OK;
        }
        *At<uint32_t>(out) = 0;
        return E_NOINTERFACE;
    }
    // ALLOCATOR_PROPERTIES: cBuffers, cbBuffer, cbAlign, cbPrefix
    uint32_t AllocGetProperties(uint32_t, uint32_t out) {
        if (!out) return E_POINTER;
        auto p = At<uint32_t>(out);
        p[0] = static_cast<uint32_t>(samples.size());
        p[1] = samples.empty() ? 0 : samples[0]->size;
        p[2] = 1;
        p[3] = 0;
        return S_OK;
    }
    uint32_t AllocSetProperties(uint32_t self, uint32_t, uint32_t actual) { return AllocGetProperties(self, actual); }
    uint32_t AllocGetBuffer(uint32_t, uint32_t out, uint32_t, uint32_t, uint32_t) {
        if (!out) return E_POINTER;
        Sample* s = Acquire();
        *At<uint32_t>(out) = s ? s->self : 0;
        return s ? S_OK : VFW_E_WRONG_STATE;
    }
    uint32_t AllocReleaseBuffer(uint32_t, uint32_t) { return S_OK; }

    // ---- the internals ----
    void CopyType(uint32_t out);
    bool Connect();
    void Disconnect();
    Sample* Acquire();
    void SampleFreed() {
        std::lock_guard<std::mutex> hold(lock);
        cv.notify_all();
    }
    void StartStream();   // the lock not held
    void StopStream(bool flush);
    static void StreamMain(void* g) { static_cast<Graph*>(g)->Stream(); }
    void Stream();
    void AudioMain();
    // wait until the stream time reaches `t` (or a stop): false on the stop
    bool WaitUntil(int64_t t, bool first);
};

uint32_t Sample::QueryInterface(uint32_t, uint32_t riid, uint32_t out) {
    if (!out) return E_POINTER;
    if (Is(riid, kIidUnknown) || Is(riid, kIidMediaSample)) {
        *At<uint32_t>(out) = self;
        ++refs;
        return S_OK;
    }
    *At<uint32_t>(out) = 0;   // (IMediaSample2 too: the renderer asks the plain methods then)
    return E_NOINTERFACE;
}
uint32_t Sample::Release(uint32_t) {
    int r = --refs;
    if (r <= 0) {
        refs = 0;
        if (graph) graph->SampleFreed();
    }
    return static_cast<uint32_t>(r < 0 ? 0 : r);
}

void Graph::CopyType(uint32_t out) {
    memcpy(At(out), At(mediaType), 0x48);
    uint32_t n = *At<uint32_t>(mediaType + 0x40);
    uint32_t f = TaskAlloc(n);
    if (f) memcpy(At(f), At(*At<uint32_t>(mediaType + 0x44)), n);
    *At<uint32_t>(out + 0x40) = f ? n : 0;
    *At<uint32_t>(out + 0x44) = f;
}

// AM_MEDIA_TYPE and its VIDEOINFOHEADER: RGB32, the movie's size, bottom-up
void BuildType(uint32_t mt, const MovieInfo& i) {
    memset(At(mt), 0, 0x48);
    memcpy(At(mt), kMediaTypeVideo.b, 16);
    memcpy(At(mt + 0x10), kSubtypeRgb32.b, 16);
    const uint32_t image = i.width * i.height * 4;
    *At<uint32_t>(mt + 0x20) = 1;       // bFixedSizeSamples
    *At<uint32_t>(mt + 0x24) = 0;       // bTemporalCompression
    *At<uint32_t>(mt + 0x28) = image;   // lSampleSize
    memcpy(At(mt + 0x2c), kFormatVideoInfo.b, 16);
    uint32_t vih = LowNew(88);
    memset(At(vih), 0, 88);
    auto w32 = [&](uint32_t o, uint32_t v) { *At<uint32_t>(vih + o) = v; };
    w32(0x08, i.width);    // rcSource right
    w32(0x0c, i.height);   //          bottom
    w32(0x18, i.width);    // rcTarget
    w32(0x1c, i.height);
    w32(0x20, static_cast<uint32_t>(image * 8ull * 10000000ull / static_cast<uint64_t>(std::max<int64_t>(1, i.frameTime))));
    memcpy(At(vih + 0x28), &i.frameTime, 8);   // AvgTimePerFrame
    w32(0x30, 40);         // biSize
    w32(0x34, i.width);
    w32(0x38, i.height);   // positive: bottom-up
    *At<uint16_t>(vih + 0x3c) = 1;    // biPlanes
    *At<uint16_t>(vih + 0x3e) = 32;   // biBitCount
    w32(0x40, 0);          // BI_RGB
    w32(0x44, image);      // biSizeImage
    *At<uint32_t>(mt + 0x40) = 88;
    *At<uint32_t>(mt + 0x44) = vih;
}

// the reference's renderer: the first filter of its own with an input pin, connected to ours
bool Graph::Connect() {
    std::vector<uint32_t> fs;
    {
        std::lock_guard<std::mutex> hold(lock);
        fs = filters;
    }
    for (uint32_t f : fs) {
        if (Native(f)) continue;   // (ours: the DMO wrapper)
        uint32_t en = 0;
        uint32_t slot = LowAlloc(0x1000), pins = slot, fetched = slot + 4, dir = slot + 8;
        if (!slot) return false;
        if (static_cast<int32_t>(CallMethod(f, 10, slot + 12)) < 0 || !(en = U32(slot + 12))) {   // EnumPins
            LowFree(slot, 0x1000);
            continue;
        }
        uint32_t found = 0;
        while (!found && CallMethod(en, 3, 1u, pins, fetched) == S_OK && U32(fetched) == 1) {   // Next
            uint32_t p = U32(pins);
            *At<uint32_t>(dir) = 1;
            CallMethod(p, 9, dir);   // QueryDirection
            if (U32(dir) == 0) found = p;
            else CallMethod(p, 2);
        }
        CallMethod(en, 2);
        if (!found) {
            LowFree(slot, 0x1000);
            continue;
        }
        CallMethod(f, 8, 0u);   // SetSyncSource(NULL): the renderer draws each sample as it comes
        uint32_t hr = CallMethod(found, 4, pin, mediaType);   // ReceiveConnection
        if (static_cast<int32_t>(hr) < 0) {
            Log("DirectShow: the renderer %08x refused the connection (%#x)", f, hr);
            CallMethod(found, 2);
            LowFree(slot, 0x1000);
            return false;
        }
        uint32_t mi = 0;
        // (QueryInterface takes the IID's address: ours copied below 2 GB)
        memcpy(At(slot + 16), kIidMemInputPin.b, 16);
        if (static_cast<int32_t>(CallMethod(found, 0, slot + 16, slot)) >= 0) mi = U32(slot);
        if (!mi) {
            Log("DirectShow: the renderer's pin has no IMemInputPin");
            CallMethod(found, 5);   // Disconnect
            CallMethod(found, 2);
            LowFree(slot, 0x1000);
            return false;
        }
        hr = CallMethod(mi, 4, allocator, 0u);   // NotifyAllocator(ours, not read-only)
        LowFree(slot, 0x1000);
        std::lock_guard<std::mutex> hold(lock);
        renderer = f;
        inPin = found;
        memIn = mi;
        Log("DirectShow: connected to the renderer %08x (pin %08x): RGB32 %ux%u (NotifyAllocator %#x)", f, found,
            info.width, info.height, hr);
        return true;
    }
    Log("DirectShow: RenderFile: no renderer of the reference's in the graph");
    return false;
}

void Graph::Disconnect() {
    uint32_t p, m;
    {
        std::lock_guard<std::mutex> hold(lock);
        p = inPin;
        m = memIn;
        inPin = memIn = renderer = 0;
    }
    if (m) CallMethod(m, 2);
    if (p) {
        CallMethod(p, 5);   // Disconnect
        CallMethod(p, 2);
    }
}

uint32_t Graph::RenderFile(uint32_t, uint32_t name, uint32_t) {
    if (!name) return E_POINTER;
    {
        std::lock_guard<std::mutex> hold(lock);
        if (inPin) return VFW_E_ALREADY_CONNECTED;
    }
    const std::string windows = NameOf(name);
    file = HostFile(At<char16_t>(name));
    dec = OpenDecoder(file);
    if (!dec) dec = Probe::Open(file);
    if (!dec) {
        Log("DirectShow: RenderFile(%s): no such file (%s)", windows.c_str(), file.c_str());
        return VFW_E_NOT_FOUND;
    }
    info = dec->Info();
    Log("DirectShow: RenderFile(%s): %ux%u, %.1f s, %s; decoded by %s", windows.c_str(), info.width, info.height,
        static_cast<double>(info.duration) / 1e7, info.codecs.c_str(), info.decoder);
    mediaType = LowNew(0x48);
    BuildType(mediaType, info);
    // three samples of a frame each
    const uint32_t image = info.width * info.height * 4;
    for (int k = 0; k < 3 && info.decodes; k++) {
        auto s = new Sample;
        s->graph = this;
        s->size = image;
        s->buffer = LowAlloc((image + 0xffff) & ~0xffffu);
        if (!s->buffer) {
            delete s;
            break;
        }
        s->self = NewObject(SampleVtable(), s);
        samples.push_back(s);
    }
    if (!Connect()) return E_FAIL;
    return S_OK;
}

Sample* Graph::Acquire() {
    std::unique_lock<std::mutex> lk(lock);
    for (;;) {
        for (Sample* s : samples)
            if (s->refs == 0) {
                s->refs = 1;
                return s;
            }
        if (stop || samples.empty()) return nullptr;
        cv.wait_for(lk, std::chrono::milliseconds(50));
    }
}

bool Graph::WaitUntil(int64_t t, bool first) {
    std::unique_lock<std::mutex> lk(lock);
    for (;;) {
        if (stop) return false;
        if (first && state != 0) return true;   // (the first frame at once: the renderer's preroll)
        if (state == 2) {
            int64_t now = segStart + elapsed + (Now100ns() - runSince);
            if (now >= t) return true;
            cv.wait_for(lk, std::chrono::microseconds(std::min<int64_t>(20000, (t - now) / 10 + 1)));
        } else {
            cv.wait_for(lk, std::chrono::milliseconds(20));
        }
    }
}

void Graph::Stream() {
    const uint32_t stride = info.width * 4;
    bool first = true;
    int64_t base = 0;   // the decoder's time of the segment's start
    while (!stop && info.decodes) {
        Sample* s = Acquire();
        if (!s) break;
        int64_t t = 0;
        if (!dec->NextVideo(At<uint8_t>(s->buffer), stride, &t)) {
            s->Release(0);
            break;
        }
        // the stream's times from its first frame: a decoder's own may start anywhere (an ASF's preroll
        // left in, or a reader's presentation clock), and a first frame stamped late held the next one
        // back that long while the position, and the reference's subtitles with it, ran on
        if (first) {
            Log("DirectShow: first frame at %.3f s (segment from %.3f s)", t / 1e7, segStart / 1e7);
            base = t - segStart;
        }
        t -= base;
        if (!WaitUntil(t, first)) {
            s->Release(0);
            break;
        }
        s->actual = s->size;
        s->start = t - segStart;
        s->stop = s->start + info.frameTime;
        s->timed = true;
        s->discontinuity = first;
        first = false;
        uint32_t m = memIn;
        uint32_t hr = m ? CallMethod(m, 6, s->self) : VFW_E_NOT_CONNECTED;   // Receive
        s->Release(0);
        {
            std::lock_guard<std::mutex> hold(lock);
            presented = t;
        }
        if (static_cast<int32_t>(hr) < 0 || hr == S_FALSE) {
            if (!stop) Log("DirectShow: the renderer's Receive returned %#x: the stream ends", hr);
            break;
        }
    }
    if (!stop) {
        // the end, after the last sample (paused, the renderer keeps it for its Run: EC_COMPLETE then)
        WaitUntil(0, true);
        if (inPin && !stop) {
            uint32_t hr = CallMethod(inPin, 14);   // EndOfStream
            Log("DirectShow: end of stream (%#x)", hr);
        }
    }
    std::lock_guard<std::mutex> hold(lock);
    streaming = false;
    cv.notify_all();
}

// the audio thread: the device opened, fed while running, closed at the end
void Graph::AudioMain() {
    const bool open = out->Open();
    if (!open) Log("DirectShow: no audio device: the movie plays silent");
    std::vector<float> buf(2 * 1024);
    while (open && !stop) {
        int st;
        {
            std::lock_guard<std::mutex> hold(lock);
            st = state;
        }
        if (st != 2) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        uint32_t n = dec->NextAudio(buf.data(), 1024);
        if (n == 0) break;
        const float gain = volume <= -10000 ? 0.f : powf(10.f, static_cast<float>(volume) / 2000.f);
        if (gain != 1.f)
            for (uint32_t k = 0; k < 2 * n; k++) buf[k] *= gain;
        out->Write(buf.data(), n);
    }
    out->Close();
    std::lock_guard<std::mutex> hold(lock);
    audioRunning = false;
    cv.notify_all();
}

void Graph::StartStream() {
    {
        std::lock_guard<std::mutex> hold(lock);
        if (streaming) return;
        stop = false;
        streaming = true;
        presented = -1;
        audioRunning = info.decodes && info.hasAudio && out;
    }
    if (!StartThread(&Graph::StreamMain, this)) {
        Log("DirectShow: the streaming thread not started");
        std::lock_guard<std::mutex> hold(lock);
        streaming = false;
        audioRunning = false;
        return;
    }
    if (audioRunning) std::thread([this] { AudioMain(); }).detach();
}

// the threads stopped (the renderer told to let go of a waiting Receive first: a flush, or its Stop)
void Graph::StopStream(bool flush) {
    {
        std::lock_guard<std::mutex> hold(lock);
        if (!streaming && !audioRunning) return;
        stop = true;
        cv.notify_all();
    }
    if (flush && inPin) CallMethod(inPin, 15);   // BeginFlush
    {
        std::unique_lock<std::mutex> lk(lock);
        cv.wait(lk, [&] { return !streaming && !audioRunning; });
    }
    if (flush && inPin) CallMethod(inPin, 16);   // EndFlush
}

uint32_t Graph::Pause(uint32_t) {
    Log("DirectShow: Pause (state %d)", state);
    int was;
    {
        std::lock_guard<std::mutex> hold(lock);
        was = state;
        if (was == 1) return S_OK;
        if (was == 2) elapsed += Now100ns() - runSince;
        state = 1;
        cv.notify_all();
    }
    if (renderer) CallMethod(renderer, 5);   // IMediaFilter::Pause
    if (out) out->Pause(true);
    if (was == 0) {
        if (dec && segStart + elapsed != 0) dec->Seek(segStart + elapsed);
        StartStream();
    }
    std::lock_guard<std::mutex> hold(lock);
    Queue(EC_PAUSED, S_OK, 0);
    return S_OK;
}

uint32_t Graph::Run(uint32_t self) {
    Log("DirectShow: Run (state %d)", state);
    int was;
    {
        std::lock_guard<std::mutex> hold(lock);
        was = state;
        if (was == 2) return S_OK;
    }
    if (was == 0) Pause(self);
    {
        std::lock_guard<std::mutex> hold(lock);
        runSince = Now100ns();
        state = 2;
        cv.notify_all();
    }
    if (renderer) CallMethod(renderer, 6, 0u, 0u);   // IMediaFilter::Run(0): no clock, no start time
    if (out) out->Pause(false);
    return S_OK;
}

uint32_t Graph::Stop(uint32_t) {
    Log("DirectShow: Stop (state %d)", state);
    {
        std::lock_guard<std::mutex> hold(lock);
        if (state == 0) return S_OK;
        if (state == 2) elapsed += Now100ns() - runSince;
        state = 0;
        stop = true;
        cv.notify_all();
    }
    if (renderer) CallMethod(renderer, 4);   // IMediaFilter::Stop: a Receive waiting on it returns
    StopStream(false);   // (the audio thread closes its device)
    return S_OK;
}

uint32_t Graph::SetPositions(uint32_t, uint32_t pCur, uint32_t curFlags, uint32_t pStop, uint32_t stopFlags) {
    const uint32_t how = curFlags & 3;
    Log("DirectShow: SetPositions(%.3f s, flags %#x; stop flags %#x)", pCur ? Get64(pCur) / 1e7 : -1.0, curFlags,
        stopFlags);
    if (how && pCur) {
        int64_t to;
        int st;
        {
            std::lock_guard<std::mutex> hold(lock);
            const int64_t now = Position(), v = Get64(pCur);
            to = how == 1 ? v : now + v;   // absolute, or relative / incremental
            to = std::clamp<int64_t>(to, 0, info.duration);
            st = state;
        }
        StopStream(true);
        {
            std::lock_guard<std::mutex> hold(lock);
            segStart = to;
            elapsed = 0;
            runSince = Now100ns();
            ended = false;
        }
        if (dec) dec->Seek(to);
        if (inPin) CallMethod(inPin, 17, 0u, 0u, Lo(info.duration - to), Hi(info.duration - to), 0u, 0x3ff00000u);   // NewSegment(0, len, 1.0)
        if (st != 0) StartStream();
        if (curFlags & 8) Put64(pCur, to);   // AM_SEEKING_ReturnTime
    }
    if ((stopFlags & 3) && pStop && (stopFlags & 8)) Put64(pStop, info.duration);
    return S_OK;
}

void Graph::Destroy() {
    dying = true;
    Stop(0);
    Disconnect();
    std::vector<uint32_t> fs;
    {
        std::lock_guard<std::mutex> hold(lock);
        fs.swap(filters);
    }
    for (uint32_t f : fs) {
        CallMethod(f, 13, 0u, 0u);   // JoinFilterGraph(NULL)
        CallMethod(f, 2);
    }
    for (Sample* s : samples) {
        FreeObject(s->self);
        s->graph = nullptr;   // (a sample the renderer still holds: its head answers E_UNEXPECTED)
    }
    for (uint32_t h : {builder, control, seeking, events, audio, video, sink, source, pin, allocator}) FreeObject(h);
    dec.reset();   // (the threads gone: the file and its decoder let go)
    out.reset();
    Log("DirectShow: graph released");
    // (the samples' buffers and objects kept: the renderer may hold one past us; a movie's three)
}

uint32_t CreateGraph(uint32_t riid, uint32_t out) {
    static uint32_t vb, vc, vs, ve, va, vv, vk, vsrc, vp, val;
    if (!vb) {
        using G = Graph;
        const void* qi = T_<&G::QueryInterface>(), *ar = T_<&G::AddRef>(), *rl = T_<&G::Release>(),
                    *ok = T_<&G::Ok>();
        const void* b[18] = {qi, ar, rl, T_<&G::AddFilter>(), T_<&G::RemoveFilter>(), kNotImpl /* EnumFilters */,
                             T_<&G::FindFilterByName>(), kNotImpl /* ConnectDirect */, kNotImpl /* Reconnect */,
                             kNotImpl /* Disconnect */, ok /* SetDefaultSyncSource */, kNotImpl /* Connect */,
                             kNotImpl /* Render */, T_<&G::RenderFile>(), kNotImpl /* AddSourceFilter */,
                             ok /* SetLogFile */, ok /* Abort */, ok /* ShouldOperationContinue */};
        vb = Vtable(b, 18);
        const void* c[16] = {qi, ar, rl, kNotImpl, kNotImpl, kNotImpl, kNotImpl /* IDispatch */,
                             T_<&G::Run>(), T_<&G::Pause>(), T_<&G::Stop>(), T_<&G::GetState>(),
                             T_<&G::ControlRenderFile>(), kNotImpl, kNotImpl, kNotImpl, T_<&G::StopWhenReady>()};
        vc = Vtable(c, 16);
        const void* s[20] = {qi, ar, rl, T_<&G::GetCapabilities>(), T_<&G::CheckCapabilities>(),
                             T_<&G::IsFormatSupported>(), T_<&G::GetTimeFormat>() /* QueryPreferredFormat */,
                             T_<&G::GetTimeFormat>(), T_<&G::IsFormatSupported>() /* IsUsingTimeFormat */,
                             T_<&G::SetTimeFormat>(), T_<&G::GetDuration>(), T_<&G::GetDuration>() /* GetStopPosition */,
                             T_<&G::GetCurrentPosition>(), T_<&G::ConvertTimeFormat>(), T_<&G::SetPositions>(),
                             T_<&G::GetPositions>(), T_<&G::GetAvailable>(), T_<&G::SetRate>(), T_<&G::GetRate>(),
                             T_<&G::GetPreroll>()};
        vs = Vtable(s, 20);
        const void* e[16] = {qi, ar, rl, kNotImpl, kNotImpl, kNotImpl, kNotImpl, kNotImpl /* GetEventHandle */,
                             T_<&G::GetEvent>(), T_<&G::WaitForCompletion>(), ok /* CancelDefaultHandling */,
                             ok /* RestoreDefaultHandling */, T_<&G::FreeEventParams>(), T_<&G::SetNotifyWindow>(),
                             T_<&G::SetNotifyFlags>(), T_<&G::GetNotifyFlags>()};
        ve = Vtable(e, 16);
        const void* a[11] = {qi, ar, rl, kNotImpl, kNotImpl, kNotImpl, kNotImpl, T_<&G::PutVolume>(),
                             T_<&G::GetVolume>(), T_<&G::PutBalance>(), T_<&G::GetBalance>()};
        va = Vtable(a, 11);
        const void* v[39];
        for (auto& m : v) m = kNotImpl;
        v[0] = qi;
        v[1] = ar;
        v[2] = rl;
        vv = Vtable(v, 39);
        const void* k[4] = {qi, ar, rl, T_<&G::Notify>()};
        vk = Vtable(k, 4);
        const void *par = T_<&G::PartAddRef>(), *prl = T_<&G::PartRelease>();
        const void* src[15] = {qi, par, prl, T_<&G::SourceClassID>(), ok, ok, ok, T_<&G::SourceState>(), ok,
                               T_<&G::SourceNoClock>(), kNotImpl, kNotImpl, T_<&G::SourceInfo>(), ok, kNotImpl};
        vsrc = Vtable(src, 15);
        const void* p[18] = {T_<&G::PinQueryInterface>(), par, prl, T_<&G::PinUnexpected>() /* Connect */,
                             T_<&G::PinUnexpected>() /* ReceiveConnection */, T_<&G::PinDisconnect>(),
                             T_<&G::PinConnectedTo>(), T_<&G::PinConnectionMediaType>(), T_<&G::PinInfo>(),
                             T_<&G::PinDirection>(), T_<&G::PinId>(), ok /* QueryAccept */,
                             kNotImpl /* EnumMediaTypes */, kNotImpl /* QueryInternalConnections */,
                             T_<&G::PinUnexpected>() /* EndOfStream */, T_<&G::PinUnexpected>() /* BeginFlush */,
                             T_<&G::PinUnexpected>() /* EndFlush */, T_<&G::PinUnexpected>() /* NewSegment */};
        vp = Vtable(p, 18);
        const void* al[9] = {T_<&G::AllocQueryInterface>(), par, prl, T_<&G::AllocSetProperties>(),
                             T_<&G::AllocGetProperties>(), ok /* Commit */, ok /* Decommit */,
                             T_<&G::AllocGetBuffer>(), T_<&G::AllocReleaseBuffer>()};
        val = Vtable(al, 9);
    }
    auto g = new Graph;
    g->builder = NewObject(vb, g);
    g->control = NewObject(vc, g);
    g->seeking = NewObject(vs, g);
    g->events = NewObject(ve, g);
    g->audio = NewObject(va, g);
    g->video = NewObject(vv, g);
    g->sink = NewObject(vk, g);
    g->source = NewObject(vsrc, g);
    g->pin = NewObject(vp, g);
    g->allocator = NewObject(val, g);
    uint32_t hr = g->QueryInterface(0, riid, out);
    g->Release(0);
    if (hr == S_OK) Log("DirectShow: filter graph %08x made", g->builder);
    return hr;
}

}  // namespace

#ifndef RH_DSHOW_FFMPEG
std::unique_ptr<MovieDecoder> OpenFfmpeg(const std::string&) { return nullptr; }
#endif

}  // namespace dshow

// CoCreateInstance's (both runtimes'): true for a DirectShow class of ours, its result in *hr
bool DShowClass(uint32_t clsid, uint32_t outer, uint32_t riid, uint32_t out, uint32_t* hr) {
    using namespace dshow;
    const bool graph = Is(clsid, kClsidFilterGraph) || Is(clsid, kClsidFilterGraphNoThread);
    const bool dmo = Is(clsid, kClsidDmoWrapper);
    if (!graph && !dmo) return false;
    if (out) *At<uint32_t>(out) = 0;
    if (outer) {
        *hr = CLASS_E_NOAGGREGATION;
        return true;
    }
    *hr = graph ? CreateGraph(riid, out) : Dmo::Create(riid, out);
    return true;
}

}  // namespace rh
