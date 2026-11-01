// XAudio2 2.7 (the June 2010 DirectX SDK's xaudio2.h) on AAudio: the engine CoCreateInstance makes for
// CLSID_XAudio2 (and its debug class), its voices, and the two effects of xaudio2fx.h (the reverb and
// the volume meter), so a reference that plays its sound through XAudio2 is heard on the phone.
//
// One mixer per engine, on a runtime low thread (the reference's callbacks need its TEB and a low
// stack): every quantum (10 ms, XAudio2's) it calls the engine callbacks' OnProcessingPassStart and
// each running source voice's OnVoiceProcessingPassStart, then, under the engine's lock, consumes the
// voices' queued buffers (PCM 8/16/24/32, IEEE float, WAVEFORMATEXTENSIBLE of either, MS ADPCM),
// resamples them (linear, frequency ratio x source rate -> the engine's rate), filters (the voice's
// state-variable filter), applies volumes, channel volumes and output matrices, mixes the submix
// voices in processing-stage order into the mastering voice, then, without the lock, fires the
// buffer callbacks the pass produced (OnBufferStart/End, OnLoopEnd, OnStreamEnd, then
// OnVoiceProcessingPassEnd) and OnProcessingPassEnd, and writes the mastered float frames to an
// AAudio stream (blocking: the device paces the passes; without a device, a clock does). No callback
// is ever called with the lock held: a callback submits buffers, and the reference's own locks would
// otherwise order against ours.
//
// What is not done, logged once each: effects the reference implements itself (its own XAPOs in an
// effect chain) pass the audio through unprocessed, as do the volume meter (which does measure its
// levels) and the reverb (which keeps the dry part of its WetDryMix only: no reverberation); send
// filters; xWMA plays as silence of its length; operation sets apply at once.
//
// The float arguments: the reference's translation passes a float to these methods as its 32-bit
// pattern in an integer word (gen_fl2bits: SetVolume, SetFrequencyRatio, CreateSourceVoice's
// MaxFrequencyRatio), so they are declared uint32_t here and read back with Bits().
//
// The vtable slots are xaudio2.h 2.7's: IXAudio2 is IUnknown's 3 then GetDeviceCount, GetDeviceDetails,
// Initialize (which 2.8 removed), ...; IXAudio2Voice has no IUnknown (slot 0 is GetVoiceDetails).
// Structures are at x86 layouts with xaudio2.h's pack(1).
#include <aaudio/AAudio.h>
#include <math.h>
#include <time.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "Com32Posix.h"

namespace rh {

using namespace com;

namespace {

constexpr uint32_t S_OK = 0, kInvalidCall = 0x88960001u /* XAUDIO2_E_INVALID_CALL */,
                   kNoAggregation = 0x80040110u /* CLASS_E_NOAGGREGATION */;
constexpr uint32_t kEndOfStream = 0x40, kUseFilter = 0x8, kLoopInfinite = 255, kMaxQueued = 64;
constexpr unsigned kMaxChannels = 16;

// the classes and interfaces, as their bytes in memory
const uint8_t kClsidXAudio2[16] = {0x85, 0x86, 0x50, 0x5a, 0x54, 0xa2, 0xba, 0x4f,
                                   0x9b, 0x82, 0x9a, 0x24, 0xb0, 0x03, 0x06, 0xaf};   // 5a508685-...
const uint8_t kClsidXAudio2Debug[16] = {0x35, 0xea, 0x05, 0xdb, 0x29, 0x03, 0x4b, 0x4d,
                                        0xa5, 0x3a, 0x6d, 0xea, 0xd0, 0x3d, 0x38, 0x52};   // db05ea35-...
const uint8_t kClsidReverb[16] = {0x0e, 0x13, 0x93, 0x6a, 0x53, 0x1d, 0xd1, 0x41,
                                  0xa9, 0xcf, 0xe7, 0x58, 0x80, 0x0b, 0xb1, 0x79};   // 6a93130e-...
const uint8_t kClsidReverbDebug[16] = {0xd4, 0x2d, 0xf8, 0xc4, 0x4e, 0xcb, 0xe1, 0x4c,
                                       0x8b, 0xdb, 0xee, 0x32, 0xd4, 0x19, 0x82, 0x69};   // c4f82dd4-...
const uint8_t kClsidMeter[16] = {0x5f, 0x10, 0xc1, 0xca, 0x9b, 0x61, 0x04, 0x4d,
                                 0x83, 0x1a, 0x44, 0xe1, 0xcb, 0xf1, 0x2d, 0x57};   // cac1105f-...
const uint8_t kClsidMeterDebug[16] = {0x9c, 0x0f, 0x9a, 0x2d, 0x7b, 0xe6, 0x24, 0x4b,
                                      0xab, 0x44, 0x92, 0xb3, 0xe7, 0x70, 0xc0, 0x20};   // 2d9a0f9c-...
const uint8_t kIidXAudio2[16] = {0x58, 0x1f, 0xcf, 0x8b, 0xe7, 0x9f, 0x83, 0x45,
                                 0x8a, 0xc6, 0xe2, 0xad, 0xc4, 0x65, 0xc8, 0xbb};   // 8bcf1f58-...
const uint8_t kIidUnknown[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46};
const uint8_t kIidClassFactory[16] = {1, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46};
const uint8_t kIidXapoParameters[16] = {0x66, 0x5c, 0xd9, 0x26, 0xf2, 0x80, 0x9a, 0x49,
                                        0xad, 0x54, 0x5a, 0xe7, 0xf0, 0x1c, 0x6d, 0x98};   // 26d95c66-...
const uint8_t kSubtypeFloat[16] = {3, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71};

float Bits(uint32_t b) {
    float f;
    memcpy(&f, &b, 4);
    return f;
}
uint64_t NowNs() {
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<uint64_t>(t.tv_sec) * 1000000000ull + static_cast<uint64_t>(t.tv_nsec);
}
void OperationSet(uint32_t set) {
    if (set) LogOnce("xa2-opset", "XAudio2: operation sets applied at once (set %u)", set);
}

// the native object behind one of ours, nullptr for a released one (no com-foreign log: the
// reference's own effects are looked at too)
void* Native(uint32_t obj) {
    if (!obj) return nullptr;
    auto o = At<Object32>(obj);
    return o->magic == kMagic ? o->native : nullptr;
}

// T_<&C::M>: Method<> with a released object answered (XAUDIO2_E_INVALID_CALL), not called
template <auto M>
struct Thunk;
template <class C, class R, class... A, R (C::*M)(A...)>
struct Thunk<M> {
    static uint32_t Call(uint32_t self, A... a) {
        C* o = static_cast<C*>(Native(self));
        if (!o) {
            LogOnce("xa2-released", "XAudio2: a call on %08x, an object already released", self);
            return kInvalidCall;
        }
        if constexpr (std::is_void_v<R>) {
            (o->*M)(a...);
            return 0;
        } else {
            return static_cast<uint32_t>((o->*M)(a...));
        }
    }
};
template <auto M>
const void* T_() {
    return reinterpret_cast<const void*>(&Thunk<M>::Call);
}

// ---- formats ------------------------------------------------------------------------------------
enum Codec { kPcm8, kPcm16, kPcm24, kPcm32, kFloat32, kAdpcm, kWma };
const char* const kCodecNames[] = {"PCM 8", "PCM 16", "PCM 24", "PCM 32", "float", "MS ADPCM", "xWMA"};

struct Format {
    Codec codec = kPcm16;
    uint32_t channels = 0, rate = 0, avgBytes = 0, blockAlign = 0, samplesPerBlock = 0;
    std::vector<int> coef;   // ADPCM's predictor pairs
};

// WAVEFORMATEX at x86 layout: wFormatTag, nChannels, nSamplesPerSec, nAvgBytesPerSec, nBlockAlign,
// wBitsPerSample, cbSize; WAVEFORMATEXTENSIBLE's SubFormat at 24; ADPCMWAVEFORMAT's
// wSamplesPerBlock, wNumCoef and the pairs from 18
bool ParseFormat(uint32_t p, Format* f) {
    if (!p) return false;
    uint32_t tag = *At<uint16_t>(p);
    f->channels = *At<uint16_t>(p + 2);
    f->rate = U32(p + 4);
    f->avgBytes = U32(p + 8);
    f->blockAlign = *At<uint16_t>(p + 12);
    uint32_t bits = *At<uint16_t>(p + 14);
    uint32_t cb = tag == 1 ? 0 : *At<uint16_t>(p + 16);   // (PCM may come as a 16-byte PCMWAVEFORMAT)
    if (tag == 0xFFFE) {
        if (cb < 22) return false;
        tag = U32(p + 24);   // KSDATAFORMAT_SUBTYPE_PCM / _IEEE_FLOAT: the tag in Data1
    }
    if (f->channels == 0 || f->channels > kMaxChannels || f->rate < 1000 || f->rate > 200000 || f->blockAlign == 0)
        return false;
    switch (tag) {
        case 1:
            if (bits == 8) f->codec = kPcm8;
            else if (bits == 16) f->codec = kPcm16;
            else if (bits == 24) f->codec = kPcm24;
            else if (bits == 32) f->codec = kPcm32;
            else return false;
            return f->blockAlign >= f->channels * bits / 8;
        case 3:
            f->codec = kFloat32;
            return bits == 32 && f->blockAlign >= f->channels * 4;
        case 2: {
            if (f->channels > 2 || f->blockAlign <= 7 * f->channels) return false;
            f->codec = kAdpcm;
            uint32_t spb = cb >= 2 ? *At<uint16_t>(p + 18) : 0;
            uint32_t most = 2 + (f->blockAlign - 7 * f->channels) * 2 / f->channels;
            f->samplesPerBlock = spb && spb <= most ? spb : most;
            uint32_t n = cb >= 4 ? *At<uint16_t>(p + 20) : 0;
            if (n && cb >= 4 + 4 * n) {
                for (uint32_t k = 0; k < n * 2; k++) f->coef.push_back(*At<int16_t>(p + 22 + 2 * k));
            } else {
                f->coef = {256, 0, 512, -256, 0, 0, 192, 64, 240, 0, 460, -208, 392, -232};
            }
            return true;
        }
        case 0x161: case 0x162:
            f->codec = kWma;
            return true;
        default:
            return false;
    }
}

// MS ADPCM: one block (a header per channel: predictor, delta, sample 1, sample 2; then the nibbles,
// high first, the channels interleaved) as float frames
void DecodeAdpcm(const uint8_t* p, const Format& f, float* out) {
    static const int kAdapt[16] = {230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230};
    const uint32_t ch = f.channels, coefs = static_cast<uint32_t>(f.coef.size() / 2);
    int pred[2], delta[2], s1[2], s2[2];
    for (uint32_t c = 0; c < ch; c++) pred[c] = std::min<uint32_t>(p[c], coefs - 1);
    p += ch;
    for (uint32_t c = 0; c < ch; c++, p += 2) delta[c] = static_cast<int16_t>(p[0] | p[1] << 8);
    for (uint32_t c = 0; c < ch; c++, p += 2) s1[c] = static_cast<int16_t>(p[0] | p[1] << 8);
    for (uint32_t c = 0; c < ch; c++, p += 2) s2[c] = static_cast<int16_t>(p[0] | p[1] << 8);
    const float k = 1.f / 32768.f;
    for (uint32_t c = 0; c < ch; c++) {
        out[c] = s2[c] * k;
        out[ch + c] = s1[c] * k;
    }
    const uint32_t total = f.samplesPerBlock * ch;
    const uint32_t have = std::min(total, 2 * ch + (f.blockAlign - 7 * ch) * 2);
    uint32_t n = 2 * ch;
    while (n < have) {
        uint8_t byte = *p++;
        for (int h = 0; h < 2 && n < have; h++, n++) {
            int nib = h == 0 ? byte >> 4 : byte & 15;
            uint32_t c = n % ch;
            int v = (s1[c] * f.coef[pred[c] * 2] + s2[c] * f.coef[pred[c] * 2 + 1]) >> 8;
            v += (nib >= 8 ? nib - 16 : nib) * delta[c];
            v = std::max(-32768, std::min(32767, v));
            s2[c] = s1[c];
            s1[c] = v;
            delta[c] = std::max(16, (kAdapt[nib] * delta[c]) >> 8);
            out[n] = v * k;
        }
    }
    for (; n < total; n++) out[n] = 0.f;
}

// XAudio2's default matrix, m[dst * src + s]: identity; mono to the front pair; anything to mono
// averaged; 3.0 - 7.1 to stereo with the centre and the surrounds at -3 dB (no LFE); stereo to the
// front pair of more
void DefaultMatrix(uint32_t src, uint32_t dst, float* m) {
    std::fill(m, m + src * dst, 0.f);
    const float h = 0.70710678f;
    if (src == dst) {
        for (uint32_t k = 0; k < src; k++) m[k * src + k] = 1.f;
    } else if (src == 1) {
        for (uint32_t d = 0; d < std::min(dst, 2u); d++) m[d] = 1.f;
    } else if (dst == 1) {
        for (uint32_t s = 0; s < src; s++) m[s] = 1.f / src;
    } else if (dst == 2) {
        m[0] = 1.f;
        m[src + 1] = 1.f;
        const uint32_t sides = src == 4 ? 2 : src == 5 ? 3 : 4;   // the first surround channel
        if (src == 3 || src >= 5) m[2] = m[src + 2] = h;
        for (uint32_t s = sides; s < src; s++) m[((s - sides) & 1) * src + s] = h;
    } else {
        for (uint32_t k = 0; k < std::min(src, dst); k++) m[k * src + k] = 1.f;
    }
}

// ---- the effects: xaudio2fx.h's reverb and volume meter as IXAPO objects -------------------------
enum EffectKind { kReverb, kMeter };

struct Effect : Refcounted {
    EffectKind kind;
    uint32_t paramsHead = 0;              // its IXAPOParameters, the same native object
    std::vector<uint8_t> params;          // the last SetParameters
    float wetDry = 100.f;                 // XAUDIO2FX_REVERB_PARAMETERS.WetDryMix
    float peak[kMaxChannels] = {}, rms[kMaxChannels] = {};
    uint32_t levelChannels = 0;
    explicit Effect(EffectKind k) : kind(k) {}
    ~Effect() override { FreeObject(paramsHead); }

    uint32_t QueryInterface(uint32_t riid, uint32_t out) {
        if (!out) return win::E_POINTER;
        AddRef();
        *At<uint32_t>(out) = SameGuid(riid, kIidXapoParameters) ? paramsHead : self;
        return S_OK;
    }
    uint32_t AddRef_() { return AddRef(); }
    uint32_t Release_() { return Release(); }
    // IXAPO: what XAudio2 itself would call; nothing here asks
    uint32_t GetRegistrationProperties(uint32_t pp) {
        if (pp) *At<uint32_t>(pp) = 0;
        return win::E_NOTIMPL;
    }
    uint32_t IsFormatSupported(uint32_t, uint32_t, uint32_t supported) {
        if (supported) *At<uint32_t>(supported) = 0;
        return S_OK;
    }
    uint32_t Initialize(uint32_t, uint32_t) { return S_OK; }
    void Reset() {}
    uint32_t LockForProcess(uint32_t, uint32_t, uint32_t, uint32_t) { return S_OK; }
    void UnlockForProcess() {}
    void Process(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {}
    uint32_t CalcFrames(uint32_t n) { return n; }
    // IXAPOParameters (and the voices' SetEffectParameters/GetEffectParameters, the engine's lock held)
    void SetParameters(uint32_t p, uint32_t size) {
        if (!p) return;
        params.assign(At<uint8_t>(p), At<uint8_t>(p) + size);
        if (kind == kReverb && size >= 4) wetDry = std::max(0.f, std::min(100.f, Bits(U32(p))));
    }
    // the meter: XAUDIO2FX_VOLUMEMETER_LEVELS { float* pPeakLevels; float* pRMSLevels; UINT32 ChannelCount }
    void GetParameters(uint32_t p, uint32_t size) {
        if (!p) return;
        if (kind == kMeter && size >= 12) {
            uint32_t peaks = U32(p), rmss = U32(p + 4), n = std::min(U32(p + 8), levelChannels);
            for (uint32_t c = 0; c < n; c++) {
                if (peaks) memcpy(At(peaks + 4 * c), &peak[c], 4);
                if (rmss) memcpy(At(rmss + 4 * c), &rms[c], 4);
            }
            return;
        }
        memset(At(p), 0, size);
        memcpy(At(p), params.data(), std::min<size_t>(size, params.size()));
    }
    void Measure(const float* x, uint32_t ch, uint32_t frames) {
        levelChannels = std::min(ch, kMaxChannels);
        for (uint32_t c = 0; c < levelChannels; c++) {
            float pk = 0.f;
            double sq = 0.0;
            for (uint32_t f = 0; f < frames; f++) {
                float v = x[f * ch + c];
                pk = std::max(pk, fabsf(v));
                sq += static_cast<double>(v) * v;
            }
            peak[c] = pk;
            rms[c] = frames ? static_cast<float>(sqrt(sq / frames)) : 0.f;
        }
    }
};

uint32_t EffectVtable() {
    static uint32_t v = 0;
    static std::once_flag once;
    std::call_once(once, [] {
        const void* m[13] = {T_<&Effect::QueryInterface>(), T_<&Effect::AddRef_>(), T_<&Effect::Release_>(),
                             T_<&Effect::GetRegistrationProperties>(), T_<&Effect::IsFormatSupported>(),
                             T_<&Effect::IsFormatSupported>(), T_<&Effect::Initialize>(), T_<&Effect::Reset>(),
                             T_<&Effect::LockForProcess>(), T_<&Effect::UnlockForProcess>(), T_<&Effect::Process>(),
                             T_<&Effect::CalcFrames>(), T_<&Effect::CalcFrames>()};
        v = Vtable(m, 13);
    });
    return v;
}
uint32_t EffectParamsVtable() {
    static uint32_t v = 0;
    static std::once_flag once;
    std::call_once(once, [] {
        const void* m[5] = {T_<&Effect::QueryInterface>(), T_<&Effect::AddRef_>(), T_<&Effect::Release_>(),
                            T_<&Effect::SetParameters>(), T_<&Effect::GetParameters>()};
        v = Vtable(m, 5);
    });
    return v;
}
Effect* EffectOf(uint32_t obj) {
    if (!obj || !Native(obj)) return nullptr;
    uint32_t vt = At<Object32>(obj)->vtbl;
    return vt == EffectVtable() || vt == EffectParamsVtable() ? static_cast<Effect*>(Native(obj)) : nullptr;
}

uint32_t NewEffect(EffectKind kind) {
    auto e = new Effect(kind);
    e->self = NewObject(EffectVtable(), e);
    e->paramsHead = NewObject(EffectParamsVtable(), e);
    Log("XAudio2: %s effect %08x (passes the audio through%s)", kind == kReverb ? "reverb" : "volume meter", e->self,
        kind == kReverb ? ", keeping the dry part of WetDryMix" : ", measures its levels");
    return e->self;
}

// ---- voices -------------------------------------------------------------------------------------
enum Kind { kSource, kSubmix, kMaster };
struct Engine;
struct Voice;

struct Send {
    Voice* dst = nullptr;   // nullptr: the mastering voice (no sends list given)
    uint32_t src = 0, dch = 0;
    std::vector<float> m;   // dch x src
    void Fit(uint32_t s, uint32_t d) {
        if (s == src && d == dch && m.size() == s * d) return;
        src = s;
        dch = d;
        m.assign(s * d, 0.f);
        DefaultMatrix(s, d, m.data());
    }
};
struct Slot {
    uint32_t obj = 0;
    Effect* own = nullptr;   // ours; else an XAPO of the reference's
    bool enabled = true;
    uint32_t outCh = 0;
    std::vector<uint8_t> params;
};
// XAUDIO2_BUFFER (36 bytes) as submitted, with its play state
struct Buffer {
    uint32_t flags, data, playBegin, playEnd, loopBegin, loopEnd, loops, context;
    uint32_t pos = 0;
    bool begun = false;
};
// a callback the pass owes, fired after it without the lock: the voice's IXAudio2VoiceCallback slot
// (0 PassStart(bytes), 1 PassEnd, 2 StreamEnd, 3 BufferStart(ctx), 4 BufferEnd(ctx), 5 LoopEnd(ctx))
struct Event {
    uint64_t voice;
    uint32_t callback;
    uint32_t slot;
    uint32_t arg;
};

struct Voice {
    Engine* e = nullptr;
    uint32_t self = 0;
    uint64_t id = 0;
    Kind kind = kSource;
    uint32_t flags = 0, inCh = 0, inRate = 0, stage = 0;
    Format fmt;
    uint32_t callback = 0;
    float volume = 1.f;
    std::vector<float> chVol;
    std::vector<Send> sends;
    std::vector<Slot> effects;
    uint32_t filterType = 0;   // XAUDIO2_FILTER_PARAMETERS: LowPass, BandPass, HighPass, Notch
    float filterFreq = 1.f, filterQ = 1.f;
    std::vector<float> fstate;   // (low, band) per channel
    // a source voice
    bool started = false;
    std::deque<Buffer> queue;
    std::vector<uint32_t> flushed;   // contexts FlushSourceBuffers removed: OnBufferEnd next pass
    float ratio = 1.f, maxRatio = 2.f;
    double frac = 1.0;
    std::vector<float> prev, next;
    uint64_t played = 0;
    uint32_t cacheData = 0, cacheBlock = ~0u;
    std::vector<float> cache;
    // the pass's buffers: what is sent to this voice (submix, master), what it makes
    std::vector<float> in, work, tmp;

    uint32_t OutChannels() const {
        uint32_t ch = inCh;
        for (const Slot& s : effects) ch = s.outCh ? s.outCh : ch;
        return ch;
    }
    uint32_t Frames(uint32_t bytes) const {
        switch (fmt.codec) {
            case kAdpcm: return bytes / fmt.blockAlign * fmt.samplesPerBlock;
            case kWma: return fmt.avgBytes ? static_cast<uint32_t>(uint64_t(bytes) * fmt.rate / fmt.avgBytes) : 0;
            default: return bytes / fmt.blockAlign;
        }
    }
    void Read(const Buffer& b, uint32_t i, float* out);
    bool Pull(float* out, std::vector<Event>& ev);
    void Render(uint32_t frames, std::vector<Event>& ev);
    uint32_t BytesRequired(uint32_t frames) const;
    void Process(uint32_t frames);
    bool SetSends(uint32_t sendList);
    Send* SendTo(uint32_t dest);

    // IXAudio2Voice
    void GetVoiceDetails(uint32_t p);
    uint32_t SetOutputVoices(uint32_t sendList);
    uint32_t SetEffectChain(uint32_t chain);
    uint32_t EnableEffect(uint32_t k, uint32_t set);
    uint32_t DisableEffect(uint32_t k, uint32_t set);
    void GetEffectState(uint32_t k, uint32_t enabled);
    uint32_t SetEffectParameters(uint32_t k, uint32_t p, uint32_t size, uint32_t set);
    uint32_t GetEffectParameters(uint32_t k, uint32_t p, uint32_t size);
    uint32_t SetFilterParameters(uint32_t p, uint32_t set);
    void GetFilterParameters(uint32_t p);
    uint32_t SetOutputFilterParameters(uint32_t dest, uint32_t p, uint32_t set);
    void GetOutputFilterParameters(uint32_t dest, uint32_t p);
    uint32_t SetVolume(uint32_t bits, uint32_t set);
    void GetVolume(uint32_t p);
    uint32_t SetChannelVolumes(uint32_t n, uint32_t p, uint32_t set);
    void GetChannelVolumes(uint32_t n, uint32_t p);
    uint32_t SetOutputMatrix(uint32_t dest, uint32_t src, uint32_t dst, uint32_t p, uint32_t set);
    void GetOutputMatrix(uint32_t dest, uint32_t src, uint32_t dst, uint32_t p);
    void DestroyVoice();
    // IXAudio2SourceVoice
    uint32_t Start(uint32_t flags, uint32_t set);
    uint32_t Stop(uint32_t flags, uint32_t set);
    uint32_t SubmitSourceBuffer(uint32_t buffer, uint32_t wma);
    uint32_t FlushSourceBuffers();
    uint32_t Discontinuity();
    uint32_t ExitLoop(uint32_t set);
    void GetState(uint32_t p);
    uint32_t SetFrequencyRatio(uint32_t bits, uint32_t set);
    void GetFrequencyRatio(uint32_t p);
    uint32_t SetSourceSampleRate(uint32_t rate);
};

uint32_t VoiceVtable(Kind kind) {
    static uint32_t v[3] = {};
    static std::once_flag once;
    std::call_once(once, [] {
        const void* m[29] = {
            T_<&Voice::GetVoiceDetails>(), T_<&Voice::SetOutputVoices>(), T_<&Voice::SetEffectChain>(),
            T_<&Voice::EnableEffect>(), T_<&Voice::DisableEffect>(), T_<&Voice::GetEffectState>(),
            T_<&Voice::SetEffectParameters>(), T_<&Voice::GetEffectParameters>(), T_<&Voice::SetFilterParameters>(),
            T_<&Voice::GetFilterParameters>(), T_<&Voice::SetOutputFilterParameters>(),
            T_<&Voice::GetOutputFilterParameters>(), T_<&Voice::SetVolume>(), T_<&Voice::GetVolume>(),
            T_<&Voice::SetChannelVolumes>(), T_<&Voice::GetChannelVolumes>(), T_<&Voice::SetOutputMatrix>(),
            T_<&Voice::GetOutputMatrix>(), T_<&Voice::DestroyVoice>(),
            // 19: the source voice's own
            T_<&Voice::Start>(), T_<&Voice::Stop>(), T_<&Voice::SubmitSourceBuffer>(),
            T_<&Voice::FlushSourceBuffers>(), T_<&Voice::Discontinuity>(), T_<&Voice::ExitLoop>(),
            T_<&Voice::GetState>(), T_<&Voice::SetFrequencyRatio>(), T_<&Voice::GetFrequencyRatio>(),
            T_<&Voice::SetSourceSampleRate>()};
        v[kSource] = Vtable(m, 29);
        v[kSubmix] = Vtable(m, 19);   // (IXAudio2SubmixVoice and 2.7's IXAudio2MasteringVoice add nothing)
        v[kMaster] = Vtable(m, 19);
    });
    return v[kind];
}
Voice* VoiceOf(uint32_t obj) {
    if (!obj || !Native(obj)) return nullptr;
    uint32_t vt = At<Object32>(obj)->vtbl;
    for (Kind k : {kSource, kSubmix, kMaster})
        if (vt == VoiceVtable(k)) return static_cast<Voice*>(Native(obj));
    return nullptr;
}

// ---- the engine -----------------------------------------------------------------------------------
std::atomic<bool> g_hostPaused{false};

struct Engine {
    uint32_t self = 0;
    std::atomic<int> refs{1};
    std::mutex lock;
    std::condition_variable wake, cbDone, doneCv;
    std::vector<Voice*> voices;
    std::unordered_set<uint64_t> live;
    Voice* master = nullptr;
    std::vector<uint32_t> callbacks;   // IXAudio2EngineCallback
    uint64_t nextId = 1, inCallback = 0;
    bool running = true, quit = false, mixerStarted = false, done = false, orphan = false;
    uint32_t mixerTid = 0;
    uint32_t flags = 0, rate = 0, channels = 2, quantum = 480;
    // the device (the mixer's alone once it runs)
    AAudioStream* stream = nullptr;
    bool streamStarted = false;
    uint64_t retryAt = 0, paceNext = 0;
    std::atomic<int32_t> bufferFrames{0}, xruns{0};
    std::vector<float> mix;
    std::vector<Voice*> order;
    // GetPerformanceData's, under the lock
    uint64_t busyNs = 0, statSince = 0, passes = 0;
    uint32_t minNs = ~0u, maxNs = 0;

    bool Open();
    void CloseStream();
    void Run();
    void Pass();
    void Mix(std::vector<Event>& ev);
    void Output();
    void Pace();
    void Fire(const Event& e);
    void FireEngine(uint32_t cb, unsigned slot);
    void Destroy(Voice* v);
    uint32_t AddVoice(Voice* v, uint32_t out, uint32_t sends, uint32_t chain);

    // IXAudio2
    uint32_t QueryInterface(uint32_t riid, uint32_t out);
    uint32_t AddRef_() { return static_cast<uint32_t>(++refs); }
    uint32_t Release_();
    uint32_t GetDeviceCount(uint32_t p);
    uint32_t GetDeviceDetails(uint32_t index, uint32_t p);
    uint32_t Initialize(uint32_t flags, uint32_t processor);
    uint32_t RegisterForCallbacks(uint32_t cb);
    void UnregisterForCallbacks(uint32_t cb);
    uint32_t CreateSourceVoice(uint32_t out, uint32_t format, uint32_t flags, uint32_t maxRatio, uint32_t cb,
                               uint32_t sends, uint32_t chain);
    uint32_t CreateSubmixVoice(uint32_t out, uint32_t ch, uint32_t rate, uint32_t flags, uint32_t stage,
                               uint32_t sends, uint32_t chain);
    uint32_t CreateMasteringVoice(uint32_t out, uint32_t ch, uint32_t rate, uint32_t flags, uint32_t device,
                                  uint32_t chain);
    uint32_t StartEngine();
    void StopEngine();
    uint32_t CommitChanges(uint32_t set);
    void GetPerformanceData(uint32_t p);
    void SetDebugConfiguration(uint32_t, uint32_t) {}
};

std::mutex g_enginesLock;
std::vector<Engine*> g_engines;

uint32_t EngineVtable() {
    static uint32_t v = 0;
    static std::once_flag once;
    std::call_once(once, [] {
        const void* m[16] = {T_<&Engine::QueryInterface>(), T_<&Engine::AddRef_>(), T_<&Engine::Release_>(),
                             T_<&Engine::GetDeviceCount>(), T_<&Engine::GetDeviceDetails>(), T_<&Engine::Initialize>(),
                             T_<&Engine::RegisterForCallbacks>(), T_<&Engine::UnregisterForCallbacks>(),
                             T_<&Engine::CreateSourceVoice>(), T_<&Engine::CreateSubmixVoice>(),
                             T_<&Engine::CreateMasteringVoice>(), T_<&Engine::StartEngine>(), T_<&Engine::StopEngine>(),
                             T_<&Engine::CommitChanges>(), T_<&Engine::GetPerformanceData>(),
                             T_<&Engine::SetDebugConfiguration>()};
        v = Vtable(m, 16);
    });
    return v;
}

// the reference's effects: XAudio2 holds a reference on each in a chain (AddRef/Release, slots 1/2)
void HoldEffects(const std::vector<Slot>& fx) {
    for (const Slot& s : fx) {
        if (s.own) s.own->AddRef();
        else if (s.obj) CallMethod(s.obj, 1);
    }
}
void ReleaseEffects(const std::vector<Slot>& fx) {
    for (const Slot& s : fx) {
        if (s.own) s.own->Release();
        else if (s.obj) CallMethod(s.obj, 2);
    }
}
// XAUDIO2_EFFECT_CHAIN { EffectCount, pEffectDescriptors }, each { pEffect, InitialState, OutputChannels }
bool ReadChain(uint32_t chain, std::vector<Slot>* out) {
    out->clear();
    if (!chain) return true;
    uint32_t n = U32(chain), d = U32(chain + 4);
    if (n > 64 || (n && !d)) return false;
    for (uint32_t k = 0; k < n; k++, d += 12) {
        Slot s;
        s.obj = U32(d);
        s.own = EffectOf(s.obj);
        s.enabled = U32(d + 4) != 0;
        s.outCh = U32(d + 8);
        if (!s.obj || s.outCh > kMaxChannels) return false;
        if (!s.own) LogOnce("xa2-xapo", "XAudio2: the reference's own XAPO %08x in an effect chain: passed through, not run", s.obj);
        out->push_back(s);
    }
    return true;
}

// ---- Voice: the mixer's side (the engine's lock held) ----------------------------------------------
void Voice::Read(const Buffer& b, uint32_t i, float* out) {
    const uint32_t ch = fmt.channels;
    const uint32_t at = b.data + i * fmt.blockAlign;
    switch (fmt.codec) {
        case kPcm8: {
            auto s = At<uint8_t>(at);
            for (uint32_t c = 0; c < ch; c++) out[c] = (s[c] - 128) * (1.f / 128.f);
            break;
        }
        case kPcm16: {
            auto s = At<uint8_t>(at);
            for (uint32_t c = 0; c < ch; c++) {
                int16_t v;
                memcpy(&v, s + 2 * c, 2);
                out[c] = v * (1.f / 32768.f);
            }
            break;
        }
        case kPcm24: {
            auto s = At<uint8_t>(at);
            for (uint32_t c = 0; c < ch; c++, s += 3) {
                int32_t v = static_cast<int32_t>(static_cast<uint32_t>(s[0] | s[1] << 8 | s[2] << 16) << 8) >> 8;
                out[c] = v * (1.f / 8388608.f);
            }
            break;
        }
        case kPcm32: {
            auto s = At<uint8_t>(at);
            for (uint32_t c = 0; c < ch; c++) {
                int32_t v;
                memcpy(&v, s + 4 * c, 4);
                out[c] = v * (1.f / 2147483648.f);
            }
            break;
        }
        case kFloat32:
            memcpy(out, At(at), ch * 4);
            break;
        case kAdpcm: {
            uint32_t block = i / fmt.samplesPerBlock;
            if (cacheData != b.data || cacheBlock != block) {
                cache.resize(fmt.samplesPerBlock * ch);
                DecodeAdpcm(At<uint8_t>(b.data + block * fmt.blockAlign), fmt, cache.data());
                cacheData = b.data;
                cacheBlock = block;
            }
            memcpy(out, &cache[(i % fmt.samplesPerBlock) * ch], ch * 4);
            break;
        }
        case kWma:
            std::fill(out, out + ch, 0.f);
            break;
    }
}

// the next source frame of the queue: false when it is empty (the voice starved). The buffer
// callbacks as XAudio2 orders them: OnBufferStart, OnLoopEnd per loop, OnBufferEnd, OnStreamEnd
bool Voice::Pull(float* out, std::vector<Event>& ev) {
    while (!queue.empty()) {
        Buffer& b = queue.front();
        if (!b.begun) {
            b.begun = true;
            b.pos = b.playBegin;
            if (callback) ev.push_back({id, callback, 3, b.context});
        }
        if (b.loops && b.pos >= b.loopEnd) {
            if (b.loops != kLoopInfinite) b.loops--;
            b.pos = b.loopBegin;
            if (callback) ev.push_back({id, callback, 5, b.context});
        }
        if (b.pos < b.playEnd) {
            Read(b, b.pos++, out);
            played++;
            return true;
        }
        if (callback) ev.push_back({id, callback, 4, b.context});
        if (b.flags & kEndOfStream) {
            if (callback) ev.push_back({id, callback, 2, 0});
            played = 0;   // (SamplesPlayed: since the last stream ended)
        }
        queue.pop_front();
    }
    return false;
}

// `frames` output frames at the engine's rate into work (the format's channels), linear between
// source frames
void Voice::Render(uint32_t frames, std::vector<Event>& ev) {
    const uint32_t ch = fmt.channels;
    work.resize(frames * ch);
    prev.resize(ch, 0.f);
    next.resize(ch, 0.f);
    const double step = static_cast<double>(ratio) * fmt.rate / e->rate;
    for (uint32_t f = 0; f < frames; f++) {
        while (frac >= 1.0) {
            prev.swap(next);
            if (!Pull(next.data(), ev)) std::fill(next.begin(), next.end(), 0.f);
            frac -= 1.0;
        }
        const float t = static_cast<float>(frac);
        for (uint32_t c = 0; c < ch; c++) work[f * ch + c] = prev[c] + (next[c] - prev[c]) * t;
        frac += step;
    }
}

// OnVoiceProcessingPassStart's BytesRequired: what the next pass reads beyond what is queued
uint32_t Voice::BytesRequired(uint32_t frames) const {
    double need = frames * static_cast<double>(ratio) * fmt.rate / e->rate + 2.0;
    double have = 0;
    for (const Buffer& b : queue) {
        if (b.loops == kLoopInfinite) return 0;
        have += (b.begun ? b.playEnd - std::min(b.pos, b.playEnd) : b.playEnd - b.playBegin) +
                double(b.loops) * (b.loopEnd - b.loopBegin);
        if (have >= need) return 0;
    }
    auto missing = static_cast<uint32_t>(ceil(need - have));
    if (fmt.codec == kAdpcm) return (missing + fmt.samplesPerBlock - 1) / fmt.samplesPerBlock * fmt.blockAlign;
    if (fmt.codec == kWma) return static_cast<uint32_t>(uint64_t(missing) * fmt.avgBytes / fmt.rate);
    return missing * fmt.blockAlign;
}

// work (inCh channels) through the filter, the effects, the volumes, then into the destinations'
// inputs
void Voice::Process(uint32_t frames) {
    uint32_t ch = inCh;
    // the state-variable filter (XAudio2's, FAudio's formulation), skipped when wide open
    bool wide = (filterType == 0 && filterFreq >= 1.f) || (filterType == 2 && filterFreq <= 0.f);
    if ((flags & kUseFilter) && !wide) {
        fstate.resize(ch * 2, 0.f);
        for (uint32_t f = 0; f < frames; f++)
            for (uint32_t c = 0; c < ch; c++) {
                float& low = fstate[c * 2];
                float& band = fstate[c * 2 + 1];
                float x = work[f * ch + c];
                low += filterFreq * band;
                float high = x - low - filterQ * band;
                band += filterFreq * high;
                if (fabsf(low) < 1e-20f) low = 0.f;
                if (fabsf(band) < 1e-20f) band = 0.f;
                float y = filterType == 0 ? low : filterType == 1 ? band : filterType == 2 ? high : high + low;
                work[f * ch + c] = y;
            }
    }
    // the effects: each its own channel count out; ours applied, the reference's passed through
    for (Slot& s : effects) {
        uint32_t oc = s.outCh ? s.outCh : ch;
        if (oc != ch) {
            float m[kMaxChannels * kMaxChannels];
            DefaultMatrix(ch, oc, m);
            tmp.assign(frames * oc, 0.f);
            for (uint32_t f = 0; f < frames; f++)
                for (uint32_t d = 0; d < oc; d++) {
                    float sum = 0.f;
                    for (uint32_t c = 0; c < ch; c++) sum += m[d * ch + c] * work[f * ch + c];
                    tmp[f * oc + d] = sum;
                }
            work.swap(tmp);
            ch = oc;
        }
        if (!s.enabled || !s.own) continue;
        if (s.own->kind == kMeter) {
            s.own->Measure(work.data(), ch, frames);
        } else {
            LogOnce("xa2-reverb", "XAudio2: reverb: no reverberation here, the dry part of WetDryMix only");
            float dry = 1.f - s.own->wetDry / 100.f;
            for (float& x : work) x *= dry;
        }
    }
    if (chVol.size() != ch) chVol.assign(ch, 1.f);
    for (uint32_t f = 0; f < frames; f++)
        for (uint32_t c = 0; c < ch; c++) work[f * ch + c] *= volume * chVol[c];
    if (kind == kMaster) return;
    for (Send& s : sends) {
        Voice* d = s.dst ? s.dst : e->master;
        if (!d || d == this) continue;
        const uint32_t dch = d->inCh;
        d->in.resize(frames * dch, 0.f);
        s.Fit(ch, dch);
        for (uint32_t f = 0; f < frames; f++)
            for (uint32_t k = 0; k < dch; k++) {
                const float* row = &s.m[k * ch];
                float sum = 0.f;
                for (uint32_t c = 0; c < ch; c++) sum += row[c] * work[f * ch + c];
                d->in[f * dch + k] += sum;
            }
    }
}

// XAUDIO2_VOICE_SENDS { SendCount, pSends }, each XAUDIO2_SEND_DESCRIPTOR { Flags, pOutputVoice };
// none given: the mastering voice
bool Voice::SetSends(uint32_t sendList) {
    std::vector<Send> next;
    if (!sendList) {
        next.emplace_back();
    } else {
        uint32_t n = U32(sendList), d = U32(sendList + 4);
        if (n > 64 || (n && !d)) return false;
        for (uint32_t k = 0; k < n; k++, d += 8) {
            Send s;
            s.dst = VoiceOf(U32(d + 4));
            if (!s.dst || s.dst == this || s.dst->kind == kSource) return false;
            if (U32(d) & 0x80) LogOnce("xa2-sendfilter", "XAudio2: send filters (XAUDIO2_SEND_USEFILTER) not applied");
            next.push_back(std::move(s));
        }
    }
    sends.swap(next);
    return true;
}
Send* Voice::SendTo(uint32_t dest) {
    if (!dest) return sends.size() == 1 ? &sends[0] : nullptr;
    Voice* d = VoiceOf(dest);
    for (Send& s : sends)
        if ((s.dst ? s.dst : e->master) == d) return &s;
    return nullptr;
}

// ---- Voice: the reference's calls ------------------------------------------------------------------
// XAUDIO2_VOICE_DETAILS (2.7): CreationFlags, InputChannels, InputSampleRate
void Voice::GetVoiceDetails(uint32_t p) {
    if (!p) return;
    uint32_t d[3] = {flags, inCh, inRate};
    memcpy(At(p), d, sizeof d);
}
uint32_t Voice::SetOutputVoices(uint32_t sendList) {
    std::lock_guard<std::mutex> hold(e->lock);
    return SetSends(sendList) ? S_OK : kInvalidCall;
}
uint32_t Voice::SetEffectChain(uint32_t chain) {
    std::vector<Slot> fx;
    if (!ReadChain(chain, &fx)) return kInvalidCall;
    HoldEffects(fx);
    {
        std::lock_guard<std::mutex> hold(e->lock);
        effects.swap(fx);
    }
    ReleaseEffects(fx);   // (the old chain, without the lock: the reference's Release may lock its own)
    return S_OK;
}
uint32_t Voice::EnableEffect(uint32_t k, uint32_t set) {
    OperationSet(set);
    std::lock_guard<std::mutex> hold(e->lock);
    if (k >= effects.size()) return kInvalidCall;
    effects[k].enabled = true;
    return S_OK;
}
uint32_t Voice::DisableEffect(uint32_t k, uint32_t set) {
    OperationSet(set);
    std::lock_guard<std::mutex> hold(e->lock);
    if (k >= effects.size()) return kInvalidCall;
    effects[k].enabled = false;
    return S_OK;
}
void Voice::GetEffectState(uint32_t k, uint32_t enabled) {
    std::lock_guard<std::mutex> hold(e->lock);
    if (enabled) *At<uint32_t>(enabled) = k < effects.size() && effects[k].enabled ? 1 : 0;
}
uint32_t Voice::SetEffectParameters(uint32_t k, uint32_t p, uint32_t size, uint32_t set) {
    OperationSet(set);
    std::lock_guard<std::mutex> hold(e->lock);
    if (k >= effects.size() || !p) return kInvalidCall;
    Slot& s = effects[k];
    if (s.own) {
        s.own->SetParameters(p, size);
    } else {
        LogOnce("xa2-xapoparams", "XAudio2: parameters for the reference's own XAPO kept, not passed to it");
        s.params.assign(At<uint8_t>(p), At<uint8_t>(p) + size);
    }
    return S_OK;
}
uint32_t Voice::GetEffectParameters(uint32_t k, uint32_t p, uint32_t size) {
    std::lock_guard<std::mutex> hold(e->lock);
    if (k >= effects.size() || !p) return kInvalidCall;
    Slot& s = effects[k];
    if (s.own) {
        s.own->GetParameters(p, size);
    } else {
        memset(At(p), 0, size);
        memcpy(At(p), s.params.data(), std::min<size_t>(size, s.params.size()));
    }
    return S_OK;
}
// XAUDIO2_FILTER_PARAMETERS { Type, float Frequency, float OneOverQ }
uint32_t Voice::SetFilterParameters(uint32_t p, uint32_t set) {
    OperationSet(set);
    if (!p || U32(p) > 3) return kInvalidCall;
    std::lock_guard<std::mutex> hold(e->lock);
    filterType = U32(p);
    filterFreq = std::max(0.f, std::min(1.f, Bits(U32(p + 4))));
    filterQ = std::max(0.f, std::min(1.5f, Bits(U32(p + 8))));
    return S_OK;
}
void Voice::GetFilterParameters(uint32_t p) {
    if (!p) return;
    std::lock_guard<std::mutex> hold(e->lock);
    *At<uint32_t>(p) = filterType;
    memcpy(At(p + 4), &filterFreq, 4);
    memcpy(At(p + 8), &filterQ, 4);
}
uint32_t Voice::SetOutputFilterParameters(uint32_t, uint32_t, uint32_t set) {
    OperationSet(set);
    LogOnce("xa2-outfilter", "XAudio2: SetOutputFilterParameters accepted, not applied");
    return S_OK;
}
void Voice::GetOutputFilterParameters(uint32_t, uint32_t p) {
    if (!p) return;
    const float one = 1.f;
    *At<uint32_t>(p) = 0;
    memcpy(At(p + 4), &one, 4);
    memcpy(At(p + 8), &one, 4);
}
uint32_t Voice::SetVolume(uint32_t bits, uint32_t set) {
    OperationSet(set);
    float v = Bits(bits);
    if (!(v == v)) return win::E_INVALIDARG;   // (NaN)
    std::lock_guard<std::mutex> hold(e->lock);
    volume = std::max(-16777216.f, std::min(16777216.f, v));
    return S_OK;
}
void Voice::GetVolume(uint32_t p) {
    std::lock_guard<std::mutex> hold(e->lock);
    if (p) memcpy(At(p), &volume, 4);
}
uint32_t Voice::SetChannelVolumes(uint32_t n, uint32_t p, uint32_t set) {
    OperationSet(set);
    std::lock_guard<std::mutex> hold(e->lock);
    if (!p || n != OutChannels()) return win::E_INVALIDARG;
    chVol.resize(n);
    memcpy(chVol.data(), At(p), n * 4);
    return S_OK;
}
void Voice::GetChannelVolumes(uint32_t n, uint32_t p) {
    std::lock_guard<std::mutex> hold(e->lock);
    if (!p) return;
    uint32_t ch = OutChannels();
    for (uint32_t c = 0; c < n; c++) {
        float v = c < chVol.size() && chVol.size() == ch ? chVol[c] : 1.f;
        memcpy(At(p + 4 * c), &v, 4);
    }
}
uint32_t Voice::SetOutputMatrix(uint32_t dest, uint32_t src, uint32_t dst, uint32_t p, uint32_t set) {
    OperationSet(set);
    std::lock_guard<std::mutex> hold(e->lock);
    Send* s = SendTo(dest);
    Voice* d = s ? (s->dst ? s->dst : e->master) : nullptr;
    if (!s || !d || !p || src != OutChannels() || dst != d->inCh) {
        LogOnce("xa2-matrix", "XAudio2: SetOutputMatrix(%08x, %u, %u) refused: no such send, or not its size", dest, src, dst);
        return kInvalidCall;
    }
    s->src = src;
    s->dch = dst;
    s->m.resize(src * dst);
    memcpy(s->m.data(), At(p), src * dst * 4);
    return S_OK;
}
void Voice::GetOutputMatrix(uint32_t dest, uint32_t src, uint32_t dst, uint32_t p) {
    std::lock_guard<std::mutex> hold(e->lock);
    Send* s = SendTo(dest);
    if (!s || !p || src > kMaxChannels || dst > kMaxChannels) return;
    s->Fit(src, dst);
    memcpy(At(p), s->m.data(), src * dst * 4);
}
void Voice::DestroyVoice() { e->Destroy(this); }

uint32_t Voice::Start(uint32_t, uint32_t set) {
    OperationSet(set);
    std::lock_guard<std::mutex> hold(e->lock);
    started = true;
    return S_OK;
}
uint32_t Voice::Stop(uint32_t, uint32_t set) {
    OperationSet(set);
    std::lock_guard<std::mutex> hold(e->lock);
    started = false;
    return S_OK;
}
// XAUDIO2_BUFFER: Flags, AudioBytes, pAudioData, PlayBegin, PlayLength, LoopBegin, LoopLength,
// LoopCount, pContext. Copied; its data stays the reference's until OnBufferEnd
uint32_t Voice::SubmitSourceBuffer(uint32_t buffer, uint32_t) {
    if (!buffer) return kInvalidCall;
    uint32_t w[9];
    memcpy(w, At(buffer), sizeof w);
    Buffer b;
    b.flags = w[0];
    b.data = w[2];
    const uint32_t total = Frames(w[1]);
    if ((w[1] && !b.data) || (total && w[3] >= total)) return kInvalidCall;
    b.playBegin = w[3];
    b.playEnd = std::max(b.playBegin, w[4] ? std::min(total, w[3] + w[4]) : total);
    b.loops = w[7];
    b.loopBegin = w[5];
    b.loopEnd = w[6] ? w[5] + w[6] : b.playEnd;
    b.context = w[8];
    if (b.loops && (b.loopEnd > b.playEnd || b.loopBegin >= b.loopEnd || b.loopEnd <= b.playBegin)) {
        LogOnce("xa2-badloop", "XAudio2: a buffer's loop region [%u, %u) outside its play region [%u, %u): refused",
                b.loopBegin, b.loopEnd, b.playBegin, b.playEnd);
        return kInvalidCall;
    }
    std::lock_guard<std::mutex> hold(e->lock);
    if (queue.size() >= kMaxQueued) return kInvalidCall;
    queue.push_back(b);
    return S_OK;
}
// the buffers not yet playing (all of them, the voice stopped), each with OnBufferEnd next pass
uint32_t Voice::FlushSourceBuffers() {
    std::lock_guard<std::mutex> hold(e->lock);
    auto from = queue.begin();
    if (started && from != queue.end() && from->begun) ++from;
    for (auto it = from; it != queue.end(); ++it) flushed.push_back(it->context);
    queue.erase(from, queue.end());
    return S_OK;
}
uint32_t Voice::Discontinuity() { return S_OK; }
uint32_t Voice::ExitLoop(uint32_t set) {
    OperationSet(set);
    std::lock_guard<std::mutex> hold(e->lock);
    if (!queue.empty()) queue.front().loops = 0;
    return S_OK;
}
// XAUDIO2_VOICE_STATE (2.7, packed): pCurrentBufferContext, BuffersQueued, UINT64 SamplesPlayed
void Voice::GetState(uint32_t p) {
    if (!p) return;
    std::lock_guard<std::mutex> hold(e->lock);
    uint32_t w[2] = {queue.empty() ? 0 : queue.front().context, static_cast<uint32_t>(queue.size())};
    memcpy(At(p), w, 8);
    memcpy(At(p + 8), &played, 8);
}
uint32_t Voice::SetFrequencyRatio(uint32_t bits, uint32_t set) {
    OperationSet(set);
    float r = Bits(bits);
    if (!(r == r)) return win::E_INVALIDARG;
    std::lock_guard<std::mutex> hold(e->lock);
    ratio = std::max(1.f / 1024.f, std::min(maxRatio, r));
    return S_OK;
}
void Voice::GetFrequencyRatio(uint32_t p) {
    std::lock_guard<std::mutex> hold(e->lock);
    if (p) memcpy(At(p), &ratio, 4);
}
uint32_t Voice::SetSourceSampleRate(uint32_t rate) {
    if (rate < 1000 || rate > 200000) return win::E_INVALIDARG;
    std::lock_guard<std::mutex> hold(e->lock);
    if (!queue.empty()) return kInvalidCall;
    fmt.rate = inRate = rate;
    return S_OK;
}

// ---- Engine: the device ------------------------------------------------------------------------------
// a float stream, low latency, shared; the first at the device's own rate (the engine's then), a
// reopened one at the engine's. Its buffer: about three quanta
bool Engine::Open() {
    AAudioStreamBuilder* b = nullptr;
    if (AAudio_createStreamBuilder(&b) != AAUDIO_OK) return false;
    AAudioStreamBuilder_setDirection(b, AAUDIO_DIRECTION_OUTPUT);
    AAudioStreamBuilder_setSharingMode(b, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setPerformanceMode(b, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_FLOAT);
    AAudioStreamBuilder_setChannelCount(b, 2);
    if (rate) AAudioStreamBuilder_setSampleRate(b, static_cast<int32_t>(rate));
    AAudioStreamBuilder_setUsage(b, AAUDIO_USAGE_GAME);
    AAudioStreamBuilder_setContentType(b, AAUDIO_CONTENT_TYPE_MUSIC);
    AAudioStream* s = nullptr;
    aaudio_result_t r = AAudioStreamBuilder_openStream(b, &s);
    AAudioStreamBuilder_delete(b);
    if (r != AAUDIO_OK || !s) {
        Log("XAudio2: AAudio stream not opened: %s", AAudio_convertResultToText(r));
        return false;
    }
    int32_t got = AAudioStream_getSampleRate(s), ch = AAudioStream_getChannelCount(s);
    if (got <= 0 || ch <= 0 || ch > 8) {
        Log("XAudio2: AAudio stream of %d Hz, %d channels: not usable", got, ch);
        AAudioStream_close(s);
        return false;
    }
    if (!rate) rate = static_cast<uint32_t>(got);
    else if (static_cast<uint32_t>(got) != rate) Log("XAudio2: the device reopened at %d Hz, the engine mixes at %u", got, rate);
    quantum = std::max(1u, rate / 100);
    channels = static_cast<uint32_t>(ch);
    int32_t burst = AAudioStream_getFramesPerBurst(s), cap = AAudioStream_getBufferCapacityInFrames(s);
    int32_t want = std::max(burst * 2, static_cast<int32_t>(quantum * 3));
    if (cap > 0) want = std::min(want, cap);
    AAudioStream_setBufferSizeInFrames(s, want);
    bufferFrames = AAudioStream_getBufferSizeInFrames(s);
    stream = s;
    streamStarted = false;
    Log("XAudio2: AAudio stream %d Hz, %d channels, burst %d, buffer %d of %d frames, %s", got, ch, burst,
        bufferFrames.load(), cap,
        AAudioStream_getPerformanceMode(s) == AAUDIO_PERFORMANCE_MODE_LOW_LATENCY ? "low latency" : "not low latency");
    return true;
}
void Engine::CloseStream() {
    if (!stream) return;
    AAudioStream_requestStop(stream);
    AAudioStream_close(stream);
    stream = nullptr;
    streamStarted = false;
}

// the next quantum by the clock (no device, or the host paused)
void Engine::Pace() {
    const uint64_t q = uint64_t(quantum) * 1000000000ull / rate, now = NowNs();
    if (paceNext + 200000000ull < now) paceNext = now;
    paceNext += q;
    timespec t = {static_cast<time_t>(paceNext / 1000000000ull), static_cast<long>(paceNext % 1000000000ull)};
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, nullptr);
}

void Engine::Output() {
    if (g_hostPaused) {
        if (streamStarted) {
            AAudioStream_requestPause(stream);
            streamStarted = false;
        }
        Pace();
        return;
    }
    if (!stream) {
        uint64_t now = NowMs();
        if (now >= retryAt) {
            retryAt = now + 2000;
            if (Open()) Log("XAudio2: the device is back");
        }
        if (!stream) return Pace();
    }
    if (!streamStarted) {
        aaudio_result_t r = AAudioStream_requestStart(stream);
        if (r != AAUDIO_OK) LogOnce("xa2-start", "XAudio2: AAudio start: %s", AAudio_convertResultToText(r));
        streamStarted = true;
    }
    aaudio_result_t r = AAudioStream_write(stream, mix.data(), static_cast<int32_t>(quantum), 200000000ll);
    if (r < 0) {
        Log("XAudio2: AAudio write: %s", AAudio_convertResultToText(r));
        if (r == AAUDIO_ERROR_DISCONNECTED || AAudioStream_getState(stream) == AAUDIO_STREAM_STATE_DISCONNECTED) {
            Log("XAudio2: the device went away (a headset unplugged?): reopening");
            CloseStream();
            retryAt = 0;
        }
        return Pace();
    }
    xruns = AAudioStream_getXRunCount(stream);
    paceNext = NowNs();
}

// ---- Engine: the mixer thread ----------------------------------------------------------------------
void MixerMain(void* p) { static_cast<Engine*>(p)->Run(); }

void Engine::Run() {
    for (;;) {
        {
            std::unique_lock<std::mutex> lk(lock);
            if (!quit && !(running && master)) {
                lk.unlock();
                if (streamStarted) {
                    AAudioStream_requestPause(stream);
                    streamStarted = false;
                }
                lk.lock();
                wake.wait(lk, [&] { return quit || (running && master); });
                paceNext = NowNs();
            }
            if (quit) break;
        }
        Pass();
        Output();
    }
    bool del;
    {
        std::lock_guard<std::mutex> hold(lock);
        done = true;
        del = orphan;
        doneCv.notify_all();
    }
    if (del) {
        CloseStream();
        delete this;
    }
}

// a reference callback, unless its voice was destroyed meanwhile; DestroyVoice from another thread
// waits for the one in progress
void Engine::Fire(const Event& ev) {
    {
        std::lock_guard<std::mutex> hold(lock);
        if (!live.count(ev.voice)) return;
        inCallback = ev.voice;
    }
    if (ev.slot == 1 || ev.slot == 2) CallMethod(ev.callback, ev.slot);
    else CallMethod(ev.callback, ev.slot, ev.arg);
    {
        std::lock_guard<std::mutex> hold(lock);
        inCallback = 0;
    }
    cbDone.notify_all();
}
void Engine::FireEngine(uint32_t cb, unsigned slot) {
    {
        std::lock_guard<std::mutex> hold(lock);
        if (std::find(callbacks.begin(), callbacks.end(), cb) == callbacks.end()) return;
    }
    CallMethod(cb, slot);
}

void Engine::Pass() {
    std::vector<Event> pre, ev;
    std::vector<uint32_t> ecb;
    {
        std::lock_guard<std::mutex> hold(lock);
        ecb = callbacks;
        for (Voice* v : voices)
            if (v->kind == kSource && v->started && v->callback)
                pre.push_back({v->id, v->callback, 0, v->BytesRequired(quantum)});
    }
    for (uint32_t cb : ecb) FireEngine(cb, 0);   // OnProcessingPassStart
    for (const Event& e : pre) Fire(e);           // OnVoiceProcessingPassStart(BytesRequired)
    {
        std::lock_guard<std::mutex> hold(lock);
        uint64_t t0 = NowNs();
        Mix(ev);
        auto ns = static_cast<uint32_t>(std::min<uint64_t>(NowNs() - t0, ~0u));
        busyNs += ns;
        minNs = std::min(minNs, ns);
        maxNs = std::max(maxNs, ns);
        passes++;
    }
    for (const Event& e : ev) Fire(e);
    for (uint32_t cb : ecb) FireEngine(cb, 1);   // OnProcessingPassEnd
}

void Engine::Mix(std::vector<Event>& ev) {
    const uint32_t F = quantum;
    for (Voice* v : voices) {
        if (v->kind != kSource) continue;
        for (uint32_t ctx : v->flushed)
            if (v->callback) ev.push_back({v->id, v->callback, 4, ctx});
        v->flushed.clear();
        if (!v->started) continue;
        v->Render(F, ev);
        v->Process(F);
        if (v->callback) ev.push_back({v->id, v->callback, 1, 0});
    }
    // the submixes by processing stage (a send to a stage already mixed is heard the next pass)
    order.clear();
    for (Voice* v : voices)
        if (v->kind == kSubmix) order.push_back(v);
    std::stable_sort(order.begin(), order.end(), [](Voice* a, Voice* b) { return a->stage < b->stage; });
    for (Voice* v : order) {
        v->in.resize(F * v->inCh, 0.f);
        v->work.assign(v->in.begin(), v->in.end());
        std::fill(v->in.begin(), v->in.end(), 0.f);
        v->Process(F);
    }
    mix.assign(F * channels, 0.f);
    if (Voice* m = master) {
        m->in.resize(F * m->inCh, 0.f);
        m->work.assign(m->in.begin(), m->in.end());
        std::fill(m->in.begin(), m->in.end(), 0.f);
        m->Process(F);
        const uint32_t ch = m->OutChannels();
        float dm[kMaxChannels * kMaxChannels];
        DefaultMatrix(ch, channels, dm);
        for (uint32_t f = 0; f < F; f++)
            for (uint32_t d = 0; d < channels; d++) {
                float sum = 0.f;
                for (uint32_t c = 0; c < ch; c++) sum += dm[d * ch + c] * m->work[f * ch + c];
                mix[f * channels + d] = std::max(-1.f, std::min(1.f, sum));
            }
    }
}

// ---- Engine: voices ----------------------------------------------------------------------------------
uint32_t Engine::AddVoice(Voice* v, uint32_t out, uint32_t sends, uint32_t chain) {
    v->e = this;
    std::vector<Slot> fx;
    if (!ReadChain(chain, &fx)) {
        delete v;
        return kInvalidCall;
    }
    {
        std::lock_guard<std::mutex> hold(lock);
        if (v->kind != kMaster && !v->SetSends(sends)) {
            delete v;
            return kInvalidCall;
        }
    }
    HoldEffects(fx);
    v->effects.swap(fx);
    v->self = NewObject(VoiceVtable(v->kind), v);
    {
        std::lock_guard<std::mutex> hold(lock);
        v->id = nextId++;
        voices.push_back(v);
        live.insert(v->id);
        if (v->kind == kMaster) master = v;
    }
    wake.notify_all();
    *At<uint32_t>(out) = v->self;
    return S_OK;
}

void Engine::Destroy(Voice* v) {
    std::vector<Slot> fx;
    {
        std::unique_lock<std::mutex> lk(lock);
        auto it = std::find(voices.begin(), voices.end(), v);
        if (it == voices.end()) return;
        voices.erase(it);
        live.erase(v->id);
        if (master == v) master = nullptr;
        for (Voice* o : voices)
            for (size_t k = o->sends.size(); k-- > 0;)
                if (o->sends[k].dst == v) {
                    LogOnce("xa2-destroysent", "XAudio2: a voice destroyed while others still send to it");
                    o->sends.erase(o->sends.begin() + static_cast<long>(k));
                }
        fx.swap(v->effects);
        if (CurrentThreadId() != mixerTid)
            cbDone.wait_for(lk, std::chrono::milliseconds(200), [&] { return inCallback != v->id; });
    }
    ReleaseEffects(fx);
    FreeObject(v->self);
    delete v;
}

// ---- Engine: the reference's calls -----------------------------------------------------------------
uint32_t Engine::QueryInterface(uint32_t riid, uint32_t out) {
    if (!out) return win::E_POINTER;
    if (SameGuid(riid, kIidXAudio2) || SameGuid(riid, kIidUnknown)) {
        ++refs;
        *At<uint32_t>(out) = self;
        return S_OK;
    }
    *At<uint32_t>(out) = 0;
    return win::E_NOINTERFACE;
}

uint32_t Engine::Release_() {
    int r = --refs;
    if (r > 0) return static_cast<uint32_t>(r);
    if (r < 0) return 0;
    {
        std::lock_guard<std::mutex> hold(g_enginesLock);
        g_engines.erase(std::remove(g_engines.begin(), g_engines.end(), this), g_engines.end());
    }
    FreeObject(self);
    std::vector<Voice*> vs;
    bool del;
    {
        std::unique_lock<std::mutex> lk(lock);
        quit = true;
        wake.notify_all();
        if (mixerStarted && CurrentThreadId() != mixerTid)
            doneCv.wait_for(lk, std::chrono::seconds(2), [&] { return done; });
        vs.swap(voices);
        live.clear();
        callbacks.clear();
        master = nullptr;
        del = !mixerStarted || done;
        if (!del) orphan = true;   // (the mixer, inside a callback still, deletes the engine as it leaves)
    }
    for (Voice* v : vs) {
        ReleaseEffects(v->effects);
        FreeObject(v->self);
        delete v;
    }
    Log("XAudio2: engine released (%zu voices left)", vs.size());
    if (del) {
        CloseStream();
        delete this;
    }
    return 0;
}

uint32_t Engine::GetDeviceCount(uint32_t p) {
    if (p) *At<uint32_t>(p) = 1;
    return S_OK;
}

// XAUDIO2_DEVICE_DETAILS (0x42c bytes): DeviceID[256], DisplayName[256], Role, OutputFormat
// (WAVEFORMATEXTENSIBLE, float at the device's rate and channels)
uint32_t Engine::GetDeviceDetails(uint32_t index, uint32_t p) {
    if (index != 0 || !p) return win::E_INVALIDARG;
    if (!rate && !mixerStarted) Open();
    const uint32_t r = rate ? rate : 48000, ch = channels;
    memset(At(p), 0, 0x42c);
    std::u16string id = Widen("rhipper-aaudio"), name = Widen("Android audio (AAudio)");
    memcpy(At(p), id.c_str(), (id.size() + 1) * 2);
    memcpy(At(p + 512), name.c_str(), (name.size() + 1) * 2);
    *At<uint32_t>(p + 0x400) = 0xF;   // GlobalDefaultDevice
    const uint32_t f = p + 0x404;
    *At<uint16_t>(f) = 0xFFFE;
    *At<uint16_t>(f + 2) = static_cast<uint16_t>(ch);
    *At<uint32_t>(f + 4) = r;
    *At<uint32_t>(f + 8) = r * ch * 4;
    *At<uint16_t>(f + 12) = static_cast<uint16_t>(ch * 4);
    *At<uint16_t>(f + 14) = 32;
    *At<uint16_t>(f + 16) = 22;
    *At<uint16_t>(f + 18) = 32;
    *At<uint32_t>(f + 20) = ch == 1 ? 0x4 : ch == 2 ? 0x3 : (1u << ch) - 1;   // SPEAKER_* masks
    memcpy(At(f + 24), kSubtypeFloat, 16);
    return S_OK;
}

// the device opened and the mixer started (XAudio2's engine runs from its creation)
uint32_t Engine::Initialize(uint32_t fl, uint32_t processor) {
    if (mixerStarted) return S_OK;
    flags = fl;
    if (!rate && !Open()) {
        rate = 48000;
        quantum = 480;
        Log("XAudio2: no device: the engine runs by the clock, silent");
    }
    statSince = NowNs();
    uint32_t tid = 0;
    // (8 MB, CreateThread's least: the callbacks run translated frames)
    uint32_t h = StartLowThread(MixerMain, this, 8u << 20, false, &tid);
    if (!h) {
        Log("XAudio2: the mixer thread not started");
        return win::E_OUTOFMEMORY;
    }
    CloseHandle32(h);
    {
        std::lock_guard<std::mutex> hold(lock);
        mixerStarted = true;
        mixerTid = tid;
    }
    Log("XAudio2: engine %08x initialized (flags %#x, processor %#x): %u Hz, %u channels, %u frames a pass, mixer thread %u",
        self, fl, processor, rate, channels, quantum, tid);
    return S_OK;
}

uint32_t Engine::RegisterForCallbacks(uint32_t cb) {
    if (!cb) return win::E_INVALIDARG;
    std::lock_guard<std::mutex> hold(lock);
    if (std::find(callbacks.begin(), callbacks.end(), cb) == callbacks.end()) callbacks.push_back(cb);
    return S_OK;
}
void Engine::UnregisterForCallbacks(uint32_t cb) {
    std::lock_guard<std::mutex> hold(lock);
    callbacks.erase(std::remove(callbacks.begin(), callbacks.end(), cb), callbacks.end());
}

uint32_t Engine::CreateSourceVoice(uint32_t out, uint32_t format, uint32_t fl, uint32_t maxRatio, uint32_t cb,
                                   uint32_t sends, uint32_t chain) {
    static std::atomic<uint32_t> made{0};
    if (!out) return win::E_INVALIDARG;
    *At<uint32_t>(out) = 0;
    auto v = new Voice;
    v->kind = kSource;
    if (!ParseFormat(format, &v->fmt)) {
        Log("XAudio2: CreateSourceVoice: format tag %#x, %u channels, %u Hz, %u bits not supported",
            format ? *At<uint16_t>(format) : 0, format ? *At<uint16_t>(format + 2) : 0, format ? U32(format + 4) : 0,
            format ? *At<uint16_t>(format + 14) : 0);
        delete v;
        return win::E_INVALIDARG;
    }
    if (v->fmt.codec == kWma) LogOnce("xa2-wma", "XAudio2: xWMA source voices play silence (no WMA decoder here)");
    LogOnce(kCodecNames[v->fmt.codec], "XAudio2: first %s source voice (%u channels, %u Hz)", kCodecNames[v->fmt.codec],
            v->fmt.channels, v->fmt.rate);
    v->flags = fl;
    v->inCh = v->fmt.channels;
    v->inRate = v->fmt.rate;
    v->callback = cb;
    float mr = Bits(maxRatio);
    v->maxRatio = mr >= 1.f / 1024.f && mr <= 1024.f ? mr : 2.f;
    uint32_t hr = AddVoice(v, out, sends, chain);
    if (hr == S_OK && made++ < 16)
        Log("XAudio2: source voice %08x: %s, %u ch, %u Hz, flags %#x, max ratio %g, callback %08x",
            *At<uint32_t>(out), kCodecNames[v->fmt.codec], v->fmt.channels, v->fmt.rate, fl, mr, cb);
    return hr;
}

uint32_t Engine::CreateSubmixVoice(uint32_t out, uint32_t ch, uint32_t r, uint32_t fl, uint32_t stage, uint32_t sends,
                                   uint32_t chain) {
    if (!out) return win::E_INVALIDARG;
    *At<uint32_t>(out) = 0;
    if (ch == 0 || ch > kMaxChannels || r < 1000 || r > 200000) return win::E_INVALIDARG;
    auto v = new Voice;
    v->kind = kSubmix;
    v->flags = fl;
    v->inCh = ch;
    v->inRate = r;
    v->stage = stage;
    uint32_t hr = AddVoice(v, out, sends, chain);
    if (hr == S_OK) Log("XAudio2: submix voice %08x: %u ch, %u Hz, stage %u", *At<uint32_t>(out), ch, r, stage);
    return hr;
}

uint32_t Engine::CreateMasteringVoice(uint32_t out, uint32_t ch, uint32_t r, uint32_t fl, uint32_t device,
                                      uint32_t chain) {
    if (!out) return win::E_INVALIDARG;
    *At<uint32_t>(out) = 0;
    {
        std::lock_guard<std::mutex> hold(lock);
        if (master) return kInvalidCall;
    }
    if (device != 0) return win::E_INVALIDARG;
    if (ch > kMaxChannels || (r && (r < 1000 || r > 200000))) return win::E_INVALIDARG;
    auto v = new Voice;
    v->kind = kMaster;
    v->flags = fl;
    v->inCh = ch ? ch : channels;
    v->inRate = r ? r : (rate ? rate : 48000);
    if (v->inRate != rate) Log("XAudio2: mastering voice at %u Hz, mixed at the device's %u", v->inRate, rate);
    uint32_t hr = AddVoice(v, out, 0, chain);
    if (hr == S_OK)
        Log("XAudio2: mastering voice %08x: %u ch, %u Hz (to the device's %u ch)", *At<uint32_t>(out), v->inCh, v->inRate,
            channels);
    return hr;
}

uint32_t Engine::StartEngine() {
    {
        std::lock_guard<std::mutex> hold(lock);
        running = true;
    }
    wake.notify_all();
    return S_OK;
}
void Engine::StopEngine() {
    std::lock_guard<std::mutex> hold(lock);
    running = false;
}
uint32_t Engine::CommitChanges(uint32_t set) {
    LogOnce("xa2-commit", "XAudio2: CommitChanges(%u): every change was applied at once", set);
    return S_OK;
}

// XAUDIO2_PERFORMANCE_DATA (2.7, packed, 56 bytes): the cycles as ns
void Engine::GetPerformanceData(uint32_t p) {
    if (!p) return;
    std::lock_guard<std::mutex> hold(lock);
    uint64_t now = NowNs();
    uint64_t q[2] = {busyNs, now - statSince};
    uint32_t active = 0, total = 0, subs = 0;
    for (Voice* v : voices) {
        if (v->kind == kSource) {
            total++;
            active += v->started ? 1 : 0;
        } else if (v->kind == kSubmix) {
            subs++;
        }
    }
    uint32_t w[12] = {passes ? minNs : 0, maxNs, 0, static_cast<uint32_t>(std::max(0, bufferFrames.load())),
                      static_cast<uint32_t>(std::max(0, xruns.load())), active, total, subs, active, active + subs, 0, 0};
    memcpy(At(p), q, 16);
    memcpy(At(p + 16), w, sizeof w);
    busyNs = 0;
    statSince = now;
    minNs = ~0u;
    maxNs = 0;
    passes = 0;
}

// ---- the classes: CoCreateInstance's objects and CoGetClassObject's factories -----------------------
enum ClassKind { kClassEngine, kClassReverb, kClassMeter };

uint32_t CreateOf(ClassKind kind, uint32_t riid, uint32_t out) {
    if (!out) return win::E_POINTER;
    *At<uint32_t>(out) = 0;
    if (kind != kClassEngine) {
        uint32_t fx = NewEffect(kind == kClassReverb ? kReverb : kMeter);
        if (SameGuid(riid, kIidXapoParameters)) {
            *At<uint32_t>(out) = static_cast<Effect*>(Native(fx))->paramsHead;
        } else {
            *At<uint32_t>(out) = fx;
        }
        return S_OK;
    }
    if (!SameGuid(riid, kIidXAudio2) && !SameGuid(riid, kIidUnknown)) {
        Log("XAudio2: the engine asked for as %s: no such interface (2.7's IXAudio2 only)", HexGuid(riid).c_str());
        return win::E_NOINTERFACE;
    }
    auto e = new Engine;
    e->self = NewObject(EngineVtable(), e);
    {
        std::lock_guard<std::mutex> hold(g_enginesLock);
        g_engines.push_back(e);
    }
    Log("XAudio2: engine %08x (XAudio2 2.7 on AAudio)", e->self);
    *At<uint32_t>(out) = e->self;
    return S_OK;
}

// IClassFactory: QueryInterface, AddRef, Release, CreateInstance(outer, riid, out), LockServer(lock)
struct Factory {
    ClassKind kind;
    uint32_t QueryInterface(uint32_t, uint32_t out);
    uint32_t AddRef_() { return 1; }
    uint32_t Release_() { return 1; }
    uint32_t CreateInstance(uint32_t outer, uint32_t riid, uint32_t out) {
        if (outer) {
            if (out) *At<uint32_t>(out) = 0;
            return kNoAggregation;
        }
        return CreateOf(kind, riid, out);
    }
    uint32_t LockServer(uint32_t) { return S_OK; }
};
uint32_t FactoryObject(ClassKind kind) {
    static uint32_t objs[3] = {};
    static Factory natives[3] = {{kClassEngine}, {kClassReverb}, {kClassMeter}};
    static std::once_flag once;
    std::call_once(once, [] {
        const void* m[5] = {T_<&Factory::QueryInterface>(), T_<&Factory::AddRef_>(), T_<&Factory::Release_>(),
                            T_<&Factory::CreateInstance>(), T_<&Factory::LockServer>()};
        uint32_t vt = Vtable(m, 5);
        for (int k = 0; k < 3; k++) objs[k] = NewObject(vt, &natives[k]);
    });
    return objs[kind];
}
uint32_t Factory::QueryInterface(uint32_t, uint32_t out) {
    if (!out) return win::E_POINTER;
    *At<uint32_t>(out) = FactoryObject(kind);
    return S_OK;
}

}  // namespace

// Com32Posix.cpp's CoCreateInstance and CoGetClassObject: true when `clsid` is one of XAudio2 2.7's
// (the engine, the reverb, the volume meter, each also as its debug class), *hr the call's result
bool XAudio2Class(uint32_t clsid, uint32_t riid, uint32_t out, bool factory, uint32_t* hr) {
    ClassKind kind;
    if (SameGuid(clsid, kClsidXAudio2) || SameGuid(clsid, kClsidXAudio2Debug)) kind = kClassEngine;
    else if (SameGuid(clsid, kClsidReverb) || SameGuid(clsid, kClsidReverbDebug)) kind = kClassReverb;
    else if (SameGuid(clsid, kClsidMeter) || SameGuid(clsid, kClsidMeterDebug)) kind = kClassMeter;
    else return false;
    if (!factory) {
        *hr = CreateOf(kind, riid, out);
        return true;
    }
    if (!out) {
        *hr = win::E_POINTER;
    } else if (SameGuid(riid, kIidClassFactory) || SameGuid(riid, kIidUnknown)) {
        *At<uint32_t>(out) = FactoryObject(kind);
        *hr = S_OK;
    } else {
        *At<uint32_t>(out) = 0;
        *hr = win::E_NOINTERFACE;
    }
    return true;
}

// the host's lifecycle (Host.cpp's rhipper_host_lifecycle): paused, the stream is paused and the
// passes go on by the clock, silent (the reference's streaming keeps its pace); resumed, it plays
void XAudio2Lifecycle(int event) {
    if (event != 1 && event != 2) return;
    g_hostPaused = event == 1;
    std::lock_guard<std::mutex> hold(g_enginesLock);
    if (!g_engines.empty()) Log("XAudio2: %s", event == 1 ? "paused by the host" : "resumed");
}

void OnHostLifecycle(void (*fn)(int event));   // Host.cpp
namespace {
// (told of the lifecycle from the start: Host.cpp's list is constant-initialized)
const bool g_lifecycleHooked = (OnHostLifecycle(XAudio2Lifecycle), true);
}

}  // namespace rh
