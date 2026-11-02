// dshow32's movie decoder on Windows: Media Foundation's source reader (DShowHost.cpp's OpenDecoder).
// Windows has the reference's codecs (FFXIV's movies are ASF: WMV3 video, WMA Pro 5.1 audio), so the
// desktop port plays the real movie. The reader decodes and converts: the video to RGB32 (its video
// processing), the audio to float; to stereo at kAudioRate when the reader takes that type, else
// from its own channels and rate here (a 5.1 downmix, a linear resampler). The file is opened as a
// byte stream and resolved by its content, not its name: the reference's are .dat.
//
// MF's RGB32 is top-down at MF_MT_DEFAULT_STRIDE (or a buffer's own pitch, IMF2DBuffer's); the graph
// takes a DIB's rows, bottom-up, so the rows are copied in reverse.
#include <windows.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <propidl.h>

#include <algorithm>
#include <cstdlib>
#include <mutex>
#include <vector>

#include "../dshow32/dshow_host.h"

namespace rh::dshow {

namespace {

constexpr DWORD kVideo = static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM);
constexpr DWORD kAudio = static_cast<DWORD>(MF_SOURCE_READER_FIRST_AUDIO_STREAM);

template <typename T>
void Release(T*& p) {
    if (p) p->Release();
    p = nullptr;
}

// a FOURCC or a format tag, the subtype's first word, for the log
std::string SubtypeName(IMFMediaType* t, bool video) {
    GUID g = {};
    if (!t || FAILED(t->GetGUID(MF_MT_SUBTYPE, &g))) return "?";
    char s[16];
    if (video) {
        for (int k = 0; k < 4; k++) {
            char c = static_cast<char>((g.Data1 >> (8 * k)) & 0xff);
            s[k] = c >= 0x20 && c < 0x7f ? c : '?';
        }
        s[4] = 0;
    } else {
        snprintf(s, sizeof s, "tag %#lx", static_cast<unsigned long>(g.Data1));
    }
    return s;
}

// a reader over the file's content (an ASF by its bytes: the name's .dat says nothing), its video
// converted by the reader's processor: the advanced one (Windows 8, the Video Processor MFT) or the
// plain one
IMFSourceReader* MakeReader(const std::wstring& path, bool advanced) {
    IMFByteStream* bs = nullptr;
    IMFSourceResolver* resolver = nullptr;
    IUnknown* object = nullptr;
    IMFMediaSource* source = nullptr;
    IMFAttributes* attrs = nullptr;
    IMFSourceReader* reader = nullptr;
    HRESULT hr = MFCreateFile(MF_ACCESSMODE_READ, MF_OPENMODE_FAIL_IF_NOT_EXIST, MF_FILEFLAGS_NONE, path.c_str(), &bs);
    if (SUCCEEDED(hr)) {
        IMFAttributes* a = nullptr;
        if (SUCCEEDED(bs->QueryInterface(IID_PPV_ARGS(&a)))) {
            a->SetString(MF_BYTESTREAM_CONTENT_TYPE, L"video/x-ms-asf");
            a->Release();
        }
        hr = MFCreateSourceResolver(&resolver);
    }
    MF_OBJECT_TYPE type = MF_OBJECT_INVALID;
    if (SUCCEEDED(hr))
        hr = resolver->CreateObjectFromByteStream(
            bs, path.c_str(),
            MF_RESOLUTION_MEDIASOURCE | MF_RESOLUTION_READ | MF_RESOLUTION_CONTENT_DOES_NOT_HAVE_TO_MATCH_EXTENSION_OR_MIME_TYPE,
            nullptr, &type, &object);
    if (SUCCEEDED(hr)) hr = object->QueryInterface(IID_PPV_ARGS(&source));
    if (SUCCEEDED(hr)) hr = MFCreateAttributes(&attrs, 1);
    if (SUCCEEDED(hr))
        hr = attrs->SetUINT32(advanced ? MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING : MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING,
                              TRUE);
    if (SUCCEEDED(hr)) hr = MFCreateSourceReaderFromMediaSource(source, attrs, &reader);
    if (FAILED(hr)) Log("DirectShow: Media Foundation could not open the movie (%#lx)", static_cast<unsigned long>(hr));
    if (FAILED(hr) && source) source->Shutdown();
    Release(attrs);
    Release(source);
    Release(object);
    Release(resolver);
    Release(bs);
    return reader;
}

class MediaFoundation : public MovieDecoder {
public:
    ~MediaFoundation() override { Release(reader); }

    bool Open(const std::wstring& path) {
        static const HRESULT started = MFStartup(MF_VERSION, MFSTARTUP_FULL);
        if (FAILED(started)) {
            Log("DirectShow: no Media Foundation (MFStartup %#lx)", static_cast<unsigned long>(started));
            return false;
        }
        for (bool advanced : {true, false}) {
            reader = MakeReader(path, advanced);
            if (!reader) {
                if (advanced) continue;
                return false;
            }
            reader->SetStreamSelection(static_cast<DWORD>(MF_SOURCE_READER_ALL_STREAMS), FALSE);
            if (FAILED(reader->SetStreamSelection(kVideo, TRUE))) {
                Log("DirectShow: Media Foundation: the movie has no video");
                Release(reader);
                return false;
            }
            IMFMediaType* t = nullptr;
            HRESULT hr = MFCreateMediaType(&t);
            if (SUCCEEDED(hr)) hr = t->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
            if (SUCCEEDED(hr)) hr = t->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
            if (SUCCEEDED(hr)) hr = reader->SetCurrentMediaType(kVideo, nullptr, t);
            Release(t);
            if (SUCCEEDED(hr) && VideoType()) break;
            Log("DirectShow: Media Foundation: no RGB32 from the %s video processor (%#lx)", advanced ? "advanced" : "plain",
                static_cast<unsigned long>(hr));
            Release(reader);
            if (!advanced) return false;
        }
        IMFMediaType* native = nullptr;
        reader->GetNativeMediaType(kVideo, 0, &native);
        info.codecs = "video " + SubtypeName(native, true);
        Release(native);
        OpenAudio();

        PROPVARIANT v;
        PropVariantInit(&v);
        if (SUCCEEDED(reader->GetPresentationAttribute(static_cast<DWORD>(MF_SOURCE_READER_MEDIASOURCE), MF_PD_DURATION, &v)) &&
            v.vt == VT_UI8)
            info.duration = static_cast<int64_t>(v.uhVal.QuadPart);
        PropVariantClear(&v);
        info.hasVideo = true;
        info.decodes = true;
        info.decoder = "Media Foundation";
        return true;
    }

    const MovieInfo& Info() const override { return info; }

    bool NextVideo(uint8_t* bgrx, uint32_t outStride, int64_t* time) override {
        std::lock_guard<std::mutex> hold(lock);
        for (;;) {
            DWORD index = 0, flags = 0;
            LONGLONG ts = 0;
            IMFSample* s = nullptr;
            HRESULT hr = reader->ReadSample(kVideo, 0, &index, &flags, &ts, &s);
            if (FAILED(hr)) {
                Log("DirectShow: Media Foundation: a video frame not read (%#lx)", static_cast<unsigned long>(hr));
                return false;
            }
            if (flags & MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED) VideoType();
            if (flags & (MF_SOURCE_READERF_ENDOFSTREAM | MF_SOURCE_READERF_ERROR)) {
                Release(s);
                return false;
            }
            if (!s) continue;   // (a gap: a stream tick)
            if (ts < skipVideoBefore) {
                Release(s);
                continue;
            }
            const bool copied = Copy(s, bgrx, outStride);
            Release(s);
            if (!copied) return false;
            *time = ts;
            return true;
        }
    }

    uint32_t NextAudio(float* stereo, uint32_t n) override {
        std::lock_guard<std::mutex> hold(lock);
        if (!audio) return 0;
        while (pendingAt >= pending.size()) {
            pending.clear();
            pendingAt = 0;
            DWORD index = 0, flags = 0;
            LONGLONG ts = 0;
            IMFSample* s = nullptr;
            HRESULT hr = reader->ReadSample(kAudio, 0, &index, &flags, &ts, &s);
            if (FAILED(hr)) return 0;
            if (flags & MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED) AudioType();
            if (flags & (MF_SOURCE_READERF_ENDOFSTREAM | MF_SOURCE_READERF_ERROR)) {
                Release(s);
                return 0;
            }
            if (!s) continue;
            LONGLONG d = 0;
            s->GetSampleDuration(&d);
            IMFMediaBuffer* b = nullptr;
            if (ts + d > skipAudioBefore && SUCCEEDED(s->ConvertToContiguousBuffer(&b))) {
                BYTE* data = nullptr;
                DWORD len = 0;
                if (SUCCEEDED(b->Lock(&data, nullptr, &len))) {
                    Mix(reinterpret_cast<const float*>(data), len / (4 * channels));
                    b->Unlock();
                }
                b->Release();
            }
            Release(s);
        }
        const uint32_t k = std::min<uint32_t>(n, static_cast<uint32_t>((pending.size() - pendingAt) / 2));
        memcpy(stereo, pending.data() + pendingAt, k * 2 * sizeof(float));
        pendingAt += k * 2;
        return k;
    }

    bool Seek(int64_t time) override {
        std::lock_guard<std::mutex> hold(lock);
        PROPVARIANT v;
        PropVariantInit(&v);
        v.vt = VT_I8;
        v.hVal.QuadPart = time;
        HRESULT hr = reader->SetCurrentPosition(GUID_NULL, v);
        PropVariantClear(&v);
        pending.clear();
        pendingAt = 0;
        phase = 0;
        last[0] = last[1] = 0.f;
        skipVideoBefore = skipAudioBefore = time;
        return SUCCEEDED(hr);
    }

    MovieInfo info;

private:
    // the video's current output type: its size, its rows' stride
    bool VideoType() {
        IMFMediaType* t = nullptr;
        if (FAILED(reader->GetCurrentMediaType(kVideo, &t))) return false;
        UINT32 w = 0, h = 0, num = 0, den = 0;
        MFGetAttributeSize(t, MF_MT_FRAME_SIZE, &w, &h);
        stride = static_cast<LONG>(MFGetAttributeUINT32(t, MF_MT_DEFAULT_STRIDE, 0));
        if (stride == 0) MFGetStrideForBitmapInfoHeader(MFVideoFormat_RGB32.Data1, w, &stride);
        if (SUCCEEDED(MFGetAttributeRatio(t, MF_MT_FRAME_RATE, &num, &den)) && num && den)
            frameTime = static_cast<int64_t>(10000000ull * den / num);
        Release(t);
        if (!w || !h) return false;
        frameWidth = w;
        frameHeight = h;
        if (!info.width) {   // (the graph's size fixed at the first: a later change copied into it)
            info.width = w;
            info.height = h;
            info.frameTime = frameTime;
        }
        return true;
    }

    // the audio: float stereo at kAudioRate if the reader converts to it, else float as it comes
    void OpenAudio() {
        if (FAILED(reader->SetStreamSelection(kAudio, TRUE))) return;
        IMFMediaType* native = nullptr;
        reader->GetNativeMediaType(kAudio, 0, &native);
        const std::string name = SubtypeName(native, false);
        const UINT32 nativeChannels = native ? MFGetAttributeUINT32(native, MF_MT_AUDIO_NUM_CHANNELS, 0) : 0;
        const UINT32 nativeRate = native ? MFGetAttributeUINT32(native, MF_MT_AUDIO_SAMPLES_PER_SECOND, 0) : 0;
        Release(native);
        bool full = false;
        for (bool stereo48 : {true, false}) {
            IMFMediaType* t = nullptr;
            HRESULT hr = MFCreateMediaType(&t);
            if (SUCCEEDED(hr)) hr = t->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
            if (SUCCEEDED(hr)) hr = t->SetGUID(MF_MT_SUBTYPE, MFAudioFormat_Float);
            if (SUCCEEDED(hr) && stereo48) {
                t->SetUINT32(MF_MT_AUDIO_NUM_CHANNELS, 2);
                t->SetUINT32(MF_MT_AUDIO_SAMPLES_PER_SECOND, kAudioRate);
                t->SetUINT32(MF_MT_AUDIO_BITS_PER_SAMPLE, 32);
                t->SetUINT32(MF_MT_AUDIO_BLOCK_ALIGNMENT, 8);
                t->SetUINT32(MF_MT_AUDIO_AVG_BYTES_PER_SECOND, kAudioRate * 8);
            }
            if (SUCCEEDED(hr)) hr = reader->SetCurrentMediaType(kAudio, nullptr, t);
            Release(t);
            if (SUCCEEDED(hr) && AudioType()) {
                audio = true;
                full = stereo48;
                break;
            }
        }
        if (!audio) {
            reader->SetStreamSelection(kAudio, FALSE);
            Log("DirectShow: Media Foundation: no float audio from the %s decoder: the movie plays silent", name.c_str());
            return;
        }
        info.hasAudio = true;
        char s[96];
        snprintf(s, sizeof s, ", audio %s %u ch %u Hz (%s)", name.c_str(), nativeChannels, nativeRate,
                 full ? "the reader's stereo 48 kHz" : "mixed here");
        info.codecs += s;
    }
    bool AudioType() {
        IMFMediaType* t = nullptr;
        if (FAILED(reader->GetCurrentMediaType(kAudio, &t))) return false;
        channels = MFGetAttributeUINT32(t, MF_MT_AUDIO_NUM_CHANNELS, 0);
        rate = MFGetAttributeUINT32(t, MF_MT_AUDIO_SAMPLES_PER_SECOND, 0);
        Release(t);
        if (!channels || !rate) {
            channels = 2;
            return false;
        }
        step = static_cast<double>(rate) / kAudioRate;
        return true;
    }

    // a frame's rows into the graph's sample, the bottom row first
    bool Copy(IMFSample* s, uint8_t* out, uint32_t outStride) {
        IMFMediaBuffer* b = nullptr;
        DWORD count = 0;
        HRESULT hr = s->GetBufferCount(&count);
        if (SUCCEEDED(hr)) hr = count == 1 ? s->GetBufferByIndex(0, &b) : s->ConvertToContiguousBuffer(&b);
        if (FAILED(hr)) return false;
        IMF2DBuffer* b2 = nullptr;
        BYTE* scan0 = nullptr;
        LONG pitch = 0;
        BYTE* data = nullptr;
        DWORD len = 0;
        if (SUCCEEDED(b->QueryInterface(IID_PPV_ARGS(&b2))) && SUCCEEDED(b2->Lock2D(&scan0, &pitch))) {
            len = static_cast<DWORD>(std::abs(pitch)) * frameHeight;
        } else {
            Release(b2);
            if (FAILED(b->Lock(&data, nullptr, &len))) {
                b->Release();
                return false;
            }
            pitch = stride;
            scan0 = pitch < 0 ? data + static_cast<size_t>(-pitch) * (frameHeight - 1) : data;
        }
        const uint32_t w = std::min(frameWidth, info.width), h = std::min(frameHeight, info.height);
        const size_t need = static_cast<size_t>(std::abs(pitch)) * (h ? h - 1 : 0) + w * 4u;
        if (len >= need) {
            for (uint32_t y = 0; y < h; y++)
                memcpy(out + static_cast<size_t>(info.height - 1 - y) * outStride, scan0 + static_cast<ptrdiff_t>(y) * pitch,
                       w * 4u);
        }
        if (b2) {
            b2->Unlock2D();
            b2->Release();
        } else {
            b->Unlock();
        }
        b->Release();
        return true;
    }

    // `n` frames of `channels` floats at `rate` as stereo at kAudioRate: the 5.1 downmix (L, R, C, LFE,
    // the back pair; the LFE left out), then linear interpolation between the last frame and this one
    void Mix(const float* in, uint32_t n) {
        constexpr float kC = 0.7071f, kNorm = 1.f / (1.f + 2.f * kC);
        for (uint32_t k = 0; k < n; k++, in += channels) {
            float l, r;
            if (channels == 1) {
                l = r = in[0];
            } else if (channels >= 6) {
                l = (in[0] + kC * in[2] + kC * in[4]) * kNorm;
                r = (in[1] + kC * in[2] + kC * in[5]) * kNorm;
            } else {
                l = in[0];
                r = in[1];
            }
            if (rate == kAudioRate) {
                pending.push_back(l);
                pending.push_back(r);
                continue;
            }
            for (; phase < 1.0; phase += step) {
                const float f = static_cast<float>(phase);
                pending.push_back(last[0] + (l - last[0]) * f);
                pending.push_back(last[1] + (r - last[1]) * f);
            }
            phase -= 1.0;
            last[0] = l;
            last[1] = r;
        }
    }

    std::mutex lock;
    IMFSourceReader* reader = nullptr;
    uint32_t frameWidth = 0, frameHeight = 0;
    LONG stride = 0;
    int64_t frameTime = 333667;
    bool audio = false;
    uint32_t channels = 2, rate = kAudioRate;
    double step = 1.0, phase = 0;
    float last[2] = {};
    std::vector<float> pending;
    size_t pendingAt = 0;
    int64_t skipVideoBefore = 0, skipAudioBefore = 0;
};

}  // namespace

std::unique_ptr<MovieDecoder> OpenMediaFoundation(const std::wstring& path) {
    auto d = std::make_unique<MediaFoundation>();
    if (!d->Open(path)) return nullptr;
    return d;
}

}  // namespace rh::dshow
