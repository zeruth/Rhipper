// The movie decoder behind dshow.cpp's filter graph: a file opened, its video frames pulled in order
// as 32-bit RGB rows, its audio as interleaved float stereo at kAudioRate. The runtime picks one
// (dshow_host.h's OpenDecoder): FFmpeg's (dshow_ffmpeg.cpp, a build with FFmpeg: RH_DSHOW_FFMPEG),
// Media Foundation's on Windows (runtime32/DShowMediaFoundation.cpp); and the probe (dshow.cpp)
// when neither opens it, which reads an ASF file's header for its size and length and decodes
// nothing, so a movie without a decoder still opens, runs and ends (the reference waits for its
// end: FFXIV's first-run opening).
#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace rh::dshow {

constexpr uint32_t kAudioRate = 48000;

struct MovieInfo {
    uint32_t width = 0, height = 0;
    int64_t duration = 0;          // 100 ns units, REFERENCE_TIME's
    int64_t frameTime = 333667;    // 100 ns a frame (VIDEOINFOHEADER's AvgTimePerFrame)
    bool hasVideo = false, hasAudio = false;
    bool decodes = false;          // false: the probe's, no frames or audio come
    std::string codecs;            // for the log
    const char* decoder = "";      // whose (the log's "decoded by ...")
};

class MovieDecoder {
public:
    virtual ~MovieDecoder() = default;
    virtual const MovieInfo& Info() const = 0;
    // the next video frame, written as width x height 32-bit pixels (B, G, R, X), the bottom row
    // first (a DIB's order), `stride` bytes a row; its time in 100 ns. false at the end
    virtual bool NextVideo(uint8_t* bgrx, uint32_t stride, int64_t* time) = 0;
    // up to `frames` stereo float frames at kAudioRate; 0 at the end
    virtual uint32_t NextAudio(float* stereo, uint32_t frames) = 0;
    // both streams from `time` (100 ns) on: the next video frame the first at or after it
    virtual bool Seek(int64_t time) = 0;
};

// FFmpeg's, nullptr when the build has none or it cannot open the file (dshow_ffmpeg.cpp)
std::unique_ptr<MovieDecoder> OpenFfmpeg(const std::string& hostPath);

}  // namespace rh::dshow
