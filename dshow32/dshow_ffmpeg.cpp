// dshow.cpp's movie decoder on FFmpeg (5.1 or later: AVChannelLayout): the file demuxed once, its
// packets queued per stream, the video decoded and converted by swscale to 32-bit BGRX rows bottom-up
// (a DIB's order, as the reference's renderer takes them), the audio resampled by swresample to float
// stereo at kAudioRate. The streaming thread pulls the video, the audio thread the audio; one lock.
// Built when Runtime32Posix.cmake's RHIPPER_FFMPEG names an FFmpeg (RH_DSHOW_FFMPEG); nothing in it
// is the runtime's but the log (dshow_host.h).
#include <algorithm>
#include <cstring>
#include <deque>
#include <mutex>
#include <vector>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/opt.h>
#include <libswresample/swresample.h>
#include <libswscale/swscale.h>
}

#include "dshow_host.h"

namespace rh::dshow {

namespace {

constexpr AVRational k100ns = {1, 10000000};

class Ffmpeg : public MovieDecoder {
public:
    ~Ffmpeg() override {
        for (auto* q : {&vq, &aq})
            for (AVPacket* p : *q) av_packet_free(&p);
        av_frame_free(&frame);
        av_frame_free(&aframe);
        sws_freeContext(sws);
        swr_free(&swr);
        avcodec_free_context(&vc);
        avcodec_free_context(&ac);
        avformat_close_input(&fmt);
    }

    bool Open(const std::string& path) {
        if (avformat_open_input(&fmt, path.c_str(), nullptr, nullptr) < 0) return false;
        if (avformat_find_stream_info(fmt, nullptr) < 0) return false;
        vi = av_find_best_stream(fmt, AVMEDIA_TYPE_VIDEO, -1, -1, nullptr, 0);
        ai = av_find_best_stream(fmt, AVMEDIA_TYPE_AUDIO, -1, vi, nullptr, 0);
        if (vi >= 0 && !OpenCodec(vi, &vc)) vi = -1;
        if (ai >= 0 && !OpenCodec(ai, &ac)) ai = -1;
        if (vi < 0) return false;
        frame = av_frame_alloc();
        aframe = av_frame_alloc();
        info.width = static_cast<uint32_t>(vc->width);
        info.height = static_cast<uint32_t>(vc->height);
        info.hasVideo = true;
        info.decodes = true;
        info.decoder = "FFmpeg";
        if (fmt->duration > 0) info.duration = av_rescale_q(fmt->duration, AV_TIME_BASE_Q, k100ns);
        AVRational fr = fmt->streams[vi]->avg_frame_rate;
        if (fr.num > 0 && fr.den > 0) info.frameTime = av_rescale_q(1, av_inv_q(fr), k100ns);
        info.codecs = std::string("video ") + avcodec_get_name(vc->codec_id);
        if (ai >= 0) {
            AVChannelLayout stereo = AV_CHANNEL_LAYOUT_STEREO;
            if (swr_alloc_set_opts2(&swr, &stereo, AV_SAMPLE_FMT_FLT, static_cast<int>(kAudioRate), &ac->ch_layout,
                                    ac->sample_fmt, ac->sample_rate, 0, nullptr) < 0 ||
                swr_init(swr) < 0) {
                swr_free(&swr);
                ai = -1;
            } else {
                info.hasAudio = true;
                info.codecs += std::string(", audio ") + avcodec_get_name(ac->codec_id) + " " +
                               std::to_string(ac->ch_layout.nb_channels) + " ch " + std::to_string(ac->sample_rate) + " Hz";
            }
        }
        return true;
    }

    const MovieInfo& Info() const override { return info; }

    bool NextVideo(uint8_t* bgrx, uint32_t stride, int64_t* time) override {
        std::lock_guard<std::mutex> hold(lock);
        for (;;) {
            int r = avcodec_receive_frame(vc, frame);
            if (r == 0) {
                int64_t pts = frame->best_effort_timestamp;
                int64_t t = pts == AV_NOPTS_VALUE ? lastVideo + info.frameTime
                                                  : av_rescale_q(pts, fmt->streams[vi]->time_base, k100ns);
                lastVideo = t;
                if (t < skipVideoBefore) {
                    av_frame_unref(frame);
                    continue;
                }
                sws = sws_getCachedContext(sws, frame->width, frame->height, static_cast<AVPixelFormat>(frame->format),
                                           static_cast<int>(info.width), static_cast<int>(info.height), AV_PIX_FMT_BGR0,
                                           SWS_BILINEAR, nullptr, nullptr, nullptr);
                if (!sws) return false;
                // the last row first: the destination walked upward
                uint8_t* dst[4] = {bgrx + static_cast<size_t>(info.height - 1) * stride, nullptr, nullptr, nullptr};
                int dstStride[4] = {-static_cast<int>(stride), 0, 0, 0};
                sws_scale(sws, frame->data, frame->linesize, 0, frame->height, dst, dstStride);
                av_frame_unref(frame);
                *time = t;
                return true;
            }
            if (r == AVERROR_EOF) return false;
            if (r != AVERROR(EAGAIN)) return false;
            AVPacket* p = Take(vq);
            r = avcodec_send_packet(vc, p);   // (nullptr at the end: the decoder drained)
            if (p) av_packet_free(&p);
            else if (r == AVERROR_EOF) return false;
        }
    }

    uint32_t NextAudio(float* stereo, uint32_t frames) override {
        std::lock_guard<std::mutex> hold(lock);
        if (ai < 0) return 0;
        while (pendingAt >= pending.size()) {
            pending.clear();
            pendingAt = 0;
            int r = avcodec_receive_frame(ac, aframe);
            if (r == 0) {
                int64_t pts = aframe->best_effort_timestamp;
                if (pts != AV_NOPTS_VALUE &&
                    av_rescale_q(pts, fmt->streams[ai]->time_base, k100ns) < skipAudioBefore) {
                    av_frame_unref(aframe);
                    continue;
                }
                int n = swr_get_out_samples(swr, aframe->nb_samples);
                pending.resize(static_cast<size_t>(std::max(n, 0)) * 2);
                uint8_t* out = reinterpret_cast<uint8_t*>(pending.data());
                int got = swr_convert(swr, &out, n, const_cast<const uint8_t**>(aframe->extended_data), aframe->nb_samples);
                pending.resize(static_cast<size_t>(std::max(got, 0)) * 2);
                av_frame_unref(aframe);
                continue;
            }
            if (r == AVERROR_EOF || r != AVERROR(EAGAIN)) return 0;
            AVPacket* p = Take(aq);
            r = avcodec_send_packet(ac, p);
            if (p) av_packet_free(&p);
            else if (r == AVERROR_EOF) return 0;
        }
        const uint32_t n = std::min<uint32_t>(frames, static_cast<uint32_t>((pending.size() - pendingAt) / 2));
        memcpy(stereo, pending.data() + pendingAt, n * 2 * sizeof(float));
        pendingAt += n * 2;
        return n;
    }

    bool Seek(int64_t time) override {
        std::lock_guard<std::mutex> hold(lock);
        const int64_t us = av_rescale_q(time, k100ns, AV_TIME_BASE_Q);
        int r = av_seek_frame(fmt, -1, us, AVSEEK_FLAG_BACKWARD);
        for (auto* q : {&vq, &aq}) {
            for (AVPacket* p : *q) av_packet_free(&p);
            q->clear();
        }
        if (vc) avcodec_flush_buffers(vc);
        if (ac) avcodec_flush_buffers(ac);
        if (swr) swr_init(swr);
        pending.clear();
        pendingAt = 0;
        eof = false;
        skipVideoBefore = skipAudioBefore = time;
        lastVideo = time;
        return r >= 0;
    }

    MovieInfo info;

private:
    bool OpenCodec(int index, AVCodecContext** ctx) {
        const AVCodecParameters* par = fmt->streams[index]->codecpar;
        const AVCodec* codec = avcodec_find_decoder(par->codec_id);
        if (!codec) {
            Log("DirectShow: FFmpeg has no decoder for %s", avcodec_get_name(par->codec_id));
            return false;
        }
        *ctx = avcodec_alloc_context3(codec);
        if (!*ctx || avcodec_parameters_to_context(*ctx, par) < 0) return false;
        (*ctx)->thread_count = 2;
        (*ctx)->pkt_timebase = fmt->streams[index]->time_base;
        return avcodec_open2(*ctx, codec, nullptr) >= 0;
    }
    // the next packet of a stream, read from the file until one comes (the other stream's queued);
    // nullptr at the file's end
    AVPacket* Take(std::deque<AVPacket*>& q) {
        while (q.empty() && !eof) {
            AVPacket* p = av_packet_alloc();
            if (av_read_frame(fmt, p) < 0) {
                av_packet_free(&p);
                eof = true;
                break;
            }
            if (p->stream_index == vi) vq.push_back(p);
            else if (p->stream_index == ai) aq.push_back(p);
            else av_packet_free(&p);
            // (a stream nobody pulls must not grow without bound: the audio when there is no device)
            if (aq.size() > 4096) {
                av_packet_free(&aq.front());
                aq.pop_front();
            }
        }
        if (q.empty()) return nullptr;
        AVPacket* p = q.front();
        q.pop_front();
        return p;
    }

    std::mutex lock;
    AVFormatContext* fmt = nullptr;
    AVCodecContext *vc = nullptr, *ac = nullptr;
    int vi = -1, ai = -1;
    AVFrame *frame = nullptr, *aframe = nullptr;
    SwsContext* sws = nullptr;
    SwrContext* swr = nullptr;
    std::deque<AVPacket*> vq, aq;
    bool eof = false;
    std::vector<float> pending;
    size_t pendingAt = 0;
    int64_t skipVideoBefore = 0, skipAudioBefore = 0, lastVideo = 0;
};

}  // namespace

std::unique_ptr<MovieDecoder> OpenFfmpeg(const std::string& hostPath) {
    auto d = std::make_unique<Ffmpeg>();
    if (!d->Open(hostPath)) {
        Log("DirectShow: FFmpeg could not open %s", hostPath.c_str());
        return nullptr;
    }
    return d;
}

}  // namespace rh::dshow
