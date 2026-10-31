// The log: every line to logcat under the project's tag and to <log dir>/<name>.log, which a crash
// report and a user's bug report both want. The file is opened on the first line after the host set
// the directory; lines before go to logcat alone.
#include <android/log.h>
#include <fcntl.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unordered_set>

#include "Runtime.h"

namespace rh {

namespace {
std::mutex g_logLock;
std::string g_dir;
int g_fd = -1;
bool g_tried = false;

void OpenFile() {
    if (g_tried || g_dir.empty()) return;
    g_tried = true;
    std::string path = g_dir + "/" RHIPPER_NAME ".log";
    g_fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
}
}  // namespace

const std::string& LogDir() { return g_dir; }

void SetLogDir(const char* dir) {
    std::lock_guard<std::mutex> hold(g_logLock);
    g_dir = dir ? dir : "";
    g_tried = false;
    if (g_fd >= 0) close(g_fd);
    g_fd = -1;
}

void Log(const char* fmt, ...) {
    char line[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > static_cast<int>(sizeof line) - 2) n = sizeof line - 2;
    __android_log_write(ANDROID_LOG_INFO, RHIPPER_NAME, line);
    std::lock_guard<std::mutex> hold(g_logLock);
    OpenFile();
    if (g_fd >= 0) {
        line[n] = '\n';
        (void)!write(g_fd, line, n + 1);
    }
}

void LogOnce(const char* key, const char* fmt, ...) {
    static std::mutex lock;
    static std::unordered_set<std::string> seen;
    {
        std::lock_guard<std::mutex> hold(lock);
        if (!seen.insert(key).second) return;
    }
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    Log("%s", line);
}

void LogFlush() {
    std::lock_guard<std::mutex> hold(g_logLock);
    if (g_fd >= 0) fsync(g_fd);
}

// (from a signal handler: no lock, no allocation; logcat's writer is async-signal tolerant enough
// for a report the process dies after)
void LogRaw(const char* s) {
    __android_log_write(ANDROID_LOG_ERROR, RHIPPER_NAME, s);
    if (g_fd >= 0) {
        (void)!write(g_fd, s, strlen(s));
        (void)!write(g_fd, "\n", 1);
    }
}

std::string Env(const char* suffix) {
    std::string name = std::string(RHIPPER_ENV) + "_" + suffix;
    const char* v = getenv(name.c_str());
    return v ? v : "";
}

}  // namespace rh
