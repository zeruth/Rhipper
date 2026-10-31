// kernel32's time, environment, command line and version: Windows 7 SP1 as a Western user's PC
// would answer, the clocks the host's.
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <vector>

#include "Runtime.h"

namespace rh {

namespace {
std::mutex g_envLock;
// the reference's environment: case-insensitive names, kept sorted as Windows keeps its block
struct NoCase {
    bool operator()(const std::string& a, const std::string& b) const { return strcasecmp(a.c_str(), b.c_str()) < 0; }
};
std::map<std::string, std::string, NoCase> g_env;
std::string g_commandLine;
uint32_t g_commandLineA = 0;
}  // namespace

// the environment a Western Windows 7 user's process starts with, and the project's own variables
// (<ENV>_...) from the host's, so a debugging switch reaches the reference as on Windows
void InitEnvironment() {
    std::lock_guard<std::mutex> hold(g_envLock);
    if (!g_env.empty()) return;
    const char* defaults[][2] = {
        {"ALLUSERSPROFILE", "C:\\ProgramData"}, {"APPDATA", "C:\\Users\\Player\\AppData\\Roaming"},
        {"CommonProgramFiles", "C:\\Program Files\\Common Files"}, {"COMPUTERNAME", "ANDROID"},
        {"ComSpec", "C:\\Windows\\system32\\cmd.exe"}, {"HOMEDRIVE", "C:"}, {"HOMEPATH", "\\Users\\Player"},
        {"LOCALAPPDATA", "C:\\Users\\Player\\AppData\\Local"}, {"OS", "Windows_NT"},
        {"PATH", "C:\\Windows\\system32;C:\\Windows"}, {"PATHEXT", ".COM;.EXE;.BAT;.CMD"},
        {"PROCESSOR_ARCHITECTURE", "x86"}, {"PROCESSOR_ARCHITEW6432", "AMD64"},
        {"ProgramData", "C:\\ProgramData"}, {"ProgramFiles", "C:\\Program Files (x86)"},
        {"PUBLIC", "C:\\Users\\Public"}, {"SystemDrive", "C:"}, {"SystemRoot", "C:\\Windows"},
        {"TEMP", "C:\\Users\\Player\\AppData\\Local\\Temp"}, {"TMP", "C:\\Users\\Player\\AppData\\Local\\Temp"},
        {"USERDOMAIN", "ANDROID"}, {"USERNAME", "Player"}, {"USERPROFILE", "C:\\Users\\Player"},
        {"windir", "C:\\Windows"}};
    for (auto& d : defaults) g_env[d[0]] = d[1];
    g_env["NUMBER_OF_PROCESSORS"] = std::to_string(sysconf(_SC_NPROCESSORS_ONLN));
    std::string prefix = std::string(RHIPPER_ENV) + "_";
    for (char** e = environ; e && *e; e++)
        if (strncmp(*e, prefix.c_str(), prefix.size()) == 0)
            if (const char* eq = strchr(*e, '=')) g_env[std::string(*e, static_cast<size_t>(eq - *e))] = eq + 1;
}

// the command line as the reference's: the program's Windows path quoted, then each argument,
// quoted where it has a space
void SetCommandLine(int argc, const char* const* argv) {
    std::string line = "\"" + Narrow(RefModulePath().c_str()) + "\"";
    for (int k = 1; k < argc; k++) {
        std::string a = argv[k] ? argv[k] : "";
        line += " ";
        line += a.find_first_of(" \t") == std::string::npos && !a.empty() ? a : "\"" + a + "\"";
    }
    g_commandLine = line;
    std::string ansi = AnsiOf(Widen(line.c_str()));
    auto p = static_cast<char*>(LowNew(ansi.size() + 1));
    memcpy(p, ansi.c_str(), ansi.size() + 1);
    g_commandLineA = Low(p);
    Log("command line: %s", line.c_str());
}

}  // namespace rh

using namespace rh;

static uint32_t GetCommandLineA_() { return g_commandLineA; }
RH_REG(KERNEL32, GetCommandLineA, GetCommandLineA_)

// GetEnvironmentStringsW: a block of its own, NAME=value\0 ... \0, freed by FreeEnvironmentStringsW
static uint32_t GetEnvironmentStringsW_() {
    InitEnvironment();
    std::u16string block;
    {
        std::lock_guard<std::mutex> hold(g_envLock);
        for (auto& [k, v] : g_env) block += Widen((k + "=" + v).c_str()) + u'\0';
    }
    block += u'\0';
    uint32_t p = HeapAllocIn(ProcessHeap(), 0, static_cast<uint32_t>(block.size() * 2));
    memcpy(At(p), block.data(), block.size() * 2);
    return p;
}
RH_REG(KERNEL32, GetEnvironmentStringsW, GetEnvironmentStringsW_)
static uint32_t FreeEnvironmentStringsW_(uint32_t p) { return HeapFreeIn(ProcessHeap(), 0, p); }
RH_REG(KERNEL32, FreeEnvironmentStringsW, FreeEnvironmentStringsW_)
static uint32_t SetEnvironmentVariableA_(uint32_t name, uint32_t value) {
    InitEnvironment();
    std::lock_guard<std::mutex> hold(g_envLock);
    if (value) g_env[At<char>(name)] = At<char>(value);
    else g_env.erase(At<char>(name));
    return 1;
}
RH_REG(KERNEL32, SetEnvironmentVariableA, SetEnvironmentVariableA_)

// GetVersionExA: Windows 7 SP1 (OSVERSIONINFOA 148 bytes, the EX form 156)
static uint32_t GetVersionExA_(uint32_t out) {
    uint32_t size = U32(out);
    if (size != 148 && size != 156) return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
    auto o = At<uint8_t>(out);
    memset(o + 4, 0, size - 4);
    uint32_t v[4] = {6, 1, 7601, 2};
    memcpy(o + 4, v, 16);
    strcpy(reinterpret_cast<char*>(o + 20), "Service Pack 1");
    if (size == 156) {
        *reinterpret_cast<uint16_t*>(o + 148) = 1;   // wServicePackMajor
        *reinterpret_cast<uint16_t*>(o + 152) = 0x100;   // wSuiteMask: VER_SUITE_SINGLEUSERTS
        o[154] = 1;                                   // wProductType: VER_NT_WORKSTATION
    }
    return 1;
}
RH_REG(KERNEL32, GetVersionExA, GetVersionExA_)

// ---- time ---------------------------------------------------------------------------------------
namespace {
uint64_t Mono100ns() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 10000000ull + ts.tv_nsec / 100;
}
uint64_t NowFileTime() {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return FileTimeOf(ts);
}
struct SystemTime {
    uint16_t year, month, dayOfWeek, day, hour, minute, second, ms;
};
static_assert(sizeof(SystemTime) == 16, "SYSTEMTIME");

SystemTime ToSystemTime(uint64_t ft) {
    time_t secs = static_cast<time_t>(ft / 10000000ull - 11644473600ull);
    tm t;
    gmtime_r(&secs, &t);
    return {static_cast<uint16_t>(t.tm_year + 1900), static_cast<uint16_t>(t.tm_mon + 1), static_cast<uint16_t>(t.tm_wday),
            static_cast<uint16_t>(t.tm_mday), static_cast<uint16_t>(t.tm_hour), static_cast<uint16_t>(t.tm_min),
            static_cast<uint16_t>(t.tm_sec), static_cast<uint16_t>((ft / 10000) % 1000)};
}
int64_t LocalBias100ns(time_t at) {
    tm l;
    localtime_r(&at, &l);
    return static_cast<int64_t>(l.tm_gmtoff) * 10000000;
}
}  // namespace

static uint32_t GetTickCount_() { return static_cast<uint32_t>(NowMs()); }
RH_REG(KERNEL32, GetTickCount, GetTickCount_)
// (10 MHz, as Windows 8's and a modern Windows 7's invariant counter)
static uint32_t QueryPerformanceCounter_(uint32_t out) {
    *At<uint64_t>(out) = Mono100ns();
    return 1;
}
RH_REG(KERNEL32, QueryPerformanceCounter, QueryPerformanceCounter_)
static uint32_t QueryPerformanceFrequency_(uint32_t out) {
    *At<uint64_t>(out) = 10000000;
    return 1;
}
RH_REG(KERNEL32, QueryPerformanceFrequency, QueryPerformanceFrequency_)
static uint32_t GetSystemTimeAsFileTime_(uint32_t out) {
    *At<uint64_t>(out) = NowFileTime();
    return 0;
}
RH_REG(KERNEL32, GetSystemTimeAsFileTime, GetSystemTimeAsFileTime_)
static uint32_t GetSystemTime_(uint32_t out) {
    *At<SystemTime>(out) = ToSystemTime(NowFileTime());
    return 0;
}
RH_REG(KERNEL32, GetSystemTime, GetSystemTime_)
static uint32_t GetLocalTime_(uint32_t out) {
    uint64_t ft = NowFileTime();
    *At<SystemTime>(out) = ToSystemTime(ft + LocalBias100ns(time(nullptr)));
    return 0;
}
RH_REG(KERNEL32, GetLocalTime, GetLocalTime_)
static uint32_t FileTimeToLocalFileTime_(uint32_t in, uint32_t out) {
    uint64_t ft = *At<uint64_t>(in);
    *At<uint64_t>(out) = ft + LocalBias100ns(static_cast<time_t>(ft / 10000000ull - 11644473600ull));
    return 1;
}
RH_REG(KERNEL32, FileTimeToLocalFileTime, FileTimeToLocalFileTime_)
static uint32_t FileTimeToSystemTime_(uint32_t in, uint32_t out) {
    *At<SystemTime>(out) = ToSystemTime(*At<uint64_t>(in));
    return 1;
}
RH_REG(KERNEL32, FileTimeToSystemTime, FileTimeToSystemTime_)
static uint32_t SystemTimeToFileTime_(uint32_t in, uint32_t out) {
    const SystemTime& s = *At<SystemTime>(in);
    tm t = {};
    t.tm_year = s.year - 1900;
    t.tm_mon = s.month - 1;
    t.tm_mday = s.day;
    t.tm_hour = s.hour;
    t.tm_min = s.minute;
    t.tm_sec = s.second;
    time_t secs = timegm(&t);
    if (secs == static_cast<time_t>(-1) && s.year != 1969) return SetLastError(win::ERROR_INVALID_PARAMETER), 0;
    *At<uint64_t>(out) = (static_cast<uint64_t>(secs) + 11644473600ull) * 10000000ull + s.ms * 10000ull;
    return 1;
}
RH_REG(KERNEL32, SystemTimeToFileTime, SystemTimeToFileTime_)

// TIME_ZONE_INFORMATION (172 bytes): the bias the host's zone has now, no daylight rules
static uint32_t GetTimeZoneInformation_(uint32_t out) {
    auto o = At<uint8_t>(out);
    memset(o, 0, 172);
    time_t now = time(nullptr);
    tm l;
    localtime_r(&now, &l);
    *reinterpret_cast<int32_t*>(o) = -static_cast<int32_t>(l.tm_gmtoff / 60);
    std::u16string name = Widen(l.tm_zone ? l.tm_zone : "UTC");
    memcpy(o + 4, name.data(), std::min<size_t>(name.size(), 31) * 2);
    return 0;   // TIME_ZONE_ID_UNKNOWN
}
RH_REG(KERNEL32, GetTimeZoneInformation, GetTimeZoneInformation_)
