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
// (with the bias the zone has now, not the one it had at that time: Windows' documented behaviour)
static uint32_t FileTimeToLocalFileTime_(uint32_t in, uint32_t out) {
    uint64_t ft = *At<uint64_t>(in);
    *At<uint64_t>(out) = ft + LocalBias100ns(time(nullptr));
    return 1;
}
RH_REG(KERNEL32, FileTimeToLocalFileTime, FileTimeToLocalFileTime_)
static uint32_t FileTimeToSystemTime_(uint32_t in, uint32_t out) {
    uint64_t ft = *At<uint64_t>(in);
    if (ft > 0x7FFFFFFFFFFFFFFFull) return SetLastError(win::ERROR_INVALID_PARAMETER), 0;
    *At<SystemTime>(out) = ToSystemTime(ft);
    return 1;
}
RH_REG(KERNEL32, FileTimeToSystemTime, FileTimeToSystemTime_)
// (fields out of range fail, as Windows' do, where timegm would carry them over)
static uint32_t SystemTimeToFileTime_(uint32_t in, uint32_t out) {
    const SystemTime& s = *At<SystemTime>(in);
    static const uint8_t days[12] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    bool leap = (s.year % 4 == 0 && s.year % 100 != 0) || s.year % 400 == 0;
    if (s.year < 1601 || s.year > 30827 || s.month < 1 || s.month > 12 || s.day < 1 || s.day > days[s.month - 1] ||
        (s.month == 2 && s.day == 29 && !leap) || s.hour > 23 || s.minute > 59 || s.second > 59 || s.ms > 999)
        return SetLastError(win::ERROR_INVALID_PARAMETER), 0;
    tm t = {};
    t.tm_year = s.year - 1900;
    t.tm_mon = s.month - 1;
    t.tm_mday = s.day;
    t.tm_hour = s.hour;
    t.tm_min = s.minute;
    t.tm_sec = s.second;
    time_t secs = timegm(&t);
    *At<uint64_t>(out) = static_cast<uint64_t>(static_cast<int64_t>(secs) + 11644473600ll) * 10000000ull + s.ms * 10000ull;
    return 1;
}
RH_REG(KERNEL32, SystemTimeToFileTime, SystemTimeToFileTime_)

// TIME_ZONE_INFORMATION (172 bytes): the host zone's standard bias and, where it keeps daylight time,
// this year's two changes as Windows' rules ("the n-th weekday of a month at a local time", n 5 the
// last), found from the host's own rules. A zone without daylight time: TIME_ZONE_ID_UNKNOWN
namespace {
#pragma pack(push, 4)
struct TimeZone32 {
    int32_t bias;
    char16_t standardName[32];
    SystemTime standardDate;
    int32_t standardBias;
    char16_t daylightName[32];
    SystemTime daylightDate;
    int32_t daylightBias;
};
#pragma pack(pop)
static_assert(sizeof(TimeZone32) == 172, "TIME_ZONE_INFORMATION");

bool IsDst(time_t t, long* off = nullptr, std::string* name = nullptr) {
    tm l;
    localtime_r(&t, &l);
    if (off) *off = l.tm_gmtoff;
    if (name) *name = l.tm_zone ? l.tm_zone : "";
    return l.tm_isdst > 0;
}

// the first second at which IsDst differs from IsDst(lo), lo < hi and the two differing
time_t Change(time_t lo, time_t hi) {
    bool from = IsDst(lo);
    while (hi - lo > 1) {
        time_t mid = lo + (hi - lo) / 2;
        (IsDst(mid) == from ? lo : hi) = mid;
    }
    return hi;
}

// the change at `t` as a rule, in the local time it happens at (the offset before it)
SystemTime Rule(time_t t, long offBefore) {
    time_t local = t + offBefore;
    tm u;
    gmtime_r(&local, &u);
    static const int mdays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int y = u.tm_year + 1900, inMonth = mdays[u.tm_mon] + (u.tm_mon == 1 && ((y % 4 == 0 && y % 100) || y % 400 == 0));
    uint16_t week = u.tm_mday + 7 > inMonth ? 5 : static_cast<uint16_t>((u.tm_mday - 1) / 7 + 1);
    return {0, static_cast<uint16_t>(u.tm_mon + 1), static_cast<uint16_t>(u.tm_wday), week, static_cast<uint16_t>(u.tm_hour),
            static_cast<uint16_t>(u.tm_min), static_cast<uint16_t>(u.tm_sec), 0};
}

void PutName(char16_t* out, const std::string& s) {
    std::u16string w = Widen(s.empty() ? "UTC" : s.c_str());
    memcpy(out, w.data(), std::min<size_t>(w.size(), 31) * 2);
}
}  // namespace

static uint32_t ZoneOf(TimeZone32* o) {
    memset(o, 0, sizeof *o);
    time_t now = time(nullptr);
    long nowOff = 0;
    std::string nowName;
    bool nowDst = IsDst(now, &nowOff, &nowName);
    // (this year's changes: a day's steps from its first day, each change found to the second)
    tm l;
    localtime_r(&now, &l);
    tm jan = {};
    jan.tm_year = l.tm_year;
    jan.tm_mday = 1;
    time_t start = timegm(&jan) - 14 * 3600, toDst = 0, toStd = 0;
    for (time_t day = start; day < start + 367 * 86400 && !(toDst && toStd); day += 86400)
        if (IsDst(day) != IsDst(day + 86400)) {
            time_t c = Change(day, day + 86400);
            (IsDst(c) ? toDst : toStd) = c;
        }
    if (!toDst || !toStd) {
        o->bias = -static_cast<int32_t>(nowOff / 60);
        PutName(o->standardName, nowName);
        return 0;   // TIME_ZONE_ID_UNKNOWN
    }
    long stdOff = 0, dstOff = 0;
    std::string stdName, dstName;
    IsDst(toStd, &stdOff, &stdName);
    IsDst(toDst, &dstOff, &dstName);
    o->bias = -static_cast<int32_t>(stdOff / 60);
    o->daylightBias = -static_cast<int32_t>((dstOff - stdOff) / 60);
    o->standardDate = Rule(toStd, dstOff);   // (in daylight time, the time it ends at)
    o->daylightDate = Rule(toDst, stdOff);   // (in standard time, the time it starts at)
    PutName(o->standardName, stdName);
    PutName(o->daylightName, dstName);
    return nowDst ? 2 : 1;   // TIME_ZONE_ID_DAYLIGHT / TIME_ZONE_ID_STANDARD
}
// (worked out again each minute at most: a few hundred localtime_r calls)
static uint32_t GetTimeZoneInformation_(uint32_t out) {
    static std::mutex lock;
    static TimeZone32 zone;
    static uint32_t id = 0;
    static uint64_t at = 0;
    std::lock_guard<std::mutex> hold(lock);
    uint64_t now = NowMs();
    if (!at || now - at > 60000) {
        id = ZoneOf(&zone);
        at = now;
    }
    *At<TimeZone32>(out) = zone;
    return id;
}
RH_REG(KERNEL32, GetTimeZoneInformation, GetTimeZoneInformation_)
