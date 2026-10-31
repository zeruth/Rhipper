// kernel32's files: the reference's Windows paths on the host's files (Paths.cpp), file handles
// over descriptors, directory searches, pipes, the standard handles (into the log), and the time
// conversions the file functions use.
//
// Overlapped I/O: the reference imports no GetOverlappedResult nor a completion port, so an
// OVERLAPPED is a position (and an event to set): ReadFile and WriteFile with one read or write at
// its offset, synchronously, and report the transfer in it as a completed operation would.
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <vector>

#include "Runtime.h"

namespace rh {

std::shared_ptr<Object> MakeEvent(bool manual, bool initial);   // kernel32_sync.cpp
void SignalEvent(const std::shared_ptr<Object>& o);

struct File : Object {
    int fd = -1;
    bool dir = false;
    uint32_t type = 1;            // FILE_TYPE_DISK 1, CHAR 2, PIPE 3
    int logStream = 0;            // 1 stdout, 2 stderr: written into the log
    std::string path, deleteOnClose;
    const char* Kind() const override { return "file"; }
    bool Close() override {
        if (logStream) return true;   // (the standard handles stay)
        if (fd >= 0) close(fd);
        fd = -1;
        if (!deleteOnClose.empty()) unlink(deleteOnClose.c_str());
        return true;
    }
    ~File() override {
        if (fd >= 0 && !logStream) close(fd);
    }
};

uint64_t FileTimeOf(const timespec& t) {
    return (static_cast<uint64_t>(t.tv_sec) + 11644473600ull) * 10000000ull + t.tv_nsec / 100;
}

uint32_t AttributesOf(const struct stat& st, const std::string& name) {
    uint32_t a = 0;
    if (S_ISDIR(st.st_mode)) a |= 0x10;
    if (!(st.st_mode & S_IWUSR)) a |= 0x1;
    if (!name.empty() && name[0] == '.' && name != "." && name != "..") a |= 0x2;   // (hidden)
    return a ? a : 0x80;   // FILE_ATTRIBUTE_NORMAL
}

}  // namespace rh

using namespace rh;

namespace {

std::shared_ptr<File> FileOf(uint32_t h) {
    // (the standard handles' pseudo values, -10/-11/-12, are GetStdHandle's)
    return GetAs<File>(h);
}

uint32_t Fail(int e) {
    SetLastError(ErrnoToWin(e));
    return 0;
}

// CreateFile: access GENERIC_READ 0x80000000 / GENERIC_WRITE 0x40000000; disposition CREATE_NEW 1,
// CREATE_ALWAYS 2, OPEN_EXISTING 3, OPEN_ALWAYS 4, TRUNCATE_EXISTING 5; flags' DELETE_ON_CLOSE
// 0x04000000 and BACKUP_SEMANTICS 0x02000000 (a directory opened)
uint32_t OpenFile(const std::string& windows, uint32_t access, uint32_t disposition, uint32_t flags) {
    if (windows.compare(0, 4, "\\\\.\\") == 0 || windows == "CONIN$" || windows == "CONOUT$") {
        LogOnce(("device " + windows).c_str(), "CreateFile(%s): no devices here", windows.c_str());
        SetLastError(win::ERROR_FILE_NOT_FOUND);
        return kInvalidHandle;
    }
    std::string path = HostPath(windows, disposition != 3 && disposition != 5);
    struct stat st;
    bool existed = stat(path.c_str(), &st) == 0;
    auto f = std::make_shared<File>();
    f->path = path;
    if (existed && S_ISDIR(st.st_mode)) {
        if (!(flags & 0x02000000)) {
            SetLastError(win::ERROR_ACCESS_DENIED);
            return kInvalidHandle;
        }
        f->dir = true;
        f->fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        return f->fd < 0 ? (Fail(errno), kInvalidHandle) : NewHandle(f);
    }
    int o = O_CLOEXEC;
    bool rd = access & 0x80000001u, wr = access & 0x40000002u;   // (GENERIC_* or FILE_READ/WRITE_DATA)
    if (access & 0x10000000u) rd = wr = true;                       // GENERIC_ALL
    o |= rd && wr ? O_RDWR : wr ? O_WRONLY : O_RDONLY;
    switch (disposition) {
        case 1: o |= O_CREAT | O_EXCL; break;
        case 2: o |= O_CREAT | O_TRUNC; break;
        case 3: break;
        case 4: o |= O_CREAT; break;
        case 5: o |= O_TRUNC; break;
        default: SetLastError(win::ERROR_INVALID_PARAMETER); return kInvalidHandle;
    }
    if ((o & (O_CREAT | O_TRUNC)) && !wr) o = (o & ~O_RDONLY) | O_RDWR;
    f->fd = open(path.c_str(), o, 0644);
    if (f->fd < 0) {
        int e = errno;
        SetLastError(e == EEXIST ? win::ERROR_FILE_EXISTS : ErrnoToWin(e));
        if (e != ENOENT) Log("CreateFile(%s -> %s): errno %d", windows.c_str(), path.c_str(), e);
        return kInvalidHandle;
    }
    if (flags & 0x04000000) f->deleteOnClose = path;
    // (CREATE_ALWAYS and OPEN_ALWAYS on an existing file succeed with ERROR_ALREADY_EXISTS)
    SetLastError(existed && (disposition == 2 || disposition == 4) ? win::ERROR_ALREADY_EXISTS : 0);
    return NewHandle(f);
}

struct Ov32 {
    uint32_t internal, internalHigh, offset, offsetHigh, event;
};
static_assert(sizeof(Ov32) == 20, "OVERLAPPED, x86");

void OvDone(uint32_t ov, ssize_t n) {
    auto o = At<Ov32>(ov);
    o->internal = 0;   // STATUS_SUCCESS
    o->internalHigh = n < 0 ? 0 : static_cast<uint32_t>(n);
    if (o->event)
        if (auto e = GetHandle(o->event)) SignalEvent(e);
}

std::shared_ptr<File> StdFile(int which) {
    static std::shared_ptr<File> files[3];
    static std::once_flag once;
    std::call_once(once, [] {
        for (int k = 0; k < 3; k++) {
            files[k] = std::make_shared<File>();
            files[k]->type = 2;
            files[k]->fd = k == 0 ? open("/dev/null", O_RDONLY | O_CLOEXEC) : -1;
            files[k]->logStream = k;
        }
    });
    return files[which];
}
uint32_t g_std[3] = {};

}  // namespace

extern "C" {

unsigned int gen_imp_CreateFileW(uintptr_t name, uint32_t access, uint32_t, uint32_t, uint32_t disposition,
                                 uint32_t flags, uint32_t) {
    return OpenFile(Narrow(WStr(name)), access, disposition, flags);
}
unsigned int gen_imp_CreateFileA(uintptr_t name, uint32_t access, uint32_t, uint32_t, uint32_t disposition,
                                 uint32_t flags, uint32_t) {
    return OpenFile(Narrow(Ansi16(Str(name)).c_str()), access, disposition, flags);
}

unsigned int gen_imp_ReadFile(uint32_t h, uint32_t buf, uint32_t n, uint32_t got, uint32_t ov) {
    auto f = FileOf(h);
    if (got) *At<uint32_t>(got) = 0;
    if (!f || f->fd < 0) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    ssize_t r;
    if (ov) {
        auto o = At<Ov32>(ov);
        r = pread(f->fd, At(buf), n, static_cast<off_t>(o->offset | (static_cast<uint64_t>(o->offsetHigh) << 32)));
    } else {
        do r = read(f->fd, At(buf), n);
        while (r < 0 && errno == EINTR);
    }
    if (r < 0) return Fail(errno);
    if (got) *At<uint32_t>(got) = static_cast<uint32_t>(r);
    if (ov) {
        OvDone(ov, r);
        // (an overlapped read at the end: ERROR_HANDLE_EOF, as Windows)
        if (r == 0 && n) return SetLastError(win::ERROR_HANDLE_EOF), 0;
    }
    return 1;
}

unsigned int gen_imp_WriteFile(uint32_t h, uint32_t buf, uint32_t n, uint32_t put, uint32_t ov) {
    if (put) *At<uint32_t>(put) = 0;
    auto f = FileOf(h);
    if (!f) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    if (f->logStream) {
        std::string s(At<char>(buf), n);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        Log("%s: %s", f->logStream == 1 ? "stdout" : "stderr", s.c_str());
        if (put) *At<uint32_t>(put) = n;
        return 1;
    }
    if (f->fd < 0) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    ssize_t r;
    if (ov) {
        auto o = At<Ov32>(ov);
        r = pwrite(f->fd, At(buf), n, static_cast<off_t>(o->offset | (static_cast<uint64_t>(o->offsetHigh) << 32)));
    } else {
        do r = write(f->fd, At(buf), n);
        while (r < 0 && errno == EINTR);
    }
    if (r < 0) return Fail(errno);
    if (put) *At<uint32_t>(put) = static_cast<uint32_t>(r);
    if (ov) OvDone(ov, r);
    return 1;
}

// (its LARGE_INTEGER as the two words the reference pushed: ApplyFacts' splitWideImportArgs32)
unsigned int gen_imp_SetFilePointerEx(uint32_t h, uint32_t low, uint32_t high, uint32_t out, uint32_t method) {
    auto f = FileOf(h);
    if (!f || f->fd < 0) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    off_t at = lseek(f->fd, static_cast<off_t>(static_cast<int64_t>(low | (static_cast<uint64_t>(high) << 32))),
                     method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END);
    if (at < 0) return Fail(errno);
    if (out) *At<int64_t>(out) = at;
    return 1;
}

unsigned int gen_imp_CreateDirectoryW(uintptr_t path, uint32_t) {
    std::string p = HostPath(Narrow(WStr(path)), true);
    if (mkdir(p.c_str(), 0755) != 0) return SetLastError(errno == EEXIST ? win::ERROR_ALREADY_EXISTS : ErrnoToWin(errno)), 0;
    return 1;
}

unsigned int gen_imp_CreatePipe(uint32_t read, uint32_t write, uint32_t, uint32_t) {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) return Fail(errno);
    auto r = std::make_shared<File>(), w = std::make_shared<File>();
    r->fd = fds[0], w->fd = fds[1];
    r->type = w->type = 3;
    *At<uint32_t>(read) = NewHandle(r);
    *At<uint32_t>(write) = NewHandle(w);
    return 1;
}

}  // extern "C"

static uint32_t SetFilePointer_(uint32_t h, uint32_t low, uint32_t phigh, uint32_t method) {
    auto f = FileOf(h);
    if (!f || f->fd < 0) return SetLastError(win::ERROR_INVALID_HANDLE), 0xFFFFFFFFu;
    int64_t d = phigh ? static_cast<int64_t>(low | (static_cast<uint64_t>(U32(phigh)) << 32))
                      : static_cast<int64_t>(static_cast<int32_t>(low));
    off_t at = lseek(f->fd, static_cast<off_t>(d), method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END);
    if (at < 0) return Fail(errno), 0xFFFFFFFFu;
    if (phigh) *At<uint32_t>(phigh) = static_cast<uint32_t>(static_cast<uint64_t>(at) >> 32);
    SetLastError(0);
    return static_cast<uint32_t>(at);
}
RH_REG(KERNEL32, SetFilePointer, SetFilePointer_)

static uint32_t GetFileSizeEx_(uint32_t h, uint32_t out) {
    auto f = FileOf(h);
    struct stat st;
    if (!f || f->fd < 0 || fstat(f->fd, &st) != 0) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    *At<int64_t>(out) = st.st_size;
    return 1;
}
RH_REG(KERNEL32, GetFileSizeEx, GetFileSizeEx_)

static uint32_t GetFileType_(uint32_t h) {
    auto f = FileOf(h);
    return f ? f->type : 0;
}
RH_REG(KERNEL32, GetFileType, GetFileType_)

static uint32_t FlushFileBuffers_(uint32_t h) {
    auto f = FileOf(h);
    if (f && f->fd >= 0) fdatasync(f->fd);
    return f ? 1 : 0;
}
RH_REG(KERNEL32, FlushFileBuffers, FlushFileBuffers_)

static uint32_t SetEndOfFile_(uint32_t h) {
    auto f = FileOf(h);
    if (!f || f->fd < 0) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    off_t at = lseek(f->fd, 0, SEEK_CUR);
    return ftruncate(f->fd, at) == 0 ? 1 : Fail(errno);
}
RH_REG(KERNEL32, SetEndOfFile, SetEndOfFile_)

// BY_HANDLE_FILE_INFORMATION (52 bytes)
static uint32_t GetFileInformationByHandle_(uint32_t h, uint32_t out) {
    auto f = FileOf(h);
    struct stat st;
    if (!f || f->fd < 0 || fstat(f->fd, &st) != 0) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
#pragma pack(push, 4)
    struct Info {
        uint32_t attrs;
        uint64_t created, accessed, written;
        uint32_t volume, sizeHigh, sizeLow, links, indexHigh, indexLow;
    };
#pragma pack(pop)
    static_assert(sizeof(Info) == 52, "BY_HANDLE_FILE_INFORMATION");
    auto o = At<Info>(out);
    o->attrs = AttributesOf(st, "");
    o->created = FileTimeOf(st.st_ctim);
    o->accessed = FileTimeOf(st.st_atim);
    o->written = FileTimeOf(st.st_mtim);
    o->volume = static_cast<uint32_t>(st.st_dev);
    o->sizeHigh = static_cast<uint32_t>(static_cast<uint64_t>(st.st_size) >> 32);
    o->sizeLow = static_cast<uint32_t>(st.st_size);
    o->links = static_cast<uint32_t>(st.st_nlink);
    o->indexHigh = static_cast<uint32_t>(static_cast<uint64_t>(st.st_ino) >> 32);
    o->indexLow = static_cast<uint32_t>(st.st_ino);
    return 1;
}
RH_REG(KERNEL32, GetFileInformationByHandle, GetFileInformationByHandle_)

static uint32_t Attributes(const std::string& windows) {
    struct stat st;
    std::string p = HostPath(windows);
    if (stat(p.c_str(), &st) != 0) return Fail(errno), 0xFFFFFFFFu;
    return AttributesOf(st, p.substr(p.rfind('/') + 1));
}
static uint32_t GetFileAttributesA_(uint32_t name) { return Attributes(Narrow(Ansi16(At<char>(name)).c_str())); }
RH_REG(KERNEL32, GetFileAttributesA, GetFileAttributesA_)
static uint32_t GetFileAttributesW_(uint32_t name) { return Attributes(Narrow(At<char16_t>(name))); }
RH_REG(KERNEL32, GetFileAttributesW, GetFileAttributesW_)
static uint32_t SetFileAttributesW_(uint32_t name, uint32_t attrs) {
    std::string p = HostPath16(At<char16_t>(name));
    struct stat st;
    if (stat(p.c_str(), &st) != 0) return Fail(errno);
    chmod(p.c_str(), (attrs & 1) ? (st.st_mode & ~0222) : (st.st_mode | 0200));
    return 1;
}
RH_REG(KERNEL32, SetFileAttributesW, SetFileAttributesW_)

static uint32_t DeleteFileA_(uint32_t name) {
    return unlink(HostPath(Narrow(Ansi16(At<char>(name)).c_str())).c_str()) == 0 ? 1 : Fail(errno);
}
RH_REG(KERNEL32, DeleteFileA, DeleteFileA_)
static uint32_t DeleteFileW_(uint32_t name) { return unlink(HostPath16(At<char16_t>(name)).c_str()) == 0 ? 1 : Fail(errno); }
RH_REG(KERNEL32, DeleteFileW, DeleteFileW_)
static uint32_t RemoveDirectoryW_(uint32_t name) { return rmdir(HostPath16(At<char16_t>(name)).c_str()) == 0 ? 1 : Fail(errno); }
RH_REG(KERNEL32, RemoveDirectoryW, RemoveDirectoryW_)

static uint32_t Move(const std::string& from, const std::string& to) {
    std::string a = HostPath(from), b = HostPath(to, true);
    if (access(b.c_str(), F_OK) == 0) return SetLastError(win::ERROR_ALREADY_EXISTS), 0;   // (MoveFile does not replace)
    return rename(a.c_str(), b.c_str()) == 0 ? 1 : Fail(errno);
}
static uint32_t MoveFileA_(uint32_t a, uint32_t b) {
    return Move(Narrow(Ansi16(At<char>(a)).c_str()), Narrow(Ansi16(At<char>(b)).c_str()));
}
RH_REG(KERNEL32, MoveFileA, MoveFileA_)
static uint32_t MoveFileW_(uint32_t a, uint32_t b) { return Move(Narrow(At<char16_t>(a)), Narrow(At<char16_t>(b))); }
RH_REG(KERNEL32, MoveFileW, MoveFileW_)

static uint32_t CopyFileW_(uint32_t from, uint32_t to, uint32_t failIfExists) {
    std::string a = HostPath16(At<char16_t>(from)), b = HostPath16(At<char16_t>(to), true);
    int in = open(a.c_str(), O_RDONLY | O_CLOEXEC);
    if (in < 0) return Fail(errno);
    int out = open(b.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC | (failIfExists ? O_EXCL : O_TRUNC), 0644);
    if (out < 0) {
        int e = errno;
        close(in);
        return SetLastError(e == EEXIST ? win::ERROR_FILE_EXISTS : ErrnoToWin(e)), 0;
    }
    char buf[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(in, buf, sizeof buf)) > 0) ok = ok && write(out, buf, n) == n;
    close(in);
    close(out);
    return ok && n == 0 ? 1 : Fail(EIO);
}
RH_REG(KERNEL32, CopyFileW, CopyFileW_)

// ---- directory searches: WIN32_FIND_DATAW (592 bytes) and WIN32_FIND_DATAA (320) ---------------
namespace {
#pragma pack(push, 4)
struct FindDataW {
    uint32_t attrs;
    uint64_t created, accessed, written;
    uint32_t sizeHigh, sizeLow, reserved0, reserved1;
    char16_t name[260], alt[14];
};
struct FindDataA {
    uint32_t attrs;
    uint64_t created, accessed, written;
    uint32_t sizeHigh, sizeLow, reserved0, reserved1;
    char name[260], alt[14];
    uint8_t pad[2];
};
#pragma pack(pop)
static_assert(sizeof(FindDataW) == 592, "WIN32_FIND_DATAW, x86");
static_assert(sizeof(FindDataA) == 320, "WIN32_FIND_DATAA, x86");

struct Find : Object {
    std::string dir;
    std::vector<std::string> names;
    size_t next = 0;
    const char* Kind() const override { return "find"; }
};

template <typename D>
void Fill(D* d, const std::string& dir, const std::string& name) {
    memset(d, 0, sizeof *d);
    struct stat st = {};
    stat((dir + "/" + name).c_str(), &st);
    d->attrs = AttributesOf(st, name);
    d->created = FileTimeOf(st.st_ctim);
    d->accessed = FileTimeOf(st.st_atim);
    d->written = FileTimeOf(st.st_mtim);
    d->sizeHigh = S_ISDIR(st.st_mode) ? 0 : static_cast<uint32_t>(static_cast<uint64_t>(st.st_size) >> 32);
    d->sizeLow = S_ISDIR(st.st_mode) ? 0 : static_cast<uint32_t>(st.st_size);
    if constexpr (sizeof(d->name[0]) == 2) {
        std::u16string w = Widen(name.c_str());
        w.resize(std::min<size_t>(w.size(), 259));
        memcpy(d->name, w.data(), w.size() * 2);
    } else {
        std::string a = AnsiOf(Widen(name.c_str()));
        a.resize(std::min<size_t>(a.size(), 259));
        memcpy(d->name, a.data(), a.size());
    }
}

template <typename D>
uint32_t FindFirst(const std::string& pattern, uint32_t out) {
    size_t cut = pattern.find_last_of("\\/");
    std::string dirPart = cut == std::string::npos ? "." : pattern.substr(0, cut + 1);
    std::string mask = cut == std::string::npos ? pattern : pattern.substr(cut + 1);
    if (mask == "*.*") mask = "*";
    auto f = std::make_shared<Find>();
    f->dir = HostPath(dirPart);
    DIR* d = opendir(f->dir.c_str());
    if (!d) return Fail(errno), kInvalidHandle;
    bool root = f->dir == GameRoot();
    while (dirent* e = readdir(d)) {
        std::string n = e->d_name;
        if (root && (n == "." || n == "..")) continue;
        if (fnmatch(mask.c_str(), n.c_str(), FNM_CASEFOLD) == 0) f->names.push_back(n);
    }
    closedir(d);
    if (f->names.empty()) return SetLastError(win::ERROR_FILE_NOT_FOUND), kInvalidHandle;
    std::sort(f->names.begin(), f->names.end());
    Fill(At<D>(out), f->dir, f->names[f->next++]);
    return NewHandle(f);
}

template <typename D>
uint32_t FindNext(uint32_t h, uint32_t out) {
    auto f = GetAs<Find>(h);
    if (!f) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    if (f->next >= f->names.size()) return SetLastError(win::ERROR_NO_MORE_FILES), 0;
    Fill(At<D>(out), f->dir, f->names[f->next++]);
    return 1;
}
}  // namespace

static uint32_t FindFirstFileA_(uint32_t name, uint32_t out) {
    return FindFirst<FindDataA>(Narrow(Ansi16(At<char>(name)).c_str()), out);
}
RH_REG(KERNEL32, FindFirstFileA, FindFirstFileA_)
static uint32_t FindFirstFileW_(uint32_t name, uint32_t out) { return FindFirst<FindDataW>(Narrow(At<char16_t>(name)), out); }
RH_REG(KERNEL32, FindFirstFileW, FindFirstFileW_)
static uint32_t FindFirstFileExW_(uint32_t name, uint32_t, uint32_t out, uint32_t, uint32_t, uint32_t) {
    return FindFirst<FindDataW>(Narrow(At<char16_t>(name)), out);
}
RH_REG(KERNEL32, FindFirstFileExW, FindFirstFileExW_)
static uint32_t FindNextFileA_(uint32_t h, uint32_t out) { return FindNext<FindDataA>(h, out); }
RH_REG(KERNEL32, FindNextFileA, FindNextFileA_)
static uint32_t FindNextFileW_(uint32_t h, uint32_t out) { return FindNext<FindDataW>(h, out); }
RH_REG(KERNEL32, FindNextFileW, FindNextFileW_)
static uint32_t FindClose_(uint32_t h) { return CloseHandle32(h) ? 1 : 0; }
RH_REG(KERNEL32, FindClose, FindClose_)

// ---- paths and the working directory -----------------------------------------------------------
static uint32_t PutPath16(const std::u16string& s, uint32_t buf, uint32_t cap) {
    if (s.size() + 1 > cap) return static_cast<uint32_t>(s.size() + 1);
    memcpy(At(buf), s.c_str(), (s.size() + 1) * 2);
    return static_cast<uint32_t>(s.size());
}
static uint32_t PutPathA(const std::u16string& s, uint32_t buf, uint32_t cap) {
    std::string a = AnsiOf(s);
    if (a.size() + 1 > cap) return static_cast<uint32_t>(a.size() + 1);
    memcpy(At(buf), a.c_str(), a.size() + 1);
    return static_cast<uint32_t>(a.size());
}
static void FilePart(uint32_t buf, uint32_t len, uint32_t filePart, size_t unit) {
    if (!filePart) return;
    uint32_t last = 0;
    for (uint32_t k = 0; k < len; k++) {
        uint32_t c = unit == 2 ? At<char16_t>(buf)[k] : static_cast<unsigned char>(At<char>(buf)[k]);
        if (c == '\\') last = k + 1;
    }
    *At<uint32_t>(filePart) = last < len ? buf + last * static_cast<uint32_t>(unit) : 0;
}
static uint32_t GetFullPathNameW_(uint32_t name, uint32_t cap, uint32_t buf, uint32_t filePart) {
    uint32_t n = PutPath16(FullPath(At<char16_t>(name)), buf, cap);
    if (n < cap) FilePart(buf, n, filePart, 2);
    return n;
}
RH_REG(KERNEL32, GetFullPathNameW, GetFullPathNameW_)
static uint32_t GetFullPathNameA_(uint32_t name, uint32_t cap, uint32_t buf, uint32_t filePart) {
    uint32_t n = PutPathA(FullPath(Ansi16(At<char>(name))), buf, cap);
    if (n < cap) FilePart(buf, n, filePart, 1);
    return n;
}
RH_REG(KERNEL32, GetFullPathNameA, GetFullPathNameA_)
static uint32_t GetCurrentDirectoryW_(uint32_t cap, uint32_t buf) {
    std::u16string d = CurrentDirectory();
    if (d.size() > 3 && d.back() == u'\\') d.pop_back();   // (no trailing separator but the root's)
    return PutPath16(d, buf, cap);
}
RH_REG(KERNEL32, GetCurrentDirectoryW, GetCurrentDirectoryW_)
static uint32_t SetCurrentDirectoryW_(uint32_t dir) {
    return SetCurrentDirectory16(At<char16_t>(dir)) ? 1 : (SetLastError(win::ERROR_PATH_NOT_FOUND), 0);
}
RH_REG(KERNEL32, SetCurrentDirectoryW, SetCurrentDirectoryW_)
static uint32_t GetSystemDirectoryA_(uint32_t buf, uint32_t cap) { return PutPathA(u"C:\\Windows\\system32", buf, cap); }
RH_REG(KERNEL32, GetSystemDirectoryA, GetSystemDirectoryA_)

// ---- volumes: one fixed drive, C:, the game directory's file system ------------------------------
static uint32_t FreeSpace(uint32_t avail, uint32_t total, uint32_t free) {
    struct statvfs v;
    if (statvfs(GameRoot().c_str(), &v) != 0) return Fail(errno);
    if (avail) *At<uint64_t>(avail) = static_cast<uint64_t>(v.f_bavail) * v.f_frsize;
    if (total) *At<uint64_t>(total) = static_cast<uint64_t>(v.f_blocks) * v.f_frsize;
    if (free) *At<uint64_t>(free) = static_cast<uint64_t>(v.f_bfree) * v.f_frsize;
    return 1;
}
static uint32_t GetDiskFreeSpaceExA_(uint32_t, uint32_t a, uint32_t t, uint32_t f) { return FreeSpace(a, t, f); }
RH_REG(KERNEL32, GetDiskFreeSpaceExA, GetDiskFreeSpaceExA_)
static uint32_t GetDiskFreeSpaceExW_(uint32_t, uint32_t a, uint32_t t, uint32_t f) { return FreeSpace(a, t, f); }
RH_REG(KERNEL32, GetDiskFreeSpaceExW, GetDiskFreeSpaceExW_)
static uint32_t GetDriveTypeA_(uint32_t) { return 3; }   // DRIVE_FIXED
RH_REG(KERNEL32, GetDriveTypeA, GetDriveTypeA_)
static uint32_t GetDriveTypeW_(uint32_t) { return 3; }
RH_REG(KERNEL32, GetDriveTypeW, GetDriveTypeW_)
static uint32_t GetLogicalDrives_() { return 1u << 2; }   // C:
RH_REG(KERNEL32, GetLogicalDrives, GetLogicalDrives_)
static uint32_t GetVolumeInformationW_(uint32_t, uint32_t name, uint32_t nameCap, uint32_t serial, uint32_t maxLen,
                                       uint32_t flags, uint32_t fs, uint32_t fsCap) {
    if (name && nameCap) PutPath16(u"", name, nameCap);
    if (serial) *At<uint32_t>(serial) = 0x1234ABCD;
    if (maxLen) *At<uint32_t>(maxLen) = 255;
    if (flags) *At<uint32_t>(flags) = 0x3;   // FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES
    if (fs && fsCap) PutPath16(u"NTFS", fs, fsCap);
    return 1;
}
RH_REG(KERNEL32, GetVolumeInformationW, GetVolumeInformationW_)

// ---- pipes -------------------------------------------------------------------------------------
static uint32_t PeekNamedPipe_(uint32_t h, uint32_t buf, uint32_t n, uint32_t read, uint32_t avail, uint32_t left) {
    auto f = FileOf(h);
    if (!f || f->fd < 0) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    int ready = 0;
    ioctl(f->fd, FIONREAD, &ready);
    if (avail) *At<uint32_t>(avail) = static_cast<uint32_t>(ready);
    if (left) *At<uint32_t>(left) = 0;
    // (a peek's bytes cannot be had from a pipe without consuming them: none reported read)
    if (read) *At<uint32_t>(read) = 0;
    (void)buf, (void)n;
    return 1;
}
RH_REG(KERNEL32, PeekNamedPipe, PeekNamedPipe_)

// ---- the standard handles and the console --------------------------------------------------------
static uint32_t GetStdHandle_(uint32_t which) {
    int k = which == 0xFFFFFFF6u ? 0 : which == 0xFFFFFFF5u ? 1 : which == 0xFFFFFFF4u ? 2 : -1;
    if (k < 0) return kInvalidHandle;
    if (!g_std[k]) g_std[k] = NewHandle(StdFile(k));
    return g_std[k];
}
RH_REG(KERNEL32, GetStdHandle, GetStdHandle_)
static uint32_t SetStdHandle_(uint32_t which, uint32_t h) {
    int k = which == 0xFFFFFFF6u ? 0 : which == 0xFFFFFFF5u ? 1 : which == 0xFFFFFFF4u ? 2 : -1;
    if (k < 0) return 0;
    g_std[k] = h;
    return 1;
}
RH_REG(KERNEL32, SetStdHandle, SetStdHandle_)
static uint32_t SetHandleCount_(uint32_t n) { return n; }
RH_REG(KERNEL32, SetHandleCount, SetHandleCount_)
static uint32_t GetConsoleMode_(uint32_t, uint32_t) { return SetLastError(win::ERROR_INVALID_HANDLE), 0; }
RH_REG(KERNEL32, GetConsoleMode, GetConsoleMode_)
static uint32_t WriteConsoleW_(uint32_t, uint32_t buf, uint32_t n, uint32_t written, uint32_t) {
    Log("console: %s", Narrow(At<char16_t>(buf), static_cast<int>(n)).c_str());
    if (written) *At<uint32_t>(written) = n;
    return 1;
}
RH_REG(KERNEL32, WriteConsoleW, WriteConsoleW_)
static uint32_t SetConsoleCtrlHandler_(uint32_t, uint32_t) { return 1; }
RH_REG(KERNEL32, SetConsoleCtrlHandler, SetConsoleCtrlHandler_)
static uint32_t OutputDebugStringA_(uint32_t s) {
    std::string t = s ? At<char>(s) : "";
    while (!t.empty() && (t.back() == '\n' || t.back() == '\r')) t.pop_back();
    Log("debug: %s", t.c_str());
    return 0;
}
RH_REG(KERNEL32, OutputDebugStringA, OutputDebugStringA_)
