// Windows paths as the host's files. The game directory (rhipper_host_run's cwd) stands for the root
// of every drive: `C:\foo\Bar.dat`, `D:\foo\bar.dat` and `\foo\bar.dat` are all <game>/foo/bar.dat.
// Separators either way; `.` and `..` folded; each component looked up as it is and, where that
// is missing, without regard to case (the reference was written for a case-insensitive file system
// and its data is named as the installer wrote it). The working directory is the reference's own,
// a Windows path, `C:\` at the start.
#include <dirent.h>
#include <errno.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mutex>
#include <vector>

#include "Runtime.h"

namespace rh {

namespace {
std::mutex g_pathLock;
std::string g_root = "/";
std::u16string g_cwd = u"C:\\";

std::vector<std::string> Split(const std::string& p) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : p) {
        if (c == '\\' || c == '/') {
            if (!cur.empty()) parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    return parts;
}

// the absolute Windows path's components below the drive root
std::vector<std::string> Components(std::string p) {
    if (p.compare(0, 4, "\\\\?\\") == 0 || p.compare(0, 4, "\\\\.\\") == 0) p = p.substr(4);
    bool absolute = false;
    if (p.size() >= 2 && p[1] == ':') {
        p = p.substr(2);
        absolute = !p.empty() && (p[0] == '\\' || p[0] == '/');
        if (!absolute) p = "\\" + p;   // ("C:foo": relative to the drive's directory, the root here)
        absolute = true;
    } else if (!p.empty() && (p[0] == '\\' || p[0] == '/')) {
        absolute = true;
    }
    std::vector<std::string> in = absolute ? Split(p) : Split(Narrow(g_cwd.c_str()).substr(2) + "\\" + p), out;
    for (auto& c : in) {
        if (c == ".") continue;
        if (c == "..") {
            if (!out.empty()) out.pop_back();
            continue;
        }
        // (Windows drops trailing dots and spaces from a name)
        while (!c.empty() && (c.back() == '.' || c.back() == ' ')) c.pop_back();
        if (!c.empty()) out.push_back(c);
    }
    return out;
}

bool Exists(const std::string& p) {
    struct stat st;
    return lstat(p.c_str(), &st) == 0;
}

// a component in `dir` as the directory spells it, any case; empty for none
std::string FindNoCase(const std::string& dir, const std::string& name) {
    DIR* d = opendir(dir.c_str());
    if (!d) return "";
    std::string found;
    while (dirent* e = readdir(d)) {
        if (strcasecmp(e->d_name, name.c_str()) == 0) {
            found = e->d_name;
            break;
        }
    }
    closedir(d);
    return found;
}
}  // namespace

void SetGameRoot(const std::string& dir) {
    std::lock_guard<std::mutex> hold(g_pathLock);
    g_root = dir;
    while (g_root.size() > 1 && g_root.back() == '/') g_root.pop_back();
}
const std::string& GameRoot() { return g_root; }

std::string HostPath(const std::string& windows, bool forCreate) {
    (void)forCreate;   // (a create resolves the same way: the last component as given when missing)
    std::vector<std::string> parts;
    {
        std::lock_guard<std::mutex> hold(g_pathLock);
        parts = Components(windows);
    }
    std::string p = g_root;
    for (size_t k = 0; k < parts.size(); k++) {
        std::string next = p + "/" + parts[k];
        // (missing in every case: the rest as given, so a create makes it and an open fails with
        // ENOENT as it should)
        if (!Exists(next)) {
            std::string real = FindNoCase(p, parts[k]);
            if (!real.empty()) next = p + "/" + real;
        }
        p = next;
    }
    return p;
}

std::string HostPath16(const char16_t* windows, bool forCreate) { return HostPath(Narrow(windows), forCreate); }

std::u16string CurrentDirectory() {
    std::lock_guard<std::mutex> hold(g_pathLock);
    return g_cwd;
}

std::u16string FullPath(const std::u16string& p) {
    std::lock_guard<std::mutex> hold(g_pathLock);
    std::string out = "C:";
    for (auto& c : Components(Narrow(p.c_str()))) out += "\\" + c;
    if (out == "C:") out += "\\";
    // (a trailing separator kept, as Windows keeps it)
    if (!p.empty() && (p.back() == u'\\' || p.back() == u'/') && out.back() != '\\') out += "\\";
    return Widen(out.c_str());
}

bool SetCurrentDirectory16(const std::u16string& dir) {
    std::u16string full = FullPath(dir);
    struct stat st;
    if (stat(HostPath16(full.c_str()).c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    std::lock_guard<std::mutex> hold(g_pathLock);
    if (full.back() != u'\\') full += u'\\';
    g_cwd = full;
    return true;
}

uint32_t ErrnoToWin(int e) {
    switch (e) {
        case 0: return 0;
        case ENOENT: return win::ERROR_FILE_NOT_FOUND;
        case ENOTDIR: return win::ERROR_PATH_NOT_FOUND;
        case EACCES: case EPERM: case EROFS: return win::ERROR_ACCESS_DENIED;
        case EEXIST: return win::ERROR_ALREADY_EXISTS;
        case EBADF: return win::ERROR_INVALID_HANDLE;
        case ENOMEM: return win::ERROR_NOT_ENOUGH_MEMORY;
        case ENOSPC: return 112;   // ERROR_DISK_FULL
        case ENOTEMPTY: return win::ERROR_DIR_NOT_EMPTY;
        case EINVAL: return win::ERROR_INVALID_PARAMETER;
        case EISDIR: return win::ERROR_ACCESS_DENIED;
        default: return 31;   // ERROR_GEN_FAILURE
    }
}

}  // namespace rh
