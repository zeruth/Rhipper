// The reference's own resources, from its mapped image's resource directory: LoadStringA's string
// tables (user32.cpp) and version.dll's version information. Another file's version (a system
// DLL's, a driver's) has none here.
#include <strings.h>

#include <algorithm>

#include "Runtime.h"

namespace rh {

namespace {
struct ResDir {
    uint32_t characteristics, timestamp;
    uint16_t major, minor, named, ids;
};
struct ResEntry {
    uint32_t name, offset;
};
struct ResData {
    uint32_t rva, size, codepage, reserved;
};
static_assert(sizeof(ResDir) == 16 && sizeof(ResEntry) == 8 && sizeof(ResData) == 16, "resource directory");

uint32_t ResourceRoot(uint32_t* size) {
    uint32_t pe = gen_ref_base + U32(gen_ref_base + 0x3C);
    uint32_t rva = U32(pe + 0x18 + 0x60 + 2 * 8);   // IMAGE_DIRECTORY_ENTRY_RESOURCE
    *size = U32(pe + 0x18 + 0x60 + 2 * 8 + 4);
    return rva ? gen_ref_base + rva : 0;
}

// the entry with id `id` in a directory (or the first, id ~0)
uint32_t Find(uint32_t root, uint32_t dir, uint32_t id) {
    auto d = At<ResDir>(dir);
    auto e = At<ResEntry>(dir + sizeof(ResDir));
    for (uint32_t k = 0; k < static_cast<uint32_t>(d->named) + d->ids; k++) {
        if (id == ~0u || (!(e[k].name & 0x80000000u) && e[k].name == id)) return e[k].offset;
    }
    return 0xFFFFFFFFu;
}
}  // namespace

bool FindResource32(uint32_t type, uint32_t name, uint32_t* data, uint32_t* size) {
    uint32_t len = 0, root = ResourceRoot(&len);
    if (!root) return false;
    uint32_t t = Find(root, root, type);
    if (t == 0xFFFFFFFFu || !(t & 0x80000000u)) return false;
    uint32_t n = Find(root, root + (t & 0x7FFFFFFF), name);
    if (n == 0xFFFFFFFFu || !(n & 0x80000000u)) return false;
    uint32_t l = Find(root, root + (n & 0x7FFFFFFF), ~0u);   // (the first language)
    if (l == 0xFFFFFFFFu || (l & 0x80000000u)) return false;
    auto d = At<ResData>(root + l);
    *data = gen_ref_base + d->rva;
    *size = d->size;
    return true;
}

}  // namespace rh

using namespace rh;

// ---- version.dll: the reference's own VS_VERSIONINFO ----------------------------------------------
namespace {
bool IsReference(const char* path) {
    if (!path) return false;
    const char* file = path;
    for (const char* p = path; *p; p++)
        if (*p == '\\' || *p == '/') file = p + 1;
    const std::string& host = RefHostPath();
    std::string mine = host.substr(host.rfind('/') + 1);
    return strcasecmp(file, mine.c_str()) == 0;
}

// the block's wide tree: {wLength, wValueLength, wType, szKey, pad to 4, Value, pad to 4, children}
uint32_t Align4(uint32_t a) { return (a + 3) & ~3u; }
}  // namespace

// (twice the resource's size: the second half is where VerQueryValueA puts its ANSI strings, as
// Windows' own buffer holds them)
static uint32_t GetFileVersionInfoSizeA_(uint32_t path, uint32_t handle) {
    if (handle) *At<uint32_t>(handle) = 0;
    uint32_t data, size;
    if (!IsReference(path ? At<char>(path) : nullptr) || !FindResource32(16, 1, &data, &size)) {
        LogOnce(("version " + std::string(path ? At<char>(path) : "-")).c_str(), "GetFileVersionInfoSize(%s): none here",
                path ? At<char>(path) : "-");
        return SetLastError(1813 /* ERROR_RESOURCE_TYPE_NOT_FOUND */), 0;
    }
    return size * 2;
}
RH_REG(VERSION, GetFileVersionInfoSizeA, GetFileVersionInfoSizeA_)

static uint32_t GetFileVersionInfoA_(uint32_t path, uint32_t, uint32_t len, uint32_t out) {
    uint32_t data, size;
    if (!IsReference(path ? At<char>(path) : nullptr) || !FindResource32(16, 1, &data, &size))
        return SetLastError(1813), 0;
    memset(At(out), 0, len);
    memcpy(At(out), At(data), std::min(size, len));
    return 1;
}
RH_REG(VERSION, GetFileVersionInfoA, GetFileVersionInfoA_)

// VerQueryValueA(block, "\\" | "\\VarFileInfo\\Translation" | "\\StringFileInfo\\<lang>\\<name>", ...)
static uint32_t VerQueryValueA_(uint32_t block, uint32_t sub, uint32_t out, uint32_t plen) {
    std::string path = sub ? At<char>(sub) : "\\";
    uint32_t node = block, total = *At<uint16_t>(block);
    size_t at = 0;
    while (at < path.size()) {
        while (at < path.size() && path[at] == '\\') at++;
        if (at >= path.size()) break;
        size_t end = path.find('\\', at);
        std::string want = path.substr(at, end == std::string::npos ? std::string::npos : end - at);
        at = end == std::string::npos ? path.size() : end;
        // (the children: after the node's key and value)
        uint32_t keyEnd = node + 6 + static_cast<uint32_t>((Len16(At<char16_t>(node + 6)) + 1) * 2);
        uint16_t valueLen = *At<uint16_t>(node + 2), type = *At<uint16_t>(node + 4);
        uint32_t child = Align4(Align4(keyEnd) + (type == 1 ? valueLen * 2u : valueLen));
        uint32_t limit = node + *At<uint16_t>(node);
        bool found = false;
        while (child < limit && *At<uint16_t>(child)) {
            if (strcasecmp(Narrow(At<char16_t>(child + 6)).c_str(), want.c_str()) == 0) {
                node = child;
                found = true;
                break;
            }
            child = Align4(child + *At<uint16_t>(child));
        }
        if (!found) return 0;
    }
    uint32_t keyEnd = node + 6 + static_cast<uint32_t>((Len16(At<char16_t>(node + 6)) + 1) * 2);
    uint32_t value = Align4(keyEnd);
    uint16_t valueLen = *At<uint16_t>(node + 2), type = *At<uint16_t>(node + 4);
    if (type == 1) {
        // (a string: its ANSI copy in the buffer's second half, at the same offset)
        std::string a = AnsiOf(std::u16string(At<char16_t>(value), valueLen ? valueLen - 1 : 0));
        uint32_t copy = block + total + (value - block) / 2;
        memcpy(At(copy), a.c_str(), a.size() + 1);
        *At<uint32_t>(out) = copy;
        *At<uint32_t>(plen) = static_cast<uint32_t>(a.size() + 1);
    } else {
        *At<uint32_t>(out) = value;
        *At<uint32_t>(plen) = valueLen;
    }
    return valueLen ? 1 : 0;
}
RH_REG(VERSION, VerQueryValueA, VerQueryValueA_)
