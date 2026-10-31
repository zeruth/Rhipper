// Low trampolines: a native function's 4-byte address. The port's code is a .so the Android linker
// put high; the reference holds code addresses in 4-byte slots (its import table, COM vtables, the
// callbacks it is given), so each such function is reached through an entry below 2 GB:
//
//     ldr x16, #8      ; 0x58000050
//     br  x16          ; 0xd61f0200
//     .quad target
//
// 16 bytes, 16-aligned. x16 is the intra-procedure-call scratch register AAPCS64 gives veneers.
//
// The entries are written through a second, writable mapping of the same memory (a memfd mapped
// twice: read-execute below 2 GB, read-write anywhere), so no page is ever writable and executable
// at once and an entry is callable the moment it is written, while other threads run the page's
// earlier entries. Where memfd is refused, read-write-execute anonymous pages instead (logged).
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <mutex>
#include <unordered_map>

#include "Runtime.h"

namespace rh {

namespace {

constexpr uint32_t kLdrX16 = 0x58000050u, kBrX16 = 0xd61f0200u;

struct Arena {
    uint32_t lo = 0, size = 0, used = 0;
    uint8_t* rw = nullptr;     // the writable view (== the low one where memfd was refused)

    // the arena at `at` (the range already claimed from the reservation, LowMem.cpp)
    bool Map(uint32_t at, uint32_t len) {
        int fd = static_cast<int>(syscall(__NR_memfd_create, "rhipper-islands", 0u));
        if (fd >= 0 && ftruncate(fd, len) == 0) {
            void* x = mmap(At(at), len, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fd, 0);
            void* w = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            close(fd);
            if (x != MAP_FAILED && w != MAP_FAILED) {
                lo = at, size = len, used = 0, rw = static_cast<uint8_t*>(w);
                return true;
            }
            Log("islands: the memfd's double mapping failed (%d)", errno);
        } else if (fd >= 0) {
            close(fd);
        }
        if (mprotect(At(at), len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            Log("islands: no executable memory below 2 GB (%d): the reference cannot call the port", errno);
            return false;
        }
        Log("islands: read-write-execute pages at %08x (no memfd)", at);
        lo = at, size = len, used = 0, rw = At<uint8_t>(at);
        return true;
    }

    uint32_t Add(const void* fn) {
        if (used + 16 > size) return 0;
        uint8_t* w = rw + used;
        uint32_t words[2] = {kLdrX16, kBrX16};
        uint64_t target = reinterpret_cast<uint64_t>(fn);
        memcpy(w, words, 8);
        memcpy(w + 8, &target, 8);
        uint32_t at = lo + used;
        used += 16;
        __builtin___clear_cache(At<char>(at), At<char>(at + 16));
        return at;
    }
};

std::mutex g_lock;
Arena g_general;            // Island(): anywhere below 2 GB
Arena g_near;               // IslandNear(): within a branch of the image
std::unordered_map<const void*, uint32_t> g_made;

}  // namespace

uint32_t Island(const void* fn) {
    // (the port's .so is loaded below 2 GB by its boot library, android_jni.c: its functions are
    // 4-byte addresses already. An island only for one above, a system library's)
    if (reinterpret_cast<uintptr_t>(fn) < 0x80000000u) return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(fn));
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = g_made.find(fn);
    if (it != g_made.end()) return it->second;
    uint32_t at = g_general.Add(fn);
    if (!at) {
        constexpr uint32_t kLen = 0x100000;   // 65,536 entries a megabyte
        uint32_t region = LowAlloc(kLen);
        if (!region || !g_general.Map(region, kLen)) return 0;
        at = g_general.Add(fn);
    }
    g_made[fn] = at;
    return at;
}

void IslandsNearImage(uint32_t imageEnd, uint32_t count) {
    std::lock_guard<std::mutex> hold(g_lock);
    uint32_t len = (count * 16 + 0xFFFF) & ~0xFFFFu;
    uint32_t at = (imageEnd + 0xFFFF) & ~0xFFFFu;
    // (right after the image, or the first 64 KB that is free within the next 64 MB)
    for (uint32_t tries = 0; tries < 1024; tries++, at += 0x10000) {
        if (LowClaim(at, len)) {
            g_near.Map(at, len);
            Log("islands: %u entries at %08x-%08x", count, at, at + len);
            return;
        }
    }
    Log("islands: nothing free within 64 MB after the image (%08x)", imageEnd);
}

uint32_t IslandNear(const void* fn) {
    std::lock_guard<std::mutex> hold(g_lock);
    return g_near.Add(fn);
}

}  // namespace rh
