// The reference's memory: everything below 2 GB (Ghidra32.h's memory model).
//
// Inside an Android app the low 4 GB are partly ART's (its heap near 0x12c00000, the boot image near
// 0x70000000, wherever this boot put them). So at the library's load the runtime takes every range
// below 2 GB still free, PROT_NONE (address space only: no memory, no commit charge), and from then
// on hands it out itself: the reference's image, its heaps, VirtualAlloc, thread stacks, TEBs, the
// runtime's own structures the reference holds. ART keeps 2..4 GB for its own low allocations.
//
// Granularity: reservations 64 KB as Windows'; commits by the host's page (4 KB, or 16 KB on a
// 16 KB-page kernel: a 4 KB commit there makes its whole 16 KB page readable, inside the same 64 KB
// reservation, harmless). The bookkeeping is in 4 KB units, as Windows answers VirtualQuery.
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <map>
#include <mutex>
#include <vector>

#include "Runtime.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace rh {

namespace {

constexpr uint32_t kLowStart = 0x00010000;
constexpr uint64_t kLowEnd = 0x80000000;    // 2 GB: every address the reference holds sign-extends alike
constexpr uint32_t kGrain = 0x10000;
constexpr uint32_t kUnit = 0x1000;

constexpr uint32_t MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_DECOMMIT = 0x4000, MEM_RELEASE = 0x8000,
                   MEM_FREE = 0x10000, MEM_PRIVATE = 0x20000, MEM_RESET = 0x80000, MEM_IMAGE = 0x1000000;
constexpr uint32_t PAGE_NOACCESS = 1, PAGE_READWRITE = 4, PAGE_EXECUTE_READWRITE = 0x40;

size_t g_page = 4096;
std::mutex g_mem;
std::map<uint32_t, uint32_t> g_free;          // free reserved ranges: start -> size
uint64_t g_reserved = 0;

// what VirtualQuery reports: an allocation (a reservation and its committed units)
struct Allocation {
    uint32_t size;
    uint32_t protect;       // AllocationProtect
    uint32_t type;          // MEM_PRIVATE / MEM_IMAGE
    std::vector<uint8_t> committed;   // per 4 KB unit
};
std::map<uint32_t, Allocation> g_allocs;

uint32_t RoundUp(uint64_t v, uint64_t a) { return static_cast<uint32_t>((v + a - 1) & ~(a - 1)); }

void AddFree(uint32_t at, uint32_t size) {
    auto next = g_free.lower_bound(at);
    if (next != g_free.end() && at + size == next->first) {
        size += next->second;
        next = g_free.erase(next);
    }
    if (next != g_free.begin()) {
        auto prev = std::prev(next);
        if (prev->first + prev->second == at) {
            prev->second += size;
            return;
        }
    }
    g_free[at] = size;
}

// a free range of `size` at `align`, out of g_free (g_mem held)
uint32_t TakeFree(uint32_t size, uint32_t align) {
    for (auto it = g_free.begin(); it != g_free.end(); ++it) {
        uint32_t start = it->first, len = it->second;
        uint32_t at = RoundUp(start, align);
        if (at < start || static_cast<uint64_t>(at) + size > static_cast<uint64_t>(start) + len) continue;
        g_free.erase(it);
        if (at > start) g_free[start] = at - start;
        if (static_cast<uint64_t>(at) + size < static_cast<uint64_t>(start) + len)
            g_free[at + size] = start + len - (at + size);
        return at;
    }
    return 0;
}

bool TakeExact(uint32_t at, uint32_t size) {
    auto it = g_free.upper_bound(at);
    if (it == g_free.begin()) return false;
    --it;
    uint32_t start = it->first, len = it->second;
    if (static_cast<uint64_t>(at) + size > static_cast<uint64_t>(start) + len) return false;
    g_free.erase(it);
    if (at > start) g_free[start] = at - start;
    if (static_cast<uint64_t>(at) + size < static_cast<uint64_t>(start) + len)
        g_free[at + size] = start + len - (at + size);
    return true;
}

void Protect(uint32_t at, uint32_t size, int prot) {
    uintptr_t lo = at & ~(g_page - 1), hi = (static_cast<uintptr_t>(at) + size + g_page - 1) & ~(g_page - 1);
    if (mprotect(reinterpret_cast<void*>(lo), hi - lo, prot) != 0)
        Log("mprotect %lx+%lx %d failed (%d)", static_cast<unsigned long>(lo), static_cast<unsigned long>(hi - lo), prot,
            errno);
}

// the pages back to the kernel, address space kept (only whole host pages inside the range)
void Drop(uint32_t at, uint32_t size) {
    uintptr_t lo = (at + g_page - 1) & ~(g_page - 1), hi = (static_cast<uintptr_t>(at) + size) & ~(g_page - 1);
    if (hi <= lo) return;
    mmap(reinterpret_cast<void*>(lo), hi - lo, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0);
}

int Prot(uint32_t protect) {
    return (protect & 0xFF) == PAGE_NOACCESS || protect == 0 ? PROT_NONE : PROT_READ | PROT_WRITE;
}

void MarkCommitted(Allocation& a, uint32_t base, uint32_t at, uint32_t size, uint8_t v) {
    uint32_t first = (at - base) / kUnit, last = (at + size - base + kUnit - 1) / kUnit;
    for (uint32_t k = first; k < last && k < a.committed.size(); k++) a.committed[k] = v;
}

std::map<uint32_t, Allocation>::iterator AllocOf(uint32_t at) {
    auto it = g_allocs.upper_bound(at);
    if (it == g_allocs.begin()) return g_allocs.end();
    --it;
    return at - it->first < it->second.size ? it : g_allocs.end();
}

}  // namespace

size_t PageSize() { return g_page; }

void LowReserve() {
    static bool done = false;
    if (done) return;
    done = true;
    g_page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    // (the process's map as it is, into the log: what ART and the loader already hold below 4 GB)
    std::vector<std::pair<uint64_t, uint64_t>> used;
    {
        std::ifstream maps("/proc/self/maps");
        std::string line;
        Log("low memory: /proc/self/maps below 4 GB (page %zu):", g_page);
        while (std::getline(maps, line)) {
            unsigned long long lo = 0, hi = 0;
            if (sscanf(line.c_str(), "%llx-%llx", &lo, &hi) != 2) continue;
            used.emplace_back(lo, hi);
            if (lo < 0x100000000ull) Log("  %s", line.c_str());
        }
    }
    std::sort(used.begin(), used.end());
    uint64_t at = kLowStart;
    auto takeGap = [&](uint64_t lo, uint64_t hi) {
        lo = RoundUp(lo, kGrain);
        hi &= ~static_cast<uint64_t>(kGrain - 1);
        if (hi <= lo) return;
        void* want = reinterpret_cast<void*>(lo);
        void* got = mmap(want, hi - lo, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE,
                         -1, 0);
        if (got == MAP_FAILED) {
            Log("low memory: %llx-%llx not taken (%d)", static_cast<unsigned long long>(lo),
                static_cast<unsigned long long>(hi), errno);
            return;
        }
        if (got != want) {
            // (a kernel before 4.17 takes MAP_FIXED_NOREPLACE as a hint: somewhere else is no use)
            munmap(got, hi - lo);
            Log("low memory: %llx-%llx came back at %p, given up", static_cast<unsigned long long>(lo),
                static_cast<unsigned long long>(hi), got);
            return;
        }
        std::lock_guard<std::mutex> hold(g_mem);
        AddFree(static_cast<uint32_t>(lo), static_cast<uint32_t>(hi - lo));
        g_reserved += hi - lo;
    };
    for (auto& [lo, hi] : used) {
        if (lo >= kLowEnd) break;
        if (lo > at) takeGap(at, std::min<uint64_t>(lo, kLowEnd));
        at = std::max(at, hi);
    }
    if (at < kLowEnd) takeGap(at, kLowEnd);
    Log("low memory: %llu MB reserved below 2 GB in %zu ranges", static_cast<unsigned long long>(g_reserved >> 20),
        g_free.size());
    for (auto& [lo, len] : g_free) Log("  free %08x-%08x", lo, lo + len);
}

uint32_t LowAlloc(uint32_t size, uint32_t align) {
    size = RoundUp(size, std::max<size_t>(g_page, kUnit));
    std::lock_guard<std::mutex> hold(g_mem);
    uint32_t at = TakeFree(RoundUp(size, kGrain), std::max(align, kGrain));
    if (!at) {
        Log("low memory exhausted: %u bytes wanted", size);
        return 0;
    }
    Protect(at, size, PROT_READ | PROT_WRITE);
    Allocation a{RoundUp(size, kGrain), PAGE_READWRITE, MEM_PRIVATE, std::vector<uint8_t>(RoundUp(size, kGrain) / kUnit)};
    MarkCommitted(a, at, at, size, 1);
    g_allocs[at] = std::move(a);
    return at;
}

void LowFree(uint32_t at, uint32_t size) {
    std::lock_guard<std::mutex> hold(g_mem);
    auto it = g_allocs.find(at);
    if (it != g_allocs.end()) size = it->second.size, g_allocs.erase(it);
    size = RoundUp(size, kGrain);
    Drop(at, size);
    AddFree(at, size);
}

bool LowClaim(uint32_t at, uint32_t size) {
    std::lock_guard<std::mutex> hold(g_mem);
    uint32_t lo = at & ~(kGrain - 1), hi = RoundUp(static_cast<uint64_t>(at) + size, kGrain);
    if (!TakeExact(lo, hi - lo)) return false;
    Protect(lo, hi - lo, PROT_READ | PROT_WRITE);
    Allocation a{hi - lo, PAGE_EXECUTE_READWRITE, MEM_IMAGE, std::vector<uint8_t>((hi - lo) / kUnit, 1)};
    g_allocs[lo] = std::move(a);
    return true;
}

bool LowQuery(uint32_t address, Region* out) {
    std::lock_guard<std::mutex> hold(g_mem);
    uint32_t unit = address & ~(kUnit - 1);
    auto it = AllocOf(address);
    if (it == g_allocs.end()) {
        auto next = g_allocs.upper_bound(address);
        uint32_t end = next == g_allocs.end() ? static_cast<uint32_t>(kLowEnd) : next->first;
        *out = {unit, 0, 0, end - unit, MEM_FREE, PAGE_NOACCESS, 0};
        return address < kLowEnd;
    }
    const Allocation& a = it->second;
    uint32_t k = (unit - it->first) / kUnit, n = k;
    while (n < a.committed.size() && a.committed[n] == a.committed[k]) n++;
    out->base = unit;
    out->allocBase = it->first;
    out->allocProtect = a.protect;
    out->size = (n - k) * kUnit;
    out->state = a.committed[k] ? MEM_COMMIT : MEM_RESERVE;
    out->protect = a.committed[k] ? (a.type == MEM_IMAGE ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE) : 0;
    out->type = a.type;
    return true;
}

// ---- VirtualAlloc and VirtualFree, on the reservation ------------------------------------------
static uint32_t VirtualAlloc_(uint32_t addr, uint32_t size, uint32_t type, uint32_t protect) {
    if (size == 0) {
        SetLastError(win::ERROR_INVALID_PARAMETER);
        return 0;
    }
    std::lock_guard<std::mutex> hold(g_mem);
    if (type & MEM_RESET) return addr;   // (contents may go: kept, harmless)
    uint32_t base;
    if (type & MEM_RESERVE) {
        uint32_t len = RoundUp(static_cast<uint64_t>(addr & (kGrain - 1)) + size, kGrain);
        if (addr) {
            base = addr & ~(kGrain - 1);
            if (!TakeExact(base, len)) {
                SetLastError(win::ERROR_INVALID_PARAMETER);
                return 0;
            }
        } else {
            base = TakeFree(len, kGrain);
            if (!base) {
                Log("VirtualAlloc: low memory exhausted (%u bytes)", size);
                SetLastError(win::ERROR_NOT_ENOUGH_MEMORY);
                return 0;
            }
        }
        g_allocs[base] = Allocation{len, protect, MEM_PRIVATE, std::vector<uint8_t>(len / kUnit)};
        if (!(type & MEM_COMMIT)) return addr ? base : base;
        addr = addr ? addr : base;
    }
    if (type & MEM_COMMIT) {
        auto it = AllocOf(addr);
        if (it == g_allocs.end() || static_cast<uint64_t>(addr) + size > static_cast<uint64_t>(it->first) + it->second.size) {
            SetLastError(win::ERROR_INVALID_PARAMETER);
            return 0;
        }
        uint32_t lo = addr & ~(kUnit - 1), hi = RoundUp(static_cast<uint64_t>(addr) + size, kUnit);
        Protect(lo, hi - lo, Prot(protect));
        if (Prot(protect) != PROT_NONE) MarkCommitted(it->second, it->first, lo, hi - lo, 1);
        return lo;
    }
    SetLastError(win::ERROR_INVALID_PARAMETER);
    return 0;
}
RH_REG(KERNEL32, VirtualAlloc, VirtualAlloc_)

static uint32_t VirtualFree_(uint32_t addr, uint32_t size, uint32_t type) {
    std::lock_guard<std::mutex> hold(g_mem);
    auto it = AllocOf(addr);
    if (it == g_allocs.end()) {
        SetLastError(win::ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (type & MEM_RELEASE) {
        if (addr != it->first || size != 0) {
            SetLastError(win::ERROR_INVALID_PARAMETER);
            return 0;
        }
        uint32_t len = it->second.size;
        g_allocs.erase(it);
        Drop(addr, len);
        AddFree(addr, len);
        return 1;
    }
    if (type & MEM_DECOMMIT) {
        uint32_t lo = addr & ~(kUnit - 1);
        uint32_t hi = size ? RoundUp(static_cast<uint64_t>(addr) + size, kUnit) : it->first + it->second.size;
        MarkCommitted(it->second, it->first, lo, hi - lo, 0);
        // (zeroed as a recommit expects: the whole host pages dropped, a partial one cleared)
        uintptr_t plo = (lo + g_page - 1) & ~(g_page - 1), phi = hi & ~(g_page - 1);
        if (phi > plo) {
            Drop(static_cast<uint32_t>(plo), static_cast<uint32_t>(phi - plo));
            if (plo > lo) memset(At(lo), 0, plo - lo);
            if (hi > phi) memset(At(static_cast<uint32_t>(phi)), 0, hi - phi);
        } else {
            memset(At(lo), 0, hi - lo);
        }
        return 1;
    }
    SetLastError(win::ERROR_INVALID_PARAMETER);
    return 0;
}
RH_REG(KERNEL32, VirtualFree, VirtualFree_)

// ---- heaps -------------------------------------------------------------------------------------
// A segregated-fit heap: blocks up to 64 KB from size classes (16-byte steps to 512, then four
// classes per doubling), carved from 256 KB slabs, each class's freed blocks on a list of its own;
// larger blocks their own pages. Every block has a 16-byte header before it, so its size and heap
// are known (HeapSize, HeapReAlloc) and it is 16-aligned (x86 Windows' are 8: stricter is safe).
namespace {

constexpr uint32_t kMagic = 0x48455250;   // "PREH"
constexpr uint32_t kHeader = 16;
constexpr uint32_t kSmallMax = 0x10000;
constexpr uint32_t kSlab = 0x40000;
constexpr uint32_t kLarge = 0xFFFF;
constexpr uint32_t HEAP_NO_SERIALIZE = 1, HEAP_GENERATE_EXCEPTIONS = 4, HEAP_ZERO_MEMORY = 8,
                   HEAP_REALLOC_IN_PLACE_ONLY = 0x10;

struct BlockHeader {
    uint32_t size;      // what was asked
    uint32_t cls;       // its class, kLarge for its own pages
    uint32_t heap;      // the heap's handle
    uint32_t magic;
};
static_assert(sizeof(BlockHeader) == kHeader, "block header");

std::vector<uint32_t> g_classes;   // a class's block size, header included

void InitClasses() {
    if (!g_classes.empty()) return;
    for (uint32_t s = 32; s <= 512 + kHeader; s += 16) g_classes.push_back(s);
    for (uint32_t base = 512; base < kSmallMax; base *= 2)
        for (uint32_t q = 1; q <= 4; q++) g_classes.push_back(base + base * q / 4 + kHeader);
}

uint32_t ClassOf(uint32_t need) {
    auto it = std::lower_bound(g_classes.begin(), g_classes.end(), need);
    return it == g_classes.end() ? kLarge : static_cast<uint32_t>(it - g_classes.begin());
}

struct Heap {
    uint32_t handle = 0;
    std::mutex lock;
    std::vector<uint32_t> freeList;          // per class: the first free block (its header's address)
    std::vector<uint32_t> bump, bumpEnd;     // per class: the slab being carved
    std::vector<uint32_t> slabs;             // for HeapDestroy
    std::map<uint32_t, uint32_t> large;      // pages -> length
    uint64_t live = 0;

    Heap() : freeList(g_classes.size()), bump(g_classes.size()), bumpEnd(g_classes.size()) {}

    uint32_t Alloc(uint32_t size, uint32_t flags) {
        uint32_t need = size + kHeader;
        if (need < size) return 0;
        uint32_t cls = ClassOf(need);
        uint32_t block;
        bool fresh;
        if (cls == kLarge) {
            uint32_t len = RoundUp(need, std::max<size_t>(g_page, kUnit));
            block = LowAlloc(len);
            if (!block) return 0;
            std::lock_guard<std::mutex> hold(lock);
            large[block] = len;
            fresh = true;
        } else {
            std::lock_guard<std::mutex> hold(lock);
            if ((block = freeList[cls]) != 0) {
                freeList[cls] = *At<uint32_t>(block + kHeader);
                fresh = false;
            } else {
                uint32_t bs = g_classes[cls];
                if (bump[cls] + bs > bumpEnd[cls] || bump[cls] == 0) {
                    uint32_t slabLen = std::max(kSlab, bs * 4);
                    uint32_t slab = LowAlloc(slabLen);
                    if (!slab) return 0;
                    slabs.push_back(slab);
                    bump[cls] = slab;
                    bumpEnd[cls] = slab + slabLen;
                }
                block = bump[cls];
                bump[cls] += bs;
                fresh = true;
            }
            live += g_classes[cls];
        }
        auto h = At<BlockHeader>(block);
        *h = {size, cls, handle, kMagic};
        uint32_t p = block + kHeader;
        if ((flags & HEAP_ZERO_MEMORY) && !fresh) memset(At(p), 0, size);
        return p;
    }

    static BlockHeader* HeaderOf(uint32_t p) {
        if (p < kHeader) return nullptr;
        auto h = At<BlockHeader>(p - kHeader);
        return h->magic == kMagic ? h : nullptr;
    }

    uint32_t Capacity(const BlockHeader* h) const {
        return h->cls == kLarge ? 0 : g_classes[h->cls] - kHeader;
    }

    bool Free(uint32_t p) {
        BlockHeader* h = HeaderOf(p);
        if (!h) return false;
        uint32_t block = p - kHeader;
        h->magic = 0;
        if (h->cls == kLarge) {
            uint32_t len;
            {
                std::lock_guard<std::mutex> hold(lock);
                auto it = large.find(block);
                if (it == large.end()) return false;
                len = it->second;
                large.erase(it);
            }
            LowFree(block, len);
            return true;
        }
        std::lock_guard<std::mutex> hold(lock);
        *At<uint32_t>(p) = freeList[h->cls];
        freeList[h->cls] = block;
        live -= g_classes[h->cls];
        return true;
    }

    void Destroy() {
        for (uint32_t s : slabs) LowFree(s, 0);
        for (auto& [b, len] : large) LowFree(b, len);
        slabs.clear();
        large.clear();
    }
};

std::mutex g_heapsLock;
std::map<uint32_t, Heap*> g_heaps;
uint32_t g_processHeap = 0, g_runtimeHeap = 0;

Heap* HeapOf(uint32_t handle) {
    std::lock_guard<std::mutex> hold(g_heapsLock);
    auto it = g_heaps.find(handle);
    return it == g_heaps.end() ? nullptr : it->second;
}

uint32_t NewHeap() {
    InitClasses();
    // (the handle a low address of its own, as Windows' are: a 64 KB block nothing else uses)
    uint32_t handle = LowAlloc(kGrain);
    if (!handle) return 0;
    auto h = new Heap();
    h->handle = handle;
    std::lock_guard<std::mutex> hold(g_heapsLock);
    g_heaps[handle] = h;
    return handle;
}

void EnsureHeaps() {
    static std::once_flag once;
    std::call_once(once, [] {
        LowReserve();
        g_processHeap = NewHeap();
        g_runtimeHeap = NewHeap();
    });
}

}  // namespace

uint32_t ProcessHeap() {
    EnsureHeaps();
    return g_processHeap;
}

void* LowNew(size_t size) {
    EnsureHeaps();
    void* p = At(HeapOf(g_runtimeHeap)->Alloc(static_cast<uint32_t>(size), HEAP_ZERO_MEMORY));
    if (!p) {
        Log("LowNew: out of low memory (%zu bytes)", size);
        abort();
    }
    return p;
}

void LowDelete(void* p) {
    if (p) HeapOf(g_runtimeHeap)->Free(Low(p));
}

uint32_t HeapAllocIn(uint32_t heap, uint32_t flags, uint32_t size) {
    EnsureHeaps();
    Heap* h = HeapOf(heap);
    if (!h) h = HeapOf(g_processHeap);
    uint32_t p = h->Alloc(size, flags);
    if (!p) SetLastError(win::ERROR_NOT_ENOUGH_MEMORY);
    return p;
}

uint32_t HeapFreeIn(uint32_t heap, uint32_t flags, uint32_t p) {
    (void)flags;
    if (!p) return 1;
    BlockHeader* b = Heap::HeaderOf(p);
    Heap* h = b ? HeapOf(b->heap) : nullptr;
    if (!h) {
        LogOnce("HeapFree-bad", "HeapFree(%08x, %08x): not a block of a heap (heap %08x)", heap, p, b ? b->heap : 0);
        SetLastError(win::ERROR_INVALID_PARAMETER);
        return 0;
    }
    return h->Free(p) ? 1 : 0;
}

static uint32_t HeapCreate_(uint32_t, uint32_t, uint32_t) { return NewHeap(); }
RH_REG(KERNEL32, HeapCreate, HeapCreate_)

static uint32_t HeapDestroy_(uint32_t heap) {
    if (heap == g_processHeap) return 0;
    Heap* h;
    {
        std::lock_guard<std::mutex> hold(g_heapsLock);
        auto it = g_heaps.find(heap);
        if (it == g_heaps.end()) return 0;
        h = it->second;
        g_heaps.erase(it);
    }
    h->Destroy();
    delete h;
    LowFree(heap, 0);
    return 1;
}
RH_REG(KERNEL32, HeapDestroy, HeapDestroy_)

static uint32_t GetProcessHeap_() { return ProcessHeap(); }
RH_REG(KERNEL32, GetProcessHeap, GetProcessHeap_)

static uint32_t HeapAlloc_(uint32_t heap, uint32_t flags, uint32_t size) { return HeapAllocIn(heap, flags, size); }
RH_REG(KERNEL32, HeapAlloc, HeapAlloc_)

static uint32_t HeapFree_(uint32_t heap, uint32_t flags, uint32_t p) { return HeapFreeIn(heap, flags, p); }
RH_REG(KERNEL32, HeapFree, HeapFree_)

static uint32_t HeapSize_(uint32_t, uint32_t, uint32_t p) {
    BlockHeader* b = Heap::HeaderOf(p);
    return b ? b->size : 0xFFFFFFFFu;
}
RH_REG(KERNEL32, HeapSize, HeapSize_)

static uint32_t HeapReAlloc_(uint32_t heap, uint32_t flags, uint32_t p, uint32_t size) {
    if (!p) return HeapAllocIn(heap, flags, size);
    BlockHeader* b = Heap::HeaderOf(p);
    Heap* h = b ? HeapOf(b->heap) : nullptr;
    if (!h) {
        SetLastError(win::ERROR_INVALID_PARAMETER);
        return 0;
    }
    uint32_t old = b->size;
    // (in place where its block has the room)
    uint32_t cap = h->Capacity(b);
    if (b->cls == kLarge) {
        std::lock_guard<std::mutex> hold(h->lock);
        auto it = h->large.find(p - kHeader);
        cap = it == h->large.end() ? 0 : it->second - kHeader;
    }
    if (size <= cap) {
        if ((flags & HEAP_ZERO_MEMORY) && size > old) memset(At(p + old), 0, size - old);
        b->size = size;
        return p;
    }
    if (flags & HEAP_REALLOC_IN_PLACE_ONLY) {
        SetLastError(win::ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    uint32_t q = h->Alloc(size, flags & HEAP_ZERO_MEMORY);
    if (!q) {
        SetLastError(win::ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    memcpy(At(q), At(p), std::min(old, size));
    h->Free(p);
    return q;
}
RH_REG(KERNEL32, HeapReAlloc, HeapReAlloc_)

static uint32_t HeapSetInformation_(uint32_t, uint32_t, uint32_t, uint32_t) { return 1; }
RH_REG(KERNEL32, HeapSetInformation, HeapSetInformation_)

// HeapCompatibilityInformation: 2, the low-fragmentation heap, as Windows 7 answers
static uint32_t HeapQueryInformation_(uint32_t, uint32_t cls, uint32_t out, uint32_t len, uint32_t ret) {
    if (cls == 0 && out && len >= 4) {
        *At<uint32_t>(out) = 2;
        if (ret) *At<uint32_t>(ret) = 4;
        return 1;
    }
    SetLastError(win::ERROR_INVALID_PARAMETER);
    return 0;
}
RH_REG(KERNEL32, HeapQueryInformation, HeapQueryInformation_)

// GlobalAlloc: GMEM_MOVEABLE's handle is the block itself (GlobalLock hands it back as it is)
static uint32_t GlobalAlloc_(uint32_t flags, uint32_t size) {
    return HeapAllocIn(ProcessHeap(), (flags & 0x40) ? HEAP_ZERO_MEMORY : 0, size);
}
RH_REG(KERNEL32, GlobalAlloc, GlobalAlloc_)
static uint32_t GlobalLock_(uint32_t h) { return h; }
RH_REG(KERNEL32, GlobalLock, GlobalLock_)
static uint32_t GlobalUnlock_(uint32_t) { return 0; }
RH_REG(KERNEL32, GlobalUnlock, GlobalUnlock_)

// MEMORYSTATUSEX (64 bytes): the 2 GB the reference lives in as its virtual space, the device's RAM
static uint32_t GlobalMemoryStatusEx_(uint32_t out) {
    struct Status {
        uint32_t length, load;
        uint64_t totalPhys, availPhys, totalPage, availPage, totalVirtual, availVirtual, availExtended;
    };
    static_assert(sizeof(Status) == 64, "MEMORYSTATUSEX");
    auto s = At<Status>(out);
    long pages = sysconf(_SC_PHYS_PAGES), avail = sysconf(_SC_AVPHYS_PAGES);
    s->totalPhys = static_cast<uint64_t>(pages) * g_page;
    s->availPhys = static_cast<uint64_t>(avail) * g_page;
    s->load = s->totalPhys ? static_cast<uint32_t>(100 - s->availPhys * 100 / s->totalPhys) : 0;
    s->totalPage = s->totalPhys;
    s->availPage = s->availPhys;
    s->totalVirtual = 0x7FFE0000;
    uint64_t free = 0;
    {
        std::lock_guard<std::mutex> hold(g_mem);
        for (auto& [lo, len] : g_free) free += len;
    }
    s->availVirtual = free;
    s->availExtended = 0;
    return 1;
}
RH_REG(KERNEL32, GlobalMemoryStatusEx, GlobalMemoryStatusEx_)

// (CoTaskMem and the shell's IMalloc: the process heap)
static uint32_t CoTaskMemAlloc_(uint32_t n) { return HeapAllocIn(ProcessHeap(), 0, n); }
RH_REG(ole32, CoTaskMemAlloc, CoTaskMemAlloc_)
static uint32_t CoTaskMemFree_(uint32_t p) { return HeapFreeIn(ProcessHeap(), 0, p), 0; }
RH_REG(ole32, CoTaskMemFree, CoTaskMemFree_)

}  // namespace rh
