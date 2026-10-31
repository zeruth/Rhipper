// ws2_32: Winsock over BSD sockets. A SOCKET is a handle of the runtime's table over a descriptor;
// the structures are x86 Winsock's (fd_set's 4-byte sockets, WSADATA's order, addrinfo's and
// hostent's 4-byte pointers, built in the low heap); the constants are translated where Linux's
// differ (AF_INET6, SOL_SOCKET and its options, the ioctls, the errors).
//
// WSAAsyncSelect (the lobby connection's): a watcher thread polls the sockets registered and posts
// the window message Windows would, wParam the socket, lParam the event and its error. As Winsock,
// FD_READ is posted once and again only after a recv, FD_WRITE after connecting and again after a
// send that would block, FD_ACCEPT after an accept, FD_CONNECT and FD_CLOSE once.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <map>
#include <set>
#include <vector>

#include "Runtime.h"

namespace rh {

bool PostMessage32(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp);   // user32.cpp

namespace {

constexpr uint32_t FD_READ = 1, FD_WRITE = 2, FD_OOB = 4, FD_ACCEPT = 8, FD_CONNECT = 0x10, FD_CLOSE = 0x20;
constexpr uint32_t kSocketError = 0xFFFFFFFFu;

struct Socket : Object {
    int fd = -1;
    bool nonblocking = false, listening = false, connecting = false;
    // WSAAsyncSelect's registration and what may be posted next
    uint32_t hwnd = 0, msg = 0, events = 0;
    bool readArmed = true, writeArmed = false, acceptArmed = true, closed = false;
    const char* Kind() const override { return "socket"; }
    bool Close() override {
        if (fd >= 0) close(fd);
        fd = -1;
        return true;
    }
};

uint32_t WsaError(int e) {
    switch (e) {
        case EWOULDBLOCK: return 10035;
        case EINPROGRESS: return 10036;
        case EALREADY: return 10037;
        case ENOTSOCK: case EBADF: return 10038;
        case EDESTADDRREQ: return 10039;
        case EMSGSIZE: return 10040;
        case EPROTOTYPE: return 10041;
        case ENOPROTOOPT: return 10042;
        case EPROTONOSUPPORT: return 10043;
        case EOPNOTSUPP: return 10045;
        case EAFNOSUPPORT: return 10047;
        case EADDRINUSE: return 10048;
        case EADDRNOTAVAIL: return 10049;
        case ENETDOWN: return 10050;
        case ENETUNREACH: return 10051;
        case ECONNABORTED: return 10053;
        case ECONNRESET: case EPIPE: return 10054;
        case ENOBUFS: return 10055;
        case EISCONN: return 10056;
        case ENOTCONN: return 10057;
        case ETIMEDOUT: return 10060;
        case ECONNREFUSED: return 10061;
        case EHOSTUNREACH: return 10065;
        case EACCES: return 10013;
        case EFAULT: return 10014;
        case EINVAL: return 10022;
        case EMFILE: return 10024;
        default: return 10022;
    }
}
uint32_t Fail(int e) {
    SetLastError(WsaError(e));
    return kSocketError;
}

std::shared_ptr<Socket> SocketOf(uint32_t s) { return GetAs<Socket>(s); }

// sockaddr: the same layout, AF_INET6 23 on Windows and 10 here
int FamilyIn(uint16_t f) { return f == 23 ? AF_INET6 : f; }
uint16_t FamilyOut(int f) { return f == AF_INET6 ? 23 : static_cast<uint16_t>(f); }

struct Addr {
    sockaddr_storage ss{};
    socklen_t len = 0;
};
Addr AddrIn(uint32_t p, uint32_t len) {
    Addr a;
    if (!p) return a;
    a.len = std::min<socklen_t>(len, sizeof a.ss);
    memcpy(&a.ss, At(p), a.len);
    a.ss.ss_family = static_cast<sa_family_t>(FamilyIn(*At<uint16_t>(p)));
    return a;
}
void AddrOut(const sockaddr* sa, socklen_t len, uint32_t p, uint32_t plen) {
    if (!p) return;
    socklen_t room = plen ? U32(plen) : len;
    memcpy(At(p), sa, std::min(room, len));
    if (room >= 2) *At<uint16_t>(p) = FamilyOut(sa->sa_family);
    if (plen) *At<uint32_t>(plen) = len;
}

// ---- the WSAAsyncSelect watcher ----------------------------------------------------------------------
std::mutex g_asyncLock;
std::set<uint32_t> g_async;
int g_wake[2] = {-1, -1};

void Wake() {
    if (g_wake[1] >= 0) (void)!write(g_wake[1], "x", 1);
}

void Post(Socket& s, uint32_t handle, uint32_t event, uint32_t error) {
    if (!(s.events & event)) return;
    PostMessage32(s.hwnd, s.msg, handle, event | (error << 16));
}

void* Watcher(void*) {
    for (;;) {
        std::vector<pollfd> fds;
        std::vector<std::pair<uint32_t, std::shared_ptr<Socket>>> socks;
        {
            std::lock_guard<std::mutex> hold(g_asyncLock);
            fds.push_back({g_wake[0], POLLIN, 0});
            for (auto it = g_async.begin(); it != g_async.end();) {
                auto s = SocketOf(*it);
                if (!s || s->fd < 0 || s->closed || !s->events) {
                    it = g_async.erase(it);
                    continue;
                }
                short want = 0;
                if (s->connecting) want |= POLLOUT;
                else {
                    if ((s->readArmed && (s->events & (FD_READ | FD_CLOSE))) || (s->listening && s->acceptArmed)) want |= POLLIN;
                    if (s->writeArmed && (s->events & FD_WRITE)) want |= POLLOUT;
                }
                if (want) {
                    fds.push_back({s->fd, want, 0});
                    socks.emplace_back(*it, s);
                }
                ++it;
            }
        }
        if (poll(fds.data(), fds.size(), 1000) <= 0) continue;
        if (fds[0].revents) {
            char buf[64];
            (void)!read(g_wake[0], buf, sizeof buf);
        }
        std::lock_guard<std::mutex> hold(g_asyncLock);
        for (size_t k = 0; k < socks.size(); k++) {
            short r = fds[k + 1].revents;
            if (!r) continue;
            auto& [h, s] = socks[k];
            if (s->connecting && (r & (POLLOUT | POLLERR | POLLHUP))) {
                int err = 0;
                socklen_t l = sizeof err;
                getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &l);
                s->connecting = false;
                Post(*s, h, FD_CONNECT, err ? WsaError(err) : 0);
                if (err) {
                    s->closed = true;
                    continue;
                }
                s->writeArmed = true;
                continue;
            }
            if (s->listening) {
                if ((r & POLLIN) && s->acceptArmed) {
                    s->acceptArmed = false;
                    Post(*s, h, FD_ACCEPT, 0);
                }
                continue;
            }
            if (r & (POLLIN | POLLHUP | POLLERR)) {
                char c;
                ssize_t n = recv(s->fd, &c, 1, MSG_PEEK | MSG_DONTWAIT);
                if (n > 0 && s->readArmed) {
                    s->readArmed = false;
                    Post(*s, h, FD_READ, 0);
                } else if (n == 0 || (n < 0 && errno != EWOULDBLOCK && errno != EAGAIN)) {
                    // (the peer's end, after the data before it was read: FD_CLOSE once)
                    if (s->readArmed || n < 0) {
                        s->closed = true;
                        Post(*s, h, FD_CLOSE, n < 0 ? WsaError(errno) : 0);
                    }
                }
            }
            if ((r & POLLOUT) && s->writeArmed) {
                s->writeArmed = false;
                Post(*s, h, FD_WRITE, 0);
            }
        }
    }
    return nullptr;
}

void StartWatcher() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (pipe2(g_wake, O_CLOEXEC | O_NONBLOCK) != 0) return;
        pthread_t t;
        pthread_create(&t, nullptr, Watcher, nullptr);
        pthread_detach(t);
    });
}

void Rearm(Socket& s, bool read, bool write, bool accept) {
    if (!s.events) return;
    std::lock_guard<std::mutex> hold(g_asyncLock);
    s.readArmed = s.readArmed || read;
    s.writeArmed = s.writeArmed || write;
    s.acceptArmed = s.acceptArmed || accept;
    Wake();
}

#pragma pack(push, 2)
struct WsaData32 {
    uint16_t wVersion, wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    uint16_t iMaxSockets, iMaxUdpDg;
    uint16_t pad;
    uint32_t lpVendorInfo;
};
#pragma pack(pop)
static_assert(sizeof(WsaData32) == 400, "x86 WSADATA");

struct FdSet32 {
    uint32_t count;
    uint32_t fds[64];
};
struct AddrInfo32 {
    int32_t flags, family, socktype, protocol;
    uint32_t addrlen, canonname, addr, next;
};
struct HostEnt32 {
    uint32_t name, aliases;
    int16_t addrtype, length;
    uint32_t addr_list;
};
static_assert(sizeof(AddrInfo32) == 32 && sizeof(HostEnt32) == 16, "addrinfo, hostent, x86");

std::mutex g_aiLock;
std::set<uint32_t> g_aiLists;

// a thread's own low buffer: gethostbyname's and inet_ntoa's results live until its next call
uint8_t* ThreadBuffer() {
    static thread_local uint8_t* buf = nullptr;
    if (!buf) buf = static_cast<uint8_t*>(LowNew(2048));
    return buf;
}

}  // namespace
}  // namespace rh

using namespace rh;

extern "C" {

unsigned int gen_imp_WSAStartup(uint32_t version, uint32_t out) {
    if (out) {
        auto o = At<WsaData32>(out);
        memset(o, 0, sizeof *o);
        uint16_t v = static_cast<uint16_t>(version);
        o->wVersion = (v & 0xFF) > 2 || ((v & 0xFF) == 2 && (v >> 8) >= 2) ? 0x0202 : v;
        o->wHighVersion = 0x0202;
        strcpy(o->szDescription, "WinSock 2.0");
        strcpy(o->szSystemStatus, "Running");
    }
    return 0;
}

unsigned int gen_imp_select(uint32_t, uint32_t rd, uint32_t wr, uint32_t ex, uint32_t timeout) {
    std::vector<pollfd> fds;
    std::vector<uint32_t> socks;
    std::vector<int> which;   // (bit 0 read, 1 write, 2 except)
    auto add = [&](uint32_t set, short ev, int bit) {
        if (!set) return;
        auto s = At<FdSet32>(set);
        for (uint32_t k = 0; k < s->count && k < 64; k++) {
            auto sock = SocketOf(s->fds[k]);
            if (!sock || sock->fd < 0) continue;
            fds.push_back({sock->fd, ev, 0});
            socks.push_back(s->fds[k]);
            which.push_back(bit);
        }
    };
    add(rd, POLLIN, 0);
    add(wr, POLLOUT, 1);
    add(ex, POLLPRI, 2);
    int ms = timeout ? static_cast<int>(*At<int32_t>(timeout) * 1000 + *At<int32_t>(timeout + 4) / 1000) : -1;
    int n = poll(fds.data(), fds.size(), ms);
    if (n < 0) return Fail(errno);
    FdSet32* sets[3] = {rd ? At<FdSet32>(rd) : nullptr, wr ? At<FdSet32>(wr) : nullptr, ex ? At<FdSet32>(ex) : nullptr};
    for (auto* s : sets)
        if (s) s->count = 0;
    uint32_t total = 0;
    for (size_t k = 0; k < fds.size(); k++) {
        short r = fds[k].revents;
        bool hit = which[k] == 0 ? (r & (POLLIN | POLLHUP | POLLERR)) != 0
                 : which[k] == 1 ? (r & (POLLOUT | POLLERR)) != 0 : (r & (POLLPRI | POLLERR)) != 0;
        if (!hit) continue;
        FdSet32* s = sets[which[k]];
        s->fds[s->count++] = socks[k];
        total++;
    }
    return total;
}

unsigned int gen_imp___WSAFDIsSet(uint32_t sock, uint32_t set) {
    if (!set) return 0;
    auto s = At<FdSet32>(set);
    for (uint32_t k = 0; k < s->count && k < 64; k++)
        if (s->fds[k] == sock) return 1;
    return 0;
}

unsigned int gen_imp_getaddrinfo(uintptr_t node, uintptr_t service, uint32_t hints, uint32_t res) {
    addrinfo h = {}, *ph = nullptr;
    if (hints) {
        auto s = At<AddrInfo32>(hints);
        h.ai_flags = s->flags & 0x7;   // (AI_PASSIVE, CANONNAME, NUMERICHOST: the same bits)
        h.ai_family = FamilyIn(static_cast<uint16_t>(s->family));
        h.ai_socktype = s->socktype;
        h.ai_protocol = s->protocol;
        ph = &h;
    }
    addrinfo* out = nullptr;
    if (res) *At<uint32_t>(res) = 0;
    int r = getaddrinfo(Str(node), Str(service), ph, &out);
    if (r != 0) {
        uint32_t e = r == EAI_NONAME ? 11001 : r == EAI_AGAIN ? 11002 : r == EAI_FAIL ? 11003 : 11004;
        Log("getaddrinfo(%s): %s", Str(node) ? Str(node) : "-", gai_strerror(r));
        SetLastError(e);
        return e;
    }
    // (the x86 list in one block: the nodes, then each address, then each canonical name)
    size_t n = 0, bytes = 0;
    for (addrinfo* p = out; p; p = p->ai_next) {
        n++;
        bytes += sizeof(AddrInfo32) + ((p->ai_addrlen + 7) & ~7u) + (p->ai_canonname ? strlen(p->ai_canonname) + 1 : 0);
    }
    uint32_t block = HeapAllocIn(ProcessHeap(), 8, static_cast<uint32_t>(bytes + 8));
    uint32_t extra = block + static_cast<uint32_t>(n * sizeof(AddrInfo32));
    size_t k = 0;
    for (addrinfo* p = out; p; p = p->ai_next, k++) {
        AddrInfo32& d = At<AddrInfo32>(block)[k];
        d.flags = p->ai_flags;
        d.family = FamilyOut(p->ai_family);
        d.socktype = p->ai_socktype;
        d.protocol = p->ai_protocol;
        d.addrlen = p->ai_addrlen;
        d.addr = extra;
        memcpy(At(extra), p->ai_addr, p->ai_addrlen);
        *At<uint16_t>(extra) = FamilyOut(p->ai_addr->sa_family);
        extra += (p->ai_addrlen + 7) & ~7u;
        if (p->ai_canonname) {
            d.canonname = extra;
            strcpy(At<char>(extra), p->ai_canonname);
            extra += static_cast<uint32_t>(strlen(p->ai_canonname) + 1);
        }
        d.next = k + 1 < n ? block + static_cast<uint32_t>((k + 1) * sizeof(AddrInfo32)) : 0;
    }
    freeaddrinfo(out);
    {
        std::lock_guard<std::mutex> hold(g_aiLock);
        g_aiLists.insert(block);
    }
    if (res) *At<uint32_t>(res) = block;
    return 0;
}

unsigned int gen_imp_freeaddrinfo(uint32_t list) {
    std::lock_guard<std::mutex> hold(g_aiLock);
    if (g_aiLists.erase(list)) HeapFreeIn(ProcessHeap(), 0, list);
    return 0;
}

unsigned int gen_imp_gethostbyname(uintptr_t name) {
    addrinfo h = {}, *out = nullptr;
    h.ai_family = AF_INET;
    h.ai_socktype = SOCK_STREAM;
    h.ai_flags = AI_CANONNAME;
    if (getaddrinfo(Str(name), nullptr, &h, &out) != 0 || !out) {
        SetLastError(11001);   // WSAHOST_NOT_FOUND
        return 0;
    }
    uint8_t* b = ThreadBuffer();
    auto e = reinterpret_cast<HostEnt32*>(b);
    auto addrs = reinterpret_cast<uint32_t*>(b + 16);      // 16 address pointers
    auto ips = reinterpret_cast<uint32_t*>(b + 16 + 68);   // the addresses
    char* nm = reinterpret_cast<char*>(b + 16 + 68 + 64);
    int k = 0;
    for (addrinfo* p = out; p && k < 16; p = p->ai_next) {
        ips[k] = reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr.s_addr;
        addrs[k] = Low(&ips[k]);
        k++;
    }
    addrs[k] = 0;
    snprintf(nm, 256, "%s", out->ai_canonname ? out->ai_canonname : Str(name));
    *At<uint32_t>(Low(b) + 2040) = 0;   // (an empty alias list)
    *e = {Low(nm), Low(b) + 2040, 2, 4, Low(addrs)};
    freeaddrinfo(out);
    return Low(e);
}

}  // extern "C"

// ---- the sockets ------------------------------------------------------------------------------------
static uint32_t WSACleanup_() { return 0; }
RH_REG(WS2_32, WSACleanup, WSACleanup_)
static uint32_t WSAGetLastError_() { return GetLastError(); }
RH_REG(WS2_32, WSAGetLastError, WSAGetLastError_)

static uint32_t socket_(uint32_t af, uint32_t type, uint32_t proto) {
    int fd = socket(FamilyIn(static_cast<uint16_t>(af)), static_cast<int>(type) | SOCK_CLOEXEC, static_cast<int>(proto));
    if (fd < 0) return Fail(errno);
    auto s = std::make_shared<Socket>();
    s->fd = fd;
    return NewHandle(s);
}
RH_REG(WS2_32, socket, socket_)

static uint32_t closesocket_(uint32_t h) {
    if (!SocketOf(h)) return SetLastError(10038), kSocketError;
    CloseHandle32(h);
    Wake();
    return 0;
}
RH_REG(WS2_32, closesocket, closesocket_)

static uint32_t connect_(uint32_t h, uint32_t addr, uint32_t len) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    Addr a = AddrIn(addr, len);
    if (connect(s->fd, reinterpret_cast<sockaddr*>(&a.ss), a.len) == 0) {
        if (s->events) Rearm(*s, false, true, false);
        return 0;
    }
    int e = errno;
    if (e == EINPROGRESS && s->nonblocking) {
        std::lock_guard<std::mutex> hold(g_asyncLock);
        s->connecting = s->events != 0;
        Wake();
        e = EWOULDBLOCK;   // (Winsock's answer for a connect in progress)
    }
    return Fail(e);
}
RH_REG(WS2_32, connect, connect_)

static uint32_t bind_(uint32_t h, uint32_t addr, uint32_t len) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    Addr a = AddrIn(addr, len);
    return bind(s->fd, reinterpret_cast<sockaddr*>(&a.ss), a.len) == 0 ? 0 : Fail(errno);
}
RH_REG(WS2_32, bind, bind_)

static uint32_t listen_(uint32_t h, uint32_t backlog) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    if (listen(s->fd, static_cast<int>(backlog)) != 0) return Fail(errno);
    s->listening = true;
    Wake();
    return 0;
}
RH_REG(WS2_32, listen, listen_)

static uint32_t accept_(uint32_t h, uint32_t addr, uint32_t plen) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    sockaddr_storage ss;
    socklen_t len = sizeof ss;
    int fd = accept4(s->fd, reinterpret_cast<sockaddr*>(&ss), &len, SOCK_CLOEXEC);
    Rearm(*s, false, false, true);
    if (fd < 0) return Fail(errno);
    AddrOut(reinterpret_cast<sockaddr*>(&ss), len, addr, plen);
    auto n = std::make_shared<Socket>();
    n->fd = fd;
    // (an accepted socket takes its listener's WSAAsyncSelect, as Winsock's)
    if (s->events) {
        n->hwnd = s->hwnd, n->msg = s->msg, n->events = s->events, n->nonblocking = true, n->writeArmed = true;
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    }
    uint32_t nh = NewHandle(n);
    if (n->events) {
        std::lock_guard<std::mutex> hold(g_asyncLock);
        g_async.insert(nh);
        Wake();
    }
    return nh;
}
RH_REG(WS2_32, accept, accept_)

static uint32_t send_(uint32_t h, uint32_t buf, uint32_t len, uint32_t flags) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    ssize_t n = send(s->fd, At(buf), len, (flags & 1 ? MSG_OOB : 0) | MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) Rearm(*s, false, true, false);
        return Fail(errno);
    }
    return static_cast<uint32_t>(n);
}
RH_REG(WS2_32, send, send_)

static uint32_t sendto_(uint32_t h, uint32_t buf, uint32_t len, uint32_t flags, uint32_t to, uint32_t tolen) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    Addr a = AddrIn(to, tolen);
    ssize_t n = sendto(s->fd, At(buf), len, (flags & 1 ? MSG_OOB : 0) | MSG_NOSIGNAL,
                       to ? reinterpret_cast<sockaddr*>(&a.ss) : nullptr, to ? a.len : 0);
    if (n < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) Rearm(*s, false, true, false);
        return Fail(errno);
    }
    return static_cast<uint32_t>(n);
}
RH_REG(WS2_32, sendto, sendto_)

static uint32_t recv_(uint32_t h, uint32_t buf, uint32_t len, uint32_t flags) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    ssize_t n = recv(s->fd, At(buf), len, (flags & 1 ? MSG_OOB : 0) | (flags & 2 ? MSG_PEEK : 0));
    int e = errno;
    Rearm(*s, true, false, false);
    return n < 0 ? Fail(e) : static_cast<uint32_t>(n);
}
RH_REG(WS2_32, recv, recv_)

static uint32_t recvfrom_(uint32_t h, uint32_t buf, uint32_t len, uint32_t flags, uint32_t from, uint32_t plen) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    ssize_t n = recvfrom(s->fd, At(buf), len, (flags & 1 ? MSG_OOB : 0) | (flags & 2 ? MSG_PEEK : 0),
                         reinterpret_cast<sockaddr*>(&ss), &sl);
    int e = errno;
    Rearm(*s, true, false, false);
    if (n < 0) return Fail(e);
    AddrOut(reinterpret_cast<sockaddr*>(&ss), sl, from, plen);
    return static_cast<uint32_t>(n);
}
RH_REG(WS2_32, recvfrom, recvfrom_)

static uint32_t getsockname_(uint32_t h, uint32_t addr, uint32_t plen) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    sockaddr_storage ss;
    socklen_t len = sizeof ss;
    if (getsockname(s->fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) return Fail(errno);
    AddrOut(reinterpret_cast<sockaddr*>(&ss), len, addr, plen);
    return 0;
}
RH_REG(WS2_32, getsockname, getsockname_)
static uint32_t getpeername_(uint32_t h, uint32_t addr, uint32_t plen) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    sockaddr_storage ss;
    socklen_t len = sizeof ss;
    if (getpeername(s->fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) return Fail(errno);
    AddrOut(reinterpret_cast<sockaddr*>(&ss), len, addr, plen);
    return 0;
}
RH_REG(WS2_32, getpeername, getpeername_)

// options: Winsock's SOL_SOCKET 0xFFFF and its numbers to Linux's; the timeouts a DWORD of ms (a
// timeval here), SO_LINGER two u_shorts (two ints here)
namespace {
bool SockOpt(uint32_t level, uint32_t name, int* lv, int* nm) {
    if (level == 0xFFFF) {
        *lv = SOL_SOCKET;
        switch (name) {
            case 0x0004: *nm = SO_REUSEADDR; return true;
            case 0x0008: *nm = SO_KEEPALIVE; return true;
            case 0x0020: *nm = SO_BROADCAST; return true;
            case 0x0080: *nm = SO_LINGER; return true;
            case 0x0100: *nm = SO_OOBINLINE; return true;
            case 0x1001: *nm = SO_SNDBUF; return true;
            case 0x1002: *nm = SO_RCVBUF; return true;
            case 0x1005: *nm = SO_SNDTIMEO; return true;
            case 0x1006: *nm = SO_RCVTIMEO; return true;
            case 0x1007: *nm = SO_ERROR; return true;
            case 0x1008: *nm = SO_TYPE; return true;
            default: return false;
        }
    }
    *lv = static_cast<int>(level);
    if (level == IPPROTO_TCP) {
        *nm = name == 1 ? TCP_NODELAY : static_cast<int>(name);
        return name == 1;
    }
    if (level == IPPROTO_IP) {
        switch (name) {
            case 4: *nm = IP_TTL; return true;
            case 3: *nm = IP_TOS; return true;
            default: return false;
        }
    }
    return false;
}
}  // namespace

static uint32_t setsockopt_(uint32_t h, uint32_t level, uint32_t name, uint32_t val, uint32_t len) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    if (level == 0xFFFF && name == 0xFF7F) {   // SO_DONTLINGER
        linger l{0, 0};
        return setsockopt(s->fd, SOL_SOCKET, SO_LINGER, &l, sizeof l) == 0 ? 0 : Fail(errno);
    }
    int lv, nm;
    if (!SockOpt(level, name, &lv, &nm)) {
        LogOnce(("setsockopt " + std::to_string(level) + "/" + std::to_string(name)).c_str(),
                "setsockopt(level %#x, option %#x): not translated, ignored", level, name);
        return 0;
    }
    if (nm == SO_SNDTIMEO || nm == SO_RCVTIMEO) {
        uint32_t ms = U32(val);
        timeval tv{static_cast<time_t>(ms / 1000), static_cast<suseconds_t>((ms % 1000) * 1000)};
        return setsockopt(s->fd, lv, nm, &tv, sizeof tv) == 0 ? 0 : Fail(errno);
    }
    if (nm == SO_LINGER && lv == SOL_SOCKET) {
        linger l{*At<uint16_t>(val), *At<uint16_t>(val + 2)};
        return setsockopt(s->fd, lv, nm, &l, sizeof l) == 0 ? 0 : Fail(errno);
    }
    int v = len >= 4 ? *At<int32_t>(val) : len >= 1 ? *At<uint8_t>(val) : 0;
    return setsockopt(s->fd, lv, nm, &v, sizeof v) == 0 ? 0 : Fail(errno);
}
RH_REG(WS2_32, setsockopt, setsockopt_)

static uint32_t getsockopt_(uint32_t h, uint32_t level, uint32_t name, uint32_t val, uint32_t plen) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    int lv, nm;
    if (!SockOpt(level, name, &lv, &nm)) return SetLastError(10042), kSocketError;   // WSAENOPROTOOPT
    if (nm == SO_SNDTIMEO || nm == SO_RCVTIMEO) {
        timeval tv{};
        socklen_t l = sizeof tv;
        if (getsockopt(s->fd, lv, nm, &tv, &l) != 0) return Fail(errno);
        *At<uint32_t>(val) = static_cast<uint32_t>(tv.tv_sec * 1000 + tv.tv_usec / 1000);
        *At<uint32_t>(plen) = 4;
        return 0;
    }
    if (nm == SO_LINGER && lv == SOL_SOCKET) {
        linger l{};
        socklen_t ll = sizeof l;
        if (getsockopt(s->fd, lv, nm, &l, &ll) != 0) return Fail(errno);
        *At<uint16_t>(val) = static_cast<uint16_t>(l.l_onoff);
        *At<uint16_t>(val + 2) = static_cast<uint16_t>(l.l_linger);
        *At<uint32_t>(plen) = 4;
        return 0;
    }
    int v = 0;
    socklen_t l = sizeof v;
    if (getsockopt(s->fd, lv, nm, &v, &l) != 0) return Fail(errno);
    if (nm == SO_ERROR && lv == SOL_SOCKET && v) v = static_cast<int>(WsaError(v));
    *At<int32_t>(val) = v;
    *At<uint32_t>(plen) = 4;
    return 0;
}
RH_REG(WS2_32, getsockopt, getsockopt_)

// ioctlsocket: FIONBIO, FIONREAD, SIOCATMARK
static uint32_t ioctlsocket_(uint32_t h, uint32_t cmd, uint32_t arg) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    switch (cmd) {
        case 0x8004667E: {
            s->nonblocking = U32(arg) != 0;
            int f = fcntl(s->fd, F_GETFL);
            fcntl(s->fd, F_SETFL, s->nonblocking ? f | O_NONBLOCK : f & ~O_NONBLOCK);
            return 0;
        }
        case 0x4004667F: {
            int n = 0;
            if (ioctl(s->fd, FIONREAD, &n) != 0) return Fail(errno);
            *At<uint32_t>(arg) = static_cast<uint32_t>(n);
            return 0;
        }
        case 0x40047307: {
            int mark = 0;
            ioctl(s->fd, SIOCATMARK, &mark);
            *At<uint32_t>(arg) = mark;
            return 0;
        }
        default:
            return SetLastError(10022), kSocketError;
    }
}
RH_REG(WS2_32, ioctlsocket, ioctlsocket_)

// WSAIoctl: the reference's one use, SIO_UDP_CONNRESET (0x9800000C: no ICMP resets on a UDP socket,
// which an unconnected Linux socket never reports anyway); SIO_KEEPALIVE_VALS as the options
static uint32_t WSAIoctl_(uint32_t h, uint32_t code, uint32_t in, uint32_t inLen, uint32_t, uint32_t, uint32_t got,
                          uint32_t ov, uint32_t) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    if (got) *At<uint32_t>(got) = 0;
    if (ov) LogOnce("WSAIoctl-ov", "WSAIoctl: an overlapped call, done at once");
    if (code == 0x9800000C) return 0;
    if (code == 0x98000004 && in && inLen >= 12) {
        int on = U32(in) != 0, idle = static_cast<int>(U32(in + 4) / 1000), intvl = static_cast<int>(U32(in + 8) / 1000);
        setsockopt(s->fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
        if (idle > 0) setsockopt(s->fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
        if (intvl > 0) setsockopt(s->fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
        return 0;
    }
    Log("WSAIoctl(%#x): not supported", code);
    return SetLastError(10045), kSocketError;
}
RH_REG(WS2_32, WSAIoctl, WSAIoctl_)

// WSAAsyncSelect(socket, window, message, events): non-blocking from here, the watcher posting
static uint32_t WSAAsyncSelect_(uint32_t h, uint32_t hwnd, uint32_t msg, uint32_t events) {
    auto s = SocketOf(h);
    if (!s) return SetLastError(10038), kSocketError;
    StartWatcher();
    int f = fcntl(s->fd, F_GETFL);
    fcntl(s->fd, F_SETFL, f | O_NONBLOCK);
    std::lock_guard<std::mutex> hold(g_asyncLock);
    s->nonblocking = true;
    s->hwnd = hwnd, s->msg = msg, s->events = events;
    s->readArmed = s->acceptArmed = true;
    // (a connected socket can be written at once: FD_WRITE as Winsock posts it on registration)
    sockaddr_storage peer;
    socklen_t pl = sizeof peer;
    s->writeArmed = getpeername(s->fd, reinterpret_cast<sockaddr*>(&peer), &pl) == 0;
    if (events) g_async.insert(h);
    else g_async.erase(h);
    Wake();
    return 0;
}
RH_REG(WS2_32, WSAAsyncSelect, WSAAsyncSelect_)

static uint32_t gethostname_(uint32_t buf, uint32_t len) {
    const char* name = "ANDROID";
    if (strlen(name) + 1 > len) return SetLastError(10014), kSocketError;
    strcpy(At<char>(buf), name);
    return 0;
}
RH_REG(WS2_32, gethostname, gethostname_)
static uint32_t inet_addr_(uint32_t s) {
    in_addr a;
    return inet_aton(At<char>(s), &a) ? a.s_addr : 0xFFFFFFFFu;   // INADDR_NONE
}
RH_REG(WS2_32, inet_addr, inet_addr_)
static uint32_t inet_ntoa_(uint32_t addr) {
    char* out = reinterpret_cast<char*>(ThreadBuffer() + 1024);
    snprintf(out, 16, "%u.%u.%u.%u", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, addr >> 24);
    return Low(out);
}
RH_REG(WS2_32, inet_ntoa, inet_ntoa_)
static uint32_t htonl_(uint32_t v) { return htonl(v); }
RH_REG(WS2_32, htonl, htonl_)
static uint32_t ntohl_(uint32_t v) { return ntohl(v); }
RH_REG(WS2_32, ntohl, ntohl_)
static uint32_t htons_(uint32_t v) { return htons(static_cast<uint16_t>(v)); }
RH_REG(WS2_32, htons, htons_)
static uint32_t ntohs_(uint32_t v) { return ntohs(static_cast<uint16_t>(v)); }
RH_REG(WS2_32, ntohs, ntohs_)

// ---- iphlpapi's ping: no ICMP for an app here; every echo times out ----------------------------------
static uint32_t IcmpCreateFile_() {
    struct Icmp : Object {
        const char* Kind() const override { return "icmp"; }
    };
    return NewHandle(std::make_shared<Icmp>());
}
RH_REG(IPHLPAPI, IcmpCreateFile, IcmpCreateFile_)
static uint32_t IcmpCloseHandle_(uint32_t h) { return CloseHandle32(h) ? 1 : 0; }
RH_REG(IPHLPAPI, IcmpCloseHandle, IcmpCloseHandle_)
static uint32_t IcmpSendEcho_(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {
    LogOnce("IcmpSendEcho", "IcmpSendEcho: no ICMP here, every echo times out");
    SetLastError(11010);   // IP_REQ_TIMED_OUT
    return 0;
}
RH_REG(IPHLPAPI, IcmpSendEcho, IcmpSendEcho_)
