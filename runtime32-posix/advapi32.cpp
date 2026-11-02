// advapi32: the registry, the runtime's own, in memory and empty but for what <game>/registry.reg
// seeds (a .reg file's subset: [HKEY_...\path] sections, "name"="string" and "name"=dword:hex
// values; the reference imports no RegSetValueEx, so nothing is ever written back), and the user.
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <map>
#include <set>

#include "Runtime.h"

using namespace rh;

namespace {

struct Value {
    uint32_t type;
    std::string data;
};
struct Key {
    std::map<std::string, Value> values;   // by lower-case name
    std::string spelled;                   // its own name's last component as first given (RegEnumKeyEx's)
};

std::mutex g_regLock;
std::map<std::string, Key> g_keys;          // by lower-case full path, "hkey_local_machine\software\..."
std::map<uint32_t, std::string> g_open;     // handle -> its key's path
uint32_t g_nextKey = 0x00060000;

std::string Lower(std::string s) {
    for (char& c : s) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string RootName(uint32_t h) {
    switch (h) {
        case 0x80000000: return "hkey_classes_root";
        case 0x80000001: return "hkey_current_user";
        case 0x80000002: return "hkey_local_machine";
        case 0x80000003: return "hkey_users";
        case 0x80000005: return "hkey_current_config";
        default: {
            auto it = g_open.find(h);
            return it == g_open.end() ? "" : it->second;
        }
    }
}

// a key and every key above it, each spelled as first given ("HKEY_LOCAL_MACHINE\Software\Foo")
void MakeKey(const std::string& path) {
    for (size_t at = 0;; at++) {
        at = path.find('\\', at);
        std::string part = path.substr(0, at);
        Key& k = g_keys[Lower(part)];
        if (k.spelled.empty()) k.spelled = part.substr(part.rfind('\\') + 1);
        if (at == std::string::npos) return;
    }
}

// a quoted .reg string ("...", its \\ and \" escapes) without its quotes; `end` past it
std::string Unquote(const std::string& s, size_t from, size_t* end) {
    std::string out;
    size_t k = from + 1;
    for (; k < s.size() && s[k] != '"'; k++) {
        if (s[k] == '\\' && k + 1 < s.size()) k++;
        out.push_back(s[k]);
    }
    if (end) *end = k + 1;
    return out;
}

// hex:12,ab,... (and hex(n): its type) as bytes
std::string HexBytes(const std::string& s) {
    std::string out;
    for (size_t k = 0; k < s.size();) {
        if (!isxdigit(static_cast<unsigned char>(s[k]))) {
            k++;
            continue;
        }
        char* end = nullptr;
        out.push_back(static_cast<char>(strtoul(s.c_str() + k, &end, 16)));
        k = static_cast<size_t>(end - s.c_str());
    }
    return out;
}

void Seed() {
    static bool done = false;
    if (done) return;
    done = true;
    std::ifstream in(GameRoot() + "/registry.reg");
    std::string raw, line, key;
    int n = 0;
    while (std::getline(in, raw)) {
        while (!raw.empty() && (raw.back() == '\r' || raw.back() == ' ')) raw.pop_back();
        // (a value continued on the next line: a trailing backslash)
        if (!raw.empty() && raw.back() == '\\' && (line + raw).find("=hex") != std::string::npos) {
            line += raw.substr(0, raw.size() - 1);
            continue;
        }
        line += raw;
        std::string l = line;
        line.clear();
        while (!l.empty() && (l[0] == ' ' || l[0] == '\t')) l.erase(0, 1);
        if (l.size() > 2 && l[0] == '[') {
            key = Lower(l.substr(1, l.size() - 2));
            MakeKey(l.substr(1, l.size() - 2));
            continue;
        }
        if (key.empty() || l.empty() || (l[0] != '"' && l[0] != '@')) continue;
        // (@ the key's default value, its name "")
        size_t after = 1;
        std::string name = l[0] == '@' ? "" : Lower(Unquote(l, 0, &after));
        if (after >= l.size() || l[after] != '=') continue;
        std::string v = l.substr(after + 1);
        Value val;
        if (v.compare(0, 6, "dword:") == 0) {
            uint32_t d = static_cast<uint32_t>(strtoul(v.c_str() + 6, nullptr, 16));
            val = {4, std::string(reinterpret_cast<const char*>(&d), 4)};
        } else if (!v.empty() && v[0] == '"') {
            val = {1, Unquote(v, 0, nullptr) + std::string(1, '\0')};
        } else if (v.compare(0, 4, "hex:") == 0) {
            val = {3, HexBytes(v.substr(4))};   // REG_BINARY
        } else if (v.compare(0, 4, "hex(") == 0 && v.find("):") != std::string::npos) {
            uint32_t type = static_cast<uint32_t>(strtoul(v.c_str() + 4, nullptr, 16));
            std::string bytes = HexBytes(v.substr(v.find("):") + 2));
            // (a .reg file's strings are UTF-16: REG_EXPAND_SZ 2 and REG_MULTI_SZ 7 as the A functions' ANSI)
            if (type == 2 || type == 7) bytes = AnsiOf(std::u16string(reinterpret_cast<const char16_t*>(bytes.data()), bytes.size() / 2));
            val = {type, bytes};
        } else {
            continue;
        }
        g_keys[key].values[name] = val;
        n++;
    }
    if (n) Log("registry: %d values from registry.reg", n);
}

}  // namespace

// RegCreateKeyExA(key, subkey, 0, class, options, sam, sa, result, disposition)
static uint32_t RegCreateKeyExA_(uint32_t hkey, uint32_t sub, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                                 uint32_t out, uint32_t disposition) {
    std::lock_guard<std::mutex> hold(g_regLock);
    Seed();
    std::string root = RootName(hkey);
    if (root.empty()) return win::ERROR_INVALID_HANDLE;
    std::string spelled = root;
    if (sub && *At<char>(sub)) spelled += "\\" + std::string(At<char>(sub));
    while (!spelled.empty() && spelled.back() == '\\') spelled.pop_back();
    std::string path = Lower(spelled);
    bool existed = g_keys.count(path) != 0;
    MakeKey(spelled);
    uint32_t h = g_nextKey += 4;
    g_open[h] = path;
    *At<uint32_t>(out) = h;
    if (disposition) *At<uint32_t>(disposition) = existed ? 2 : 1;   // REG_OPENED_EXISTING_KEY / CREATED_NEW_KEY
    return win::ERROR_SUCCESS;
}
RH_REG(ADVAPI32, RegCreateKeyExA, RegCreateKeyExA_)
// (and as the translation calls it directly: runtime32's Adapters.cpp makes it an adapter for x64)
extern "C" unsigned int gen_imp_RegCreateKeyExA(uint32_t key, uint32_t sub, uint32_t reserved, uint32_t cls,
                                                uint32_t opts, uint32_t sam, uint32_t sa, uint32_t out,
                                                uint32_t disposition) {
    return RegCreateKeyExA_(key, sub, reserved, cls, opts, sam, sa, out, disposition);
}

static uint32_t RegCloseKey_(uint32_t h) {
    std::lock_guard<std::mutex> hold(g_regLock);
    return g_open.erase(h) || (h & 0x80000000u) ? win::ERROR_SUCCESS : win::ERROR_INVALID_HANDLE;
}
RH_REG(ADVAPI32, RegCloseKey, RegCloseKey_)

// RegQueryValueExA(key, name, 0, type, data, size)
static uint32_t RegQueryValueExA_(uint32_t hkey, uint32_t name, uint32_t, uint32_t type, uint32_t data, uint32_t size) {
    std::lock_guard<std::mutex> hold(g_regLock);
    Seed();
    std::string path = RootName(hkey);
    if (path.empty()) return win::ERROR_INVALID_HANDLE;
    if (data && !size) return win::ERROR_INVALID_PARAMETER;
    auto k = g_keys.find(path);
    std::string n = name ? Lower(At<char>(name)) : "";
    if (k == g_keys.end() || !k->second.values.count(n)) {
        LogOnce(("reg " + path + "\\" + n).c_str(), "registry: %s\\%s: none", path.c_str(), n.c_str());
        return win::ERROR_FILE_NOT_FOUND;
    }
    const Value& v = k->second.values[n];
    if (type) *At<uint32_t>(type) = v.type;
    uint32_t need = static_cast<uint32_t>(v.data.size());
    if (size) {
        uint32_t room = U32(size);
        *At<uint32_t>(size) = need;
        if (data) {
            if (room < need) return win::ERROR_MORE_DATA;
            memcpy(At(data), v.data.data(), need);
        }
    }
    return win::ERROR_SUCCESS;
}
RH_REG(ADVAPI32, RegQueryValueExA, RegQueryValueExA_)

// RegEnumKeyExA(key, index, name, name size, 0, class, class size, time): its direct subkeys, sorted
static uint32_t RegEnumKeyExA_(uint32_t hkey, uint32_t index, uint32_t name, uint32_t cap, uint32_t, uint32_t cls,
                               uint32_t clsCap, uint32_t time) {
    std::lock_guard<std::mutex> hold(g_regLock);
    Seed();
    std::string root = RootName(hkey);
    if (root.empty()) return win::ERROR_INVALID_HANDLE;
    std::string prefix = root + "\\";
    std::set<std::string> subs;   // (lower-case paths of the direct subkeys, sorted as names)
    for (auto& [p, k] : g_keys)
        if (p.compare(0, prefix.size(), prefix) == 0) subs.insert(p.substr(0, p.find('\\', prefix.size())));
    if (index >= subs.size()) return win::ERROR_NO_MORE_ITEMS;
    auto it = subs.begin();
    std::advance(it, index);
    const std::string& spelled = g_keys[*it].spelled;
    std::string sub = spelled.empty() ? it->substr(prefix.size()) : spelled;
    if (sub.size() + 1 > U32(cap)) return win::ERROR_MORE_DATA;
    strcpy(At<char>(name), sub.c_str());
    *At<uint32_t>(cap) = static_cast<uint32_t>(sub.size());
    if (cls && clsCap && U32(clsCap)) *At<char>(cls) = 0, *At<uint32_t>(clsCap) = 0;
    if (time) memset(At(time), 0, 8);
    return win::ERROR_SUCCESS;
}
RH_REG(ADVAPI32, RegEnumKeyExA, RegEnumKeyExA_)

static uint32_t GetUserNameW_(uint32_t buf, uint32_t pcap) {
    static const char16_t name[] = u"Player";
    uint32_t need = 7;
    if (U32(pcap) < need) {
        *At<uint32_t>(pcap) = need;
        return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
    }
    memcpy(At(buf), name, sizeof name);
    *At<uint32_t>(pcap) = need;
    return 1;
}
RH_REG(ADVAPI32, GetUserNameW, GetUserNameW_)
