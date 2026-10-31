// advapi32: the registry, the runtime's own, in memory and empty but for what <game>/registry.reg
// seeds (a .reg file's subset: [HKEY_...\path] sections, "name"="string" and "name"=dword:hex
// values; the reference imports no RegSetValueEx, so nothing is ever written back), and the user.
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

void Seed() {
    static bool done = false;
    if (done) return;
    done = true;
    std::ifstream in(GameRoot() + "/registry.reg");
    std::string line, key;
    int n = 0;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.size() > 2 && line[0] == '[') {
            key = Lower(line.substr(1, line.size() - 2));
            g_keys[key];
            continue;
        }
        size_t eq = line.find("\"=");
        if (key.empty() || line.empty() || line[0] != '"' || eq == std::string::npos) continue;
        std::string name = Lower(line.substr(1, eq - 1)), v = line.substr(eq + 2);
        Value val;
        if (v.compare(0, 6, "dword:") == 0) {
            uint32_t d = static_cast<uint32_t>(strtoul(v.c_str() + 6, nullptr, 16));
            val = {4, std::string(reinterpret_cast<const char*>(&d), 4)};
        } else if (v.size() >= 2 && v[0] == '"') {
            val = {1, v.substr(1, v.size() - 2) + std::string(1, '\0')};
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
    std::string path = root;
    if (sub && *At<char>(sub)) path += "\\" + Lower(At<char>(sub));
    while (!path.empty() && path.back() == '\\') path.pop_back();
    bool existed = g_keys.count(path) != 0;
    g_keys[path];
    uint32_t h = g_nextKey += 4;
    g_open[h] = path;
    *At<uint32_t>(out) = h;
    if (disposition) *At<uint32_t>(disposition) = existed ? 2 : 1;   // REG_OPENED_EXISTING_KEY / CREATED_NEW_KEY
    return win::ERROR_SUCCESS;
}
RH_REG(ADVAPI32, RegCreateKeyExA, RegCreateKeyExA_)

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
    std::string prefix = RootName(hkey) + "\\";
    std::set<std::string> subs;
    for (auto& [p, k] : g_keys)
        if (p.compare(0, prefix.size(), prefix) == 0) subs.insert(p.substr(prefix.size(), p.find('\\', prefix.size()) - prefix.size()));
    if (index >= subs.size()) return win::ERROR_NO_MORE_ITEMS;
    auto it = subs.begin();
    std::advance(it, index);
    if (it->size() + 1 > U32(cap)) return win::ERROR_MORE_DATA;
    strcpy(At<char>(name), it->c_str());
    *At<uint32_t>(cap) = static_cast<uint32_t>(it->size());
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
