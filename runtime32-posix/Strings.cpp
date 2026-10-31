// Strings: UTF-16 (the reference's WCHAR, 2 bytes; the runtime's char16_t), its code pages (the ANSI
// one 1252 unless <ENV>_ACP says 65001), and kernel32's and user32's string and locale functions.
// The locale is en-US's (0x409): what a Western Windows 7 answers.
#include <time.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "Runtime.h"

namespace rh {

namespace {
const char16_t k1252[32] = {0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160,
                            0x2039, 0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
                            0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178};

uint32_t Acp() {
    static uint32_t acp = [] {
        std::string v = Env("ACP");
        return v == "65001" ? 65001u : 1252u;
    }();
    return acp;
}

uint32_t Resolve(uint32_t cp) {
    if (cp == 0 || cp == 3 /* CP_THREAD_ACP */) return Acp();
    if (cp == 1 /* CP_OEMCP */ || cp == 437 || cp == 850 || cp == 28591) return 1252;
    if (cp == 20127) return 1252;
    return cp;
}

// a code page's bytes as UTF-16: 1252 (and its stand-ins) or UTF-8
std::u16string Decode(uint32_t cp, const unsigned char* s, size_t n) {
    std::u16string out;
    if (Resolve(cp) == 65001) {
        for (size_t k = 0; k < n;) {
            uint32_t c = s[k], len = c < 0x80 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
            if (k + len > n || (c >= 0x80 && c < 0xC0)) {
                out.push_back(0xFFFD);
                k++;
                continue;
            }
            uint32_t u = len == 1 ? c : len == 2 ? c & 0x1F : len == 3 ? c & 0x0F : c & 0x07;
            for (uint32_t i = 1; i < len; i++) u = (u << 6) | (s[k + i] & 0x3F);
            k += len;
            if (u >= 0x10000) {
                u -= 0x10000;
                out.push_back(static_cast<char16_t>(0xD800 + (u >> 10)));
                out.push_back(static_cast<char16_t>(0xDC00 + (u & 0x3FF)));
            } else {
                out.push_back(static_cast<char16_t>(u));
            }
        }
        return out;
    }
    for (size_t k = 0; k < n; k++)
        out.push_back(s[k] >= 0x80 && s[k] < 0xA0 ? k1252[s[k] - 0x80] : static_cast<char16_t>(s[k]));
    return out;
}

std::string Encode(uint32_t cp, const char16_t* s, size_t n, bool* lossy) {
    std::string out;
    if (Resolve(cp) == 65001) {
        for (size_t k = 0; k < n; k++) {
            uint32_t u = s[k];
            if (u >= 0xD800 && u < 0xDC00 && k + 1 < n && s[k + 1] >= 0xDC00 && s[k + 1] < 0xE000)
                u = 0x10000 + ((u - 0xD800) << 10) + (s[++k] - 0xDC00);
            if (u < 0x80) {
                out.push_back(static_cast<char>(u));
            } else if (u < 0x800) {
                out.push_back(static_cast<char>(0xC0 | (u >> 6)));
                out.push_back(static_cast<char>(0x80 | (u & 0x3F)));
            } else if (u < 0x10000) {
                out.push_back(static_cast<char>(0xE0 | (u >> 12)));
                out.push_back(static_cast<char>(0x80 | ((u >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (u & 0x3F)));
            } else {
                out.push_back(static_cast<char>(0xF0 | (u >> 18)));
                out.push_back(static_cast<char>(0x80 | ((u >> 12) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | ((u >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (u & 0x3F)));
            }
        }
        return out;
    }
    for (size_t k = 0; k < n; k++) {
        char16_t c = s[k];
        if (c < 0x80 || (c >= 0xA0 && c < 0x100)) {
            out.push_back(static_cast<char>(c));
            continue;
        }
        int found = -1;
        for (int i = 0; i < 32; i++)
            if (k1252[i] == c) found = i;
        if (found >= 0) {
            out.push_back(static_cast<char>(0x80 + found));
        } else {
            out.push_back('?');
            if (lossy) *lossy = true;
        }
    }
    return out;
}
}  // namespace

size_t Len16(const char16_t* s) {
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}
std::string Narrow(const char16_t* s, int n) {
    if (!s) return "";
    return Encode(65001, s, n < 0 ? Len16(s) : static_cast<size_t>(n), nullptr);
}
std::u16string Widen(const char* s, int n) {
    if (!s) return u"";
    return Decode(65001, reinterpret_cast<const unsigned char*>(s), n < 0 ? strlen(s) : static_cast<size_t>(n));
}
std::u16string Ansi16(const char* s, int n) {
    if (!s) return u"";
    return Decode(0, reinterpret_cast<const unsigned char*>(s), n < 0 ? strlen(s) : static_cast<size_t>(n));
}
std::string AnsiOf(const std::u16string& s) { return Encode(0, s.data(), s.size(), nullptr); }
uint32_t AnsiCodePage() { return Acp(); }

std::string HexGuid(uint32_t g) {
    if (!g) return "{null}";
    char b[64];
    const uint8_t* d = At<uint8_t>(g + 8);
    snprintf(b, sizeof b, "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", U32(g), *At<uint16_t>(g + 4),
             *At<uint16_t>(g + 6), d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
    return b;
}

char16_t Upper16(char16_t c) {
    if (c < 0x80) return static_cast<char16_t>(toupper(c));
    if ((c >= 0xE0 && c <= 0xFE && c != 0xF7)) return c - 0x20;
    if (c >= 0x430 && c <= 0x44F) return c - 0x20;   // Cyrillic
    if (c >= 0x3B1 && c <= 0x3C9 && c != 0x3C2) return c - 0x20;   // Greek
    if (c >= 0x100 && c <= 0x17F && (c & 1)) return c - 1;   // Latin Extended-A pairs (approximately)
    if (c >= 0xFF41 && c <= 0xFF5A) return c - 0x20;   // fullwidth
    return c;
}
char16_t Lower16(char16_t c) {
    if (c < 0x80) return static_cast<char16_t>(tolower(c));
    if ((c >= 0xC0 && c <= 0xDE && c != 0xD7)) return c + 0x20;
    if (c >= 0x410 && c <= 0x42F) return c + 0x20;
    if (c >= 0x391 && c <= 0x3A9) return c + 0x20;
    if (c >= 0x100 && c <= 0x17F && !(c & 1)) return c + 1;
    if (c >= 0xFF21 && c <= 0xFF3A) return c + 0x20;
    return c;
}

}  // namespace rh

using namespace rh;

// ---- code pages --------------------------------------------------------------------------------
static uint32_t MultiByteToWideChar_(uint32_t cp, uint32_t, uint32_t src, uint32_t n, uint32_t dst, uint32_t cap) {
    if (!src) return SetLastError(win::ERROR_INVALID_PARAMETER), 0;
    size_t len = static_cast<int32_t>(n) < 0 ? strlen(At<char>(src)) + 1 : n;
    std::u16string w = Decode(cp, At<unsigned char>(src), len);
    if (cap == 0) return static_cast<uint32_t>(w.size());
    if (w.size() > cap) return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
    memcpy(At(dst), w.data(), w.size() * 2);
    return static_cast<uint32_t>(w.size());
}
RH_REG(KERNEL32, MultiByteToWideChar, MultiByteToWideChar_)

static uint32_t WideCharToMultiByte_(uint32_t cp, uint32_t, uint32_t src, uint32_t n, uint32_t dst, uint32_t cap,
                                     uint32_t, uint32_t usedDefault) {
    if (!src) return SetLastError(win::ERROR_INVALID_PARAMETER), 0;
    size_t len = static_cast<int32_t>(n) < 0 ? Len16(At<char16_t>(src)) + 1 : n;
    bool lossy = false;
    std::string s = Encode(cp, At<char16_t>(src), len, &lossy);
    if (usedDefault) *At<uint32_t>(usedDefault) = lossy;
    if (cap == 0) return static_cast<uint32_t>(s.size());
    if (s.size() > cap) return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
    memcpy(At(dst), s.data(), s.size());
    return static_cast<uint32_t>(s.size());
}
RH_REG(KERNEL32, WideCharToMultiByte, WideCharToMultiByte_)

static uint32_t GetACP_() { return AnsiCodePage(); }
RH_REG(KERNEL32, GetACP, GetACP_)
static uint32_t GetOEMCP_() { return 437; }
RH_REG(KERNEL32, GetOEMCP, GetOEMCP_)
static uint32_t GetConsoleCP_() { return 437; }
RH_REG(KERNEL32, GetConsoleCP, GetConsoleCP_)
static uint32_t IsValidCodePage_(uint32_t cp) {
    return cp == 1252 || cp == 65001 || cp == 437 || cp == 850 || cp == 20127 || cp == 28591 || cp == AnsiCodePage();
}
RH_REG(KERNEL32, IsValidCodePage, IsValidCodePage_)

// CPINFO: MaxCharSize, DefaultChar[2], LeadByte[12] (20 bytes)
static uint32_t GetCPInfo_(uint32_t cp, uint32_t out) {
    if (!IsValidCodePage_(Resolve(cp))) return SetLastError(win::ERROR_INVALID_PARAMETER), 0;
    auto o = At<uint8_t>(out);
    memset(o, 0, 20);
    *reinterpret_cast<uint32_t*>(o) = Resolve(cp) == 65001 ? 4 : 1;
    o[4] = '?';
    return 1;
}
RH_REG(KERNEL32, GetCPInfo, GetCPInfo_)

// GetStringTypeW(CT_CTYPE1 1 / CT_CTYPE2 2 / CT_CTYPE3 4, s, n, out words)
static uint32_t GetStringTypeW_(uint32_t type, uint32_t src, uint32_t n, uint32_t out) {
    const char16_t* s = At<char16_t>(src);
    size_t len = static_cast<int32_t>(n) < 0 ? Len16(s) + 1 : n;
    auto o = At<uint16_t>(out);
    for (size_t k = 0; k < len; k++) {
        char16_t c = s[k];
        uint16_t t = 0;
        if (type == 1) {
            if (Upper16(c) == c && Lower16(c) != c) t |= 0x1;            // C1_UPPER
            if (Lower16(c) == c && Upper16(c) != c) t |= 0x2;            // C1_LOWER
            if (c >= '0' && c <= '9') t |= 0x4;                          // C1_DIGIT
            if (c == ' ' || (c >= 9 && c <= 13) || c == 0xA0 || c == 0x3000) t |= 0x8;   // C1_SPACE
            if (c < 0x80 && ispunct(c)) t |= 0x10;                       // C1_PUNCT
            if (c < 0x20 || c == 0x7F) t |= 0x20;                        // C1_CNTRL
            if (c == ' ' || c == '\t') t |= 0x40;                        // C1_BLANK
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) t |= 0x80;   // C1_XDIGIT
            if ((c < 0x80 && isalpha(c)) || (c >= 0xC0 && c != 0xD7 && c != 0xF7)) t |= 0x100;   // C1_ALPHA
            if (c) t |= 0x200;                                           // C1_DEFINED
        } else if (type == 2) {
            t = c < 0x80 ? (isdigit(c) ? 3 : isspace(c) ? 10 : 1) : 1;   // C2_LEFTTORIGHT ...
        }
        o[k] = t;
    }
    return 1;
}
RH_REG(KERNEL32, GetStringTypeW, GetStringTypeW_)

// LCMapStringW(lcid, flags, src, n, dst, cap): case mapping (LCMAP_LOWERCASE 0x100, UPPERCASE 0x200);
// a sort key (LCMAP_SORTKEY 0x400) as the upper-cased text's bytes
static uint32_t LCMapStringW_(uint32_t, uint32_t flags, uint32_t src, uint32_t n, uint32_t dst, uint32_t cap) {
    const char16_t* s = At<char16_t>(src);
    size_t len = static_cast<int32_t>(n) < 0 ? Len16(s) + 1 : n;
    std::u16string r(s, len);
    for (auto& c : r) c = (flags & 0x100) ? Lower16(c) : (flags & 0x200) ? Upper16(c) : c;
    if (flags & 0x400) {
        std::string key;
        for (char16_t c : r) {
            if (!c) break;
            char16_t u = Upper16(c);
            key.push_back(static_cast<char>(u >> 8));
            key.push_back(static_cast<char>(u & 0xFF));
        }
        key.push_back(0);
        if (cap == 0) return static_cast<uint32_t>(key.size());
        if (key.size() > cap) return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
        memcpy(At(dst), key.data(), key.size());
        return static_cast<uint32_t>(key.size());
    }
    if (cap == 0) return static_cast<uint32_t>(r.size());
    if (r.size() > cap) return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
    memcpy(At(dst), r.data(), r.size() * 2);
    return static_cast<uint32_t>(r.size());
}
RH_REG(KERNEL32, LCMapStringW, LCMapStringW_)

static int Compare16(const char16_t* a, size_t na, const char16_t* b, size_t nb, bool fold) {
    for (size_t k = 0;; k++) {
        if (k == na || k == nb) return k == na ? (k == nb ? 0 : -1) : 1;
        char16_t x = fold ? Upper16(a[k]) : a[k], y = fold ? Upper16(b[k]) : b[k];
        if (x != y) return x < y ? -1 : 1;
    }
}
// CompareStringW: CSTR_LESS_THAN 1, CSTR_EQUAL 2, CSTR_GREATER_THAN 3 (ordinal, NORM_IGNORECASE 1)
static uint32_t CompareStringW_(uint32_t, uint32_t flags, uint32_t a, uint32_t na, uint32_t b, uint32_t nb) {
    size_t la = static_cast<int32_t>(na) < 0 ? Len16(At<char16_t>(a)) : na;
    size_t lb = static_cast<int32_t>(nb) < 0 ? Len16(At<char16_t>(b)) : nb;
    return static_cast<uint32_t>(Compare16(At<char16_t>(a), la, At<char16_t>(b), lb, flags & 1) + 2);
}
RH_REG(KERNEL32, CompareStringW, CompareStringW_)
static uint32_t lstrcmpW_(uint32_t a, uint32_t b) {
    return static_cast<uint32_t>(Compare16(At<char16_t>(a), Len16(At<char16_t>(a)), At<char16_t>(b), Len16(At<char16_t>(b)), false));
}
RH_REG(KERNEL32, lstrcmpW, lstrcmpW_)
static uint32_t lstrlenW_(uint32_t s) { return s ? static_cast<uint32_t>(Len16(At<char16_t>(s))) : 0; }
RH_REG(KERNEL32, lstrlenW, lstrlenW_)
static uint32_t lstrcatA_(uint32_t d, uint32_t s) { return strcat(At<char>(d), At<char>(s)), d; }
RH_REG(KERNEL32, lstrcatA, lstrcatA_)
static uint32_t lstrcpyA_(uint32_t d, uint32_t s) { return strcpy(At<char>(d), At<char>(s)), d; }
RH_REG(KERNEL32, lstrcpyA, lstrcpyA_)
static uint32_t MulDiv_(uint32_t a, uint32_t b, uint32_t c) {
    if (c == 0) return 0xFFFFFFFFu;
    int64_t p = static_cast<int64_t>(static_cast<int32_t>(a)) * static_cast<int32_t>(b);
    int64_t d = static_cast<int32_t>(c);
    int64_t q = (p + ((p < 0) != (d < 0) ? -d / 2 : d / 2)) / d;   // (rounded, as Windows')
    return q > INT32_MAX || q < INT32_MIN ? 0xFFFFFFFFu : static_cast<uint32_t>(static_cast<int32_t>(q));
}
RH_REG(KERNEL32, MulDiv, MulDiv_)

// FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM): "Error <n>." (ALLOCATE_BUFFER 0x100: a heap block)
static uint32_t FormatMessageA_(uint32_t flags, uint32_t, uint32_t id, uint32_t, uint32_t buf, uint32_t n, uint32_t) {
    char text[64];
    int len = snprintf(text, sizeof text, "Error %u.\r\n", id);
    if (flags & 0x100) {
        uint32_t p = HeapAllocIn(ProcessHeap(), 0, len + 1);
        memcpy(At(p), text, len + 1);
        *At<uint32_t>(buf) = p;
        return len;
    }
    if (static_cast<uint32_t>(len) >= n) return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
    memcpy(At(buf), text, len + 1);
    return len;
}
RH_REG(KERNEL32, FormatMessageA, FormatMessageA_)

// wsprintfA(buf, fmt, ...): a varargs call, its arguments the reference's 4-byte words after the
// format (the adapter's ten words past a0..a3: twelve at most). wsprintf has no floating point
static uint32_t wsprintfA_(uint32_t buf, uint32_t fmt, uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3, uint32_t w4,
                           uint32_t w5, uint32_t w6, uint32_t w7, uint32_t w8, uint32_t w9, uint32_t w10, uint32_t w11) {
    const uint32_t words[12] = {w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11};
    unsigned next = 0;
    auto take = [&]() { return next < 12 ? words[next++] : 0u; };
    std::string out;
    for (const char* f = At<char>(fmt); *f; f++) {
        if (*f != '%') {
            out.push_back(*f);
            continue;
        }
        std::string spec = "%";
        f++;
        while (*f && strchr("-#0", *f)) spec.push_back(*f++);
        while (*f >= '0' && *f <= '9') spec.push_back(*f++);
        if (*f == '.') {
            spec.push_back(*f++);
            while (*f >= '0' && *f <= '9') spec.push_back(*f++);
        }
        bool wide = false;
        if (*f == 'l' || *f == 'h') f++;
        else if (f[0] == 'I' && f[1] == '6' && f[2] == '4') f += 3, wide = true;
        char conv = *f;
        if (!conv) break;
        char piece[512];
        if (conv == 'd' || conv == 'i') {
            long long v = wide ? static_cast<long long>(take() | (static_cast<uint64_t>(take()) << 32)) : static_cast<int32_t>(take());
            snprintf(piece, sizeof piece, (spec + "lld").c_str(), v);
        } else if (conv == 'u' || conv == 'x' || conv == 'X') {
            unsigned long long v = wide ? take() | (static_cast<uint64_t>(take()) << 32) : take();
            snprintf(piece, sizeof piece, (spec + "ll" + conv).c_str(), v);
        } else if (conv == 'c') {
            snprintf(piece, sizeof piece, (spec + "c").c_str(), static_cast<int>(take() & 0xFF));
        } else if (conv == 's') {
            uint32_t p = take();
            snprintf(piece, sizeof piece, (spec + "s").c_str(), p ? At<char>(p) : "(null)");
        } else if (conv == 'S') {
            uint32_t p = take();
            snprintf(piece, sizeof piece, (spec + "s").c_str(), p ? AnsiOf(At<char16_t>(p)).c_str() : "(null)");
        } else {
            piece[0] = conv, piece[1] = 0;
        }
        out += piece;
    }
    if (out.size() > 1023) out.resize(1023);
    memcpy(At(buf), out.c_str(), out.size() + 1);
    return static_cast<uint32_t>(out.size());
}
RH_REG(USER32, wsprintfA, wsprintfA_)

// ---- the locale: en-US ------------------------------------------------------------------------
static std::string LocaleInfo(uint32_t type) {
    switch (type & 0x0FFFFFFF) {
        case 0x1004: return std::to_string(AnsiCodePage());   // LOCALE_IDEFAULTANSICODEPAGE
        case 0x000B: return "437";                            // LOCALE_IDEFAULTCODEPAGE
        case 0x0001: return "0409";                           // LOCALE_ILANGUAGE
        case 0x0002: return "English (United States)";        // LOCALE_SLANGUAGE
        case 0x1001: return "English";                        // LOCALE_SENGLANGUAGE
        case 0x0003: return "ENU";                            // LOCALE_SABBREVLANGNAME
        case 0x0004: return "English";                        // LOCALE_SNATIVELANGNAME
        case 0x0005: return "1";                              // LOCALE_ICOUNTRY
        case 0x1002: return "United States";                  // LOCALE_SENGCOUNTRY
        case 0x0006: return "United States";
        case 0x0007: return "USA";                            // LOCALE_SABBREVCTRYNAME
        case 0x0059: return "en";                             // LOCALE_SISO639LANGNAME
        case 0x005A: return "US";                             // LOCALE_SISO3166CTRYNAME
        case 0x005C: return "en-US";                          // LOCALE_SNAME
        case 0x000E: return ".";                              // LOCALE_SDECIMAL
        case 0x000F: return ",";                              // LOCALE_STHOUSAND
        case 0x0010: return "3;0";                            // LOCALE_SGROUPING
        case 0x0014: return "$";                              // LOCALE_SCURRENCY
        case 0x001D: return "/";                              // LOCALE_SDATE
        case 0x001E: return ":";                              // LOCALE_STIME
        case 0x001F: return "M/d/yyyy";                       // LOCALE_SSHORTDATE
        case 0x0020: return "dddd, MMMM d, yyyy";             // LOCALE_SLONGDATE
        case 0x1003: return "hh:mm:ss tt";                    // LOCALE_STIMEFORMAT
        case 0x0028: return "AM";
        case 0x0029: return "PM";
        case 0x100C: return "0";                              // LOCALE_IFIRSTDAYOFWEEK... (Monday 0)
        default: return "";
    }
}
static uint32_t GetLocaleInfo(uint32_t type, char16_t* w, char* a, uint32_t cap) {
    std::string v = LocaleInfo(type);
    if (v.empty() && (type & 0x0FFFFFFF) != 0) {
        LogOnce(("locale " + std::to_string(type)).c_str(), "GetLocaleInfo(%#x): not known, empty", type);
    }
    uint32_t need = static_cast<uint32_t>(v.size() + 1);
    if (cap == 0) return need;
    if (cap < need) return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
    for (size_t k = 0; k < need; k++) {
        if (w) w[k] = static_cast<unsigned char>(v.c_str()[k]);
        else a[k] = v.c_str()[k];
    }
    return need;
}
static uint32_t GetLocaleInfoA_(uint32_t, uint32_t type, uint32_t buf, uint32_t cap) {
    return GetLocaleInfo(type, nullptr, At<char>(buf), cap);
}
RH_REG(KERNEL32, GetLocaleInfoA, GetLocaleInfoA_)
static uint32_t GetLocaleInfoW_(uint32_t, uint32_t type, uint32_t buf, uint32_t cap) {
    return GetLocaleInfo(type, At<char16_t>(buf), nullptr, cap);
}
RH_REG(KERNEL32, GetLocaleInfoW, GetLocaleInfoW_)
static uint32_t GetUserDefaultLCID_() { return 0x409; }
RH_REG(KERNEL32, GetUserDefaultLCID, GetUserDefaultLCID_)
static uint32_t GetSystemDefaultLCID_() { return 0x409; }
RH_REG(KERNEL32, GetSystemDefaultLCID, GetSystemDefaultLCID_)
static uint32_t GetUserDefaultLangID_() { return 0x409; }
RH_REG(KERNEL32, GetUserDefaultLangID, GetUserDefaultLangID_)
static uint32_t IsValidLocale_(uint32_t lcid, uint32_t) { return lcid == 0x409 || lcid == 0x400 || lcid == 0x800; }
RH_REG(KERNEL32, IsValidLocale, IsValidLocale_)
// EnumSystemLocalesA(callback, flags): the one locale, as its hex string, to the reference's callback
static uint32_t EnumSystemLocalesA_(uint32_t fn, uint32_t) {
    static char* s = nullptr;
    if (!s) {
        s = static_cast<char*>(LowNew(16));
        strcpy(s, "00000409");
    }
    CallRef(fn, Low(s));
    return 1;
}
RH_REG(KERNEL32, EnumSystemLocalesA, EnumSystemLocalesA_)

// GetDateFormatA / GetTimeFormatA with a SYSTEMTIME (or now) and a picture (or the locale's)
static std::string FormatPicture(const char* pic, const uint16_t* st) {
    static const char* const days[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
    static const char* const months[] = {"January", "February", "March", "April", "May", "June", "July",
                                         "August", "September", "October", "November", "December"};
    std::string out;
    char b[32];
    for (const char* p = pic; *p;) {
        char c = *p;
        int n = 0;
        while (p[n] == c) n++;
        auto num = [&](int v, int width) { snprintf(b, sizeof b, "%0*d", width, v); out += b; };
        switch (c) {
            case 'd': if (n >= 4) out += days[st[2] % 7]; else if (n == 3) out += std::string(days[st[2] % 7], 3); else num(st[3], n); break;
            case 'M': if (n >= 4) out += months[(st[1] + 11) % 12]; else if (n == 3) out += std::string(months[(st[1] + 11) % 12], 3); else num(st[1], n); break;
            case 'y': num(n >= 3 ? st[0] : st[0] % 100, n >= 3 ? 4 : n); break;
            case 'h': num(st[4] % 12 ? st[4] % 12 : 12, n); break;
            case 'H': num(st[4], n); break;
            case 'm': num(st[5], n); break;
            case 's': num(st[6], n); break;
            case 't': out += st[4] < 12 ? (n == 1 ? "A" : "AM") : (n == 1 ? "P" : "PM"); break;
            case '\'': {
                const char* q = p + 1;
                while (*q && *q != '\'') out.push_back(*q++);
                n = static_cast<int>(q - p) + (*q ? 1 : 0);
                break;
            }
            default: out.append(n, c);
        }
        p += n;
    }
    return out;
}
static uint32_t DateTimeFormat(bool date, uint32_t st, uint32_t pic, uint32_t buf, uint32_t cap) {
    uint16_t now[8];
    if (!st) {
        time_t t = time(nullptr);
        tm l;
        localtime_r(&t, &l);
        uint16_t v[8] = {static_cast<uint16_t>(l.tm_year + 1900), static_cast<uint16_t>(l.tm_mon + 1),
                         static_cast<uint16_t>(l.tm_wday), static_cast<uint16_t>(l.tm_mday),
                         static_cast<uint16_t>(l.tm_hour), static_cast<uint16_t>(l.tm_min),
                         static_cast<uint16_t>(l.tm_sec), 0};
        memcpy(now, v, sizeof now);
    }
    std::string s = FormatPicture(pic ? At<char>(pic) : date ? "M/d/yyyy" : "h:mm:ss tt", st ? At<uint16_t>(st) : now);
    if (cap == 0) return static_cast<uint32_t>(s.size() + 1);
    if (s.size() + 1 > cap) return SetLastError(win::ERROR_INSUFFICIENT_BUFFER), 0;
    memcpy(At(buf), s.c_str(), s.size() + 1);
    return static_cast<uint32_t>(s.size() + 1);
}
static uint32_t GetDateFormatA_(uint32_t, uint32_t, uint32_t st, uint32_t pic, uint32_t buf, uint32_t cap) {
    return DateTimeFormat(true, st, pic, buf, cap);
}
RH_REG(KERNEL32, GetDateFormatA, GetDateFormatA_)
static uint32_t GetTimeFormatA_(uint32_t, uint32_t, uint32_t st, uint32_t pic, uint32_t buf, uint32_t cap) {
    return DateTimeFormat(false, st, pic, buf, cap);
}
RH_REG(KERNEL32, GetTimeFormatA, GetTimeFormatA_)
