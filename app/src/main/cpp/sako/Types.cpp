#include "Types.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace sako {

std::string readCString(const u8* p, size_t avail, size_t maxLen) {
    size_t len = 0;
    while (len < avail && p[len] != 0 && len < maxLen) ++len;
    std::string s;
    s.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        u8 c = p[i];
        s.push_back(c >= 0x20 || c == '\t' ? char(c) : ' ');
    }
    return s;
}

std::string hexAddr(u64 v) {
    char buf[24];
    snprintf(buf, sizeof buf, "0x%llX", (unsigned long long)v);
    return buf;
}

std::string jsonEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 16);
    char buf[8];
    for (unsigned char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20 || c >= 0x7F) {
                    snprintf(buf, sizeof buf, "\\u%04X", c);
                    out += buf;
                } else out += char(c);
        }
    }
    return out;
}

std::string humanSize(u64 n) {
    const char* u[] = {"B", "KB", "MB", "GB"};
    double v = double(n);
    int k = 0;
    while (v >= 1024.0 && k < 3) { v /= 1024.0; ++k; }
    std::ostringstream os;
    os << std::fixed << std::setprecision(1) << v << " " << u[k];
    return os.str();
}

const char* fmtName(Fmt f) {
    switch (f) {
        case Fmt::ELF:   return "ELF";
        case Fmt::PE:    return "PE";
        case Fmt::DEX:   return "DEX";
        case Fmt::MachO: return "Mach-O";
        case Fmt::ZIP:   return "ZIP/APK";
        default:         return "RAW";
    }
}

Fmt detectFormat(const u8* p, size_t n) {
    if (n < 4) return Fmt::Unknown;
    if (p[0] == 0x7F && p[1] == 'E' && p[2] == 'L' && p[3] == 'F') return Fmt::ELF;
    if (p[0] == 'M' && p[1] == 'Z') return Fmt::PE;
    if (memcmp(p, "dex\n", 4) == 0) return Fmt::DEX;
    if (p[0] == 'P' && p[1] == 'K') return Fmt::ZIP;
    if (n >= 16 && (rd32(p) == 0xFEEDFACF || rd32(p) == 0xFEEDFACE ||
                    rd32be(p) == 0xFEEDFACF || rd32be(p) == 0xFEEDFACE)) return Fmt::MachO;
    return Fmt::Unknown;
}

std::vector<FoundString> extractPrintableStrings(const u8* p, size_t n, u64 vaddrBase,
                                                 size_t cap, size_t minLen) {
    std::vector<FoundString> out;
    size_t i = 0;
    while (i < n && out.size() < cap) {
        if (printable(p[i])) {
            size_t start = i, len = 0;
            while (i < n && printable(p[i]) && len < 512) { ++i; ++len; }
            if (len >= minLen) {
                FoundString fs;
                fs.addr = vaddrBase + u64(start);
                fs.value.assign(reinterpret_cast<const char*>(p + start), len);
                out.push_back(fs);
            }
        } else ++i;
    }
    return out;
}

} // namespace sako
