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

// Escaping every byte >= 0x7F as \u00XX treats UTF-8 continuation bytes as
// Latin-1 code points, so an em dash (E2 80 94) came out the other side as
// "â" plus two control characters. Valid UTF-8 is passed through untouched —
// JSON is a UTF-8 format — and only bytes that are not part of a well-formed
// sequence get escaped, which keeps strings scraped out of binaries safe.
std::string jsonEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 16);
    char buf[8];

    auto seqLen = [](unsigned char c) -> int {
        if ((c & 0xE0) == 0xC0) return 2;
        if ((c & 0xF0) == 0xE0) return 3;
        if ((c & 0xF8) == 0xF0) return 4;
        return 0;
    };

    for (size_t i = 0; i < in.size(); ++i) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"':  out += "\\\""; continue;
            case '\\': out += "\\\\"; continue;
            case '\n': out += "\\n";  continue;
            case '\r': out += "\\r";  continue;
            case '\t': out += "\\t";  continue;
            default: break;
        }
        if (c < 0x20) {
            snprintf(buf, sizeof buf, "\\u%04X", c);
            out += buf;
            continue;
        }
        if (c < 0x7F) { out += char(c); continue; }

        int n = seqLen(c);
        bool valid = n > 0 && i + size_t(n) <= in.size();
        if (valid) {
            for (int k = 1; k < n; ++k) {
                if (((unsigned char)in[i + size_t(k)] & 0xC0) != 0x80) { valid = false; break; }
            }
        }
        if (valid) {
            out.append(in, i, size_t(n));
            i += size_t(n) - 1;
        } else {
            // Lone byte from binary data: keep it representable and valid JSON.
            snprintf(buf, sizeof buf, "\\u%04X", c);
            out += buf;
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
