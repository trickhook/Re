#include "Loaders.h"
#include <cstring>

namespace sako {

static u64 uleb(const u8* p, size_t n, size_t& pos) {
    u64 r = 0; int sh = 0;
    while (pos < n) {
        u8 c = p[pos++];
        r |= u64(c & 0x7F) << sh;
        if (!(c & 0x80)) break;
        sh += 7;
        if (sh > 35) break;
    }
    return r;
}

DexInfo parseDex(const Binary& b) {
    DexInfo info;
    const u8* p = b.data.data();
    size_t n = b.data.size();

    if (n < 112 || memcmp(p, "dex\n", 4) != 0) { info.error = "Not a DEX file"; return info; }
    u32 endianTag = rd32(p + 40);
    if (endianTag != 0x12345678) { info.error = "Big-endian DEX not supported"; return info; }

    u32 strCount = rd32(p + 56), strOff = rd32(p + 60);
    u32 typeCount = rd32(p + 64), typeOff = rd32(p + 68);
    u32 protoCount = rd32(p + 72), protoOff = rd32(p + 76);
    u32 methodCount = rd32(p + 88), methodOff = rd32(p + 92);
    u32 classCount = rd32(p + 96), classOff = rd32(p + 100);

    // ---- strings ----
    size_t sCap = std::min<u32>(strCount, 50000);
    info.strings.reserve(sCap);
    for (u32 i = 0; i < sCap; ++i) {
        if (strOff + u64(i) * 4 + 4 > n) break;
        u32 dataOff = rd32(p + strOff + i * 4);
        if (dataOff >= n) { info.strings.push_back("?"); continue; }
        size_t pos = dataOff;
        uleb(p, n, pos); // utf16 length (ignore)
        if (pos >= n) { info.strings.push_back("?"); continue; }
        info.strings.push_back(readCString(p + pos, n - pos, 512));
    }

    auto typeDesc = [&](u32 idx) -> std::string {
        if (idx == 0xFFFFFFFF || idx >= typeCount) return "?";
        if (typeOff + u64(idx) * 4 + 4 > n) return "?";
        u32 sIdx = rd32(p + typeOff + idx * 4);
        if (sIdx < info.strings.size()) return info.strings[sIdx];
        return "?";
    };

    // ---- protos ----
    std::vector<std::string> protoStr;
    protoStr.reserve(std::min<u32>(protoCount, 20000));
    for (u32 i = 0; i < std::min<u32>(protoCount, 20000); ++i) {
        if (protoOff + u64(i) * 12 + 12 > n) { protoStr.push_back("()"); continue; }
        const u8* pp = p + protoOff + i * 12;
        u32 retIdx = rd32(pp + 4);
        u32 paramsOff = rd32(pp + 8);
        std::string sig = "(";
        if (paramsOff && paramsOff + 4 <= n) {
            u32 pcount = rd32(p + paramsOff);
            if (pcount <= 4096 && paramsOff + 4 + u64(pcount) * 2 <= n) {
                for (u32 k = 0; k < pcount; ++k) {
                    if (k) sig += ", ";
                    sig += typeDesc(rd16(p + paramsOff + 4 + u64(k) * 2));
                }
            }
        }
        sig += ")";
        sig += typeDesc(retIdx);
        protoStr.push_back(sig);
    }

    // ---- methods ----
    size_t mCap = std::min<u32>(methodCount, 20000);
    info.methods.reserve(mCap);
    for (u32 i = 0; i < mCap; ++i) {
        if (methodOff + u64(i) * 8 + 8 > n) break;
        const u8* mp = p + methodOff + i * 8;
        u16 classIdx = rd16(mp);
        u16 protoIdx = rd16(mp + 2);
        u32 nameIdx = rd32(mp + 4);
        DexMethod m;
        m.clazz = typeDesc(classIdx);
        m.name = nameIdx < info.strings.size() ? info.strings[nameIdx] : "?";
        m.proto = protoIdx < protoStr.size() ? protoStr[protoIdx] : "()?";
        m.codeOff = 0;
        info.methods.push_back(m);
    }

    // ---- classes (+ method code offsets via class_data) ----
    size_t cCap = std::min<u32>(classCount, 8192);
    info.classes.reserve(cCap);
    for (u32 i = 0; i < cCap; ++i) {
        if (classOff + u64(i) * 32 + 32 > n) break;
        const u8* cp = p + classOff + i * 32;
        u32 classIdx = rd32(cp);
        u32 superIdx = rd32(cp + 8);
        u32 classDataOff = rd32(cp + 24);
        DexClass c;
        c.name = typeDesc(classIdx);
        c.super = (superIdx == 0xFFFFFFFF) ? "" : typeDesc(superIdx);
        info.classes.push_back(c);
        // attach code offsets of direct+virtual methods
        if (classDataOff && classDataOff < n) {
            size_t pos = classDataOff;
            u64 staticF = uleb(p, n, pos), instF = uleb(p, n, pos);
            u64 directM = uleb(p, n, pos), virtM = uleb(p, n, pos);
            u64 fields = staticF + instF;
            for (u64 k = 0; k < fields && pos < n; ++k) { uleb(p, n, pos); uleb(p, n, pos); }
            u64 methods = std::min<u64>(directM + virtM, 8192);
            u32 mIdx = 0; u64 mDiff = 0;
            for (u64 k = 0; k < methods && pos < n; ++k) {
                u64 dIdx = uleb(p, n, pos);
                uleb(p, n, pos);              // access flags
                u64 codeOff = uleb(p, n, pos);
                mDiff += dIdx;
                u32 methodId = u32(mDiff);
                if (methodId < info.methods.size()) info.methods[methodId].codeOff = codeOff;
                ++mIdx;
            }
        }
    }

    info.ok = true;
    return info;
}

} // namespace sako
