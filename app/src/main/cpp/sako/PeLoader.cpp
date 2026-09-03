#include "Loaders.h"
#include <cstring>

namespace sako {

static const char* peMachineName(u16 m, std::string& en) {
    switch (m) {
        case 0x8664: en = "X86_64"; return "x86-64";
        case 0x014C: en = "X86";    return "i386";
        case 0xAA64: en = "ARM64";  return "AArch64";
        case 0x01C4: en = "ARM";    return "ARM";
        default: en = "";           return "unknown";
    }
}

PeInfo parsePe(const Binary& b) {
    PeInfo info;
    const u8* p = b.data.data();
    size_t n = b.data.size();

    if (n < 0x40 || p[0] != 'M' || p[1] != 'Z') { info.error = "Not a PE file (no MZ)"; return info; }
    u32 eLfanew = rd32(p + 0x3C);
    if (eLfanew + 24 > n || memcmp(p + eLfanew, "PE\0\0", 4) != 0) {
        info.error = "PE signature not found";
        return info;
    }
    const u8* coff = p + eLfanew + 4;
    if (coff + 20 > p + n) { info.error = "Truncated COFF header"; return info; }
    u16 machine = rd16(coff);
    u16 numSec  = rd16(coff + 2);
    u16 sizeOpt = rd16(coff + 16);

    const u8* opt = coff + 20;
    if (sizeOpt < 112 || opt + sizeOpt > p + n) { info.error = "Missing/truncated optional header"; return info; }
    u16 magic = rd16(opt);
    bool pe32p = (magic == 0x20B);
    if (!pe32p && magic != 0x10B) { info.error = "Unknown optional header magic"; return info; }

    info.entry = pe32p ? rd32(opt + 16) : rd32(opt + 16);
    if (pe32p) info.imageBase = rd64(opt + 24);
    else       info.imageBase = rd32(opt + 28);

    std::string en;
    info.archName = peMachineName(machine, en);
    info.archEnum = en;
    if (info.archEnum.empty()) info.archEnum = "X86_64"; // safe default for x86 subset

    u32 dataDirOff = pe32p ? 112 : 96;
    u32 numDirs = pe32p ? rd32(opt + 108) : rd32(opt + 92);

    // sections
    const u8* sh = opt + sizeOpt;
    u64 hdrEnd = u64(sh - p) + u64(numSec) * 40;
    if (numSec > 96 || hdrEnd > n) numSec = u16(std::max<u64>(0, (n - u64(sh - p)) / 40));
    for (u16 i = 0; i < numSec; ++i) {
        const u8* sp = sh + u64(i) * 40;
        Section s;
        char name[9]; memcpy(name, sp, 8); name[8] = 0;
        s.name = name;
        u32 vsize = rd32(sp + 8), vaddr = rd32(sp + 12);
        u32 rawSize = rd32(sp + 16), rawPtr = rd32(sp + 20);
        u32 chars = rd32(sp + 36);
        s.addr = info.imageBase + vaddr;
        s.offset = rawPtr;
        s.size = vsize ? vsize : rawSize;
        std::string fl;
        if (chars & 0x20000000) fl += "X";
        if (chars & 0x40000000) fl += "R";
        if (chars & 0x80000000) fl += "W";
        if (chars & 0x00000020) fl += "C";
        s.flags = fl.empty() ? "-" : fl;
        s.type = (chars & 0x00000020) ? "CODE" : "DATA";
        info.sections.push_back(s);
    }

    auto rvaToOff = [&](u32 rva) -> u32 {
        for (auto& s : info.sections) {
            u32 vaddr = u32(s.addr - info.imageBase);
            u32 vsz = u32(s.size);
            if (rva >= vaddr && rva < vaddr + std::max(vsz, u32(1))) {
                u32 delta = rva - vaddr;
                if (s.offset + delta < n) return u32(s.offset) + delta;
            }
        }
        return 0;
    };

    // exports
    if (numDirs >= 1) {
        u32 expRva = rd32(opt + dataDirOff), expSize = rd32(opt + dataDirOff + 4);
        if (expRva && expSize) {
            u32 off = rvaToOff(expRva);
            if (off && off + 40 <= n) {
                const u8* ed = p + off;
                u32 nameRva = rd32(ed + 12);
                u32 nFuncs = rd32(ed + 20), nNames = rd32(ed + 24);
                u32 addrFuncs = rd32(ed + 28), addrNames = rd32(ed + 32), addrOrds = rd32(ed + 36);
                if (nameRva) {
                    u32 no = rvaToOff(nameRva);
                    if (no && no < n) {
                        // dll name available at p+no
                    }
                }
                nFuncs = std::min<u32>(nFuncs, 20000);
                nNames = std::min<u32>(nNames, 20000);
                for (u32 i = 0; i < nNames && i < nFuncs; ++i) {
                    if (addrNames + i * 4 + 4 > n || addrOrds + i * 2 + 2 > n) break;
                    u32 nmRva = rd32(p + rvaToOff(addrNames) + i * 4);
                    u16 ord = rd16(p + rvaToOff(addrOrds) + i * 2);
                    if (addrFuncs + ord * 4 + 4 > n) break;
                    u32 fRva = rd32(p + rvaToOff(addrFuncs) + ord * 4);
                    Symbol sym;
                    if (nmRva) {
                        u32 no = rvaToOff(nmRva);
                        if (no && no < n) sym.name = readCString(p + no, n - no, 256);
                    }
                    if (sym.name.empty()) sym.name = "Ordinal_" + std::to_string(ord);
                    sym.addr = info.imageBase + fRva;
                    sym.kind = "FUNC"; sym.bind = "GLOBAL"; sym.defined = true;
                    info.exports.push_back(sym);
                }
            }
        }
    }

    // imports
    if (numDirs >= 2) {
        u32 impRva = rd32(opt + dataDirOff + 8);
        if (impRva) {
            u32 off = rvaToOff(impRva);
            for (int iter = 0; iter < 512 && off && off + 20 <= n; ++iter) {
                const u8* id = p + off;
                u32 oftRva = rd32(id), nameRva = rd32(id + 12), ftRva = rd32(id + 16);
                if (!oftRva && !ftRva && !nameRva) break; // terminator
                std::string dll;
                if (nameRva) {
                    u32 no = rvaToOff(nameRva);
                    if (no && no < n) dll = readCString(p + no, n - no, 128);
                }
                u32 thunkRva = oftRva ? oftRva : ftRva;
                u32 toff = thunkRva ? rvaToOff(thunkRva) : 0;
                u64 iatSlot = u64(ftRva);   // IAT = what code actually calls through
                for (int k = 0; k < 8192 && toff; ++k) {
                    if (toff + (pe32p ? 8 : 4) > n) break;
                    u64 thunk;
                    if (pe32p) thunk = rd64(p + toff);
                    else thunk = rd32(p + toff);
                    if (thunk == 0) break;
                    bool ordinalFlag = pe32p ? ((thunk >> 63) & 1) : ((thunk >> 31) & 1);
                    Symbol sym;
                    if (ordinalFlag) {
                        u64 ordv = pe32p ? (thunk & 0xFFFF) : (thunk & 0xFFFF);
                        sym.name = dll + "!#" + std::to_string(ordv);
                    } else {
                        u32 hn = rvaToOff(u32(pe32p ? thunk : thunk));
                        if (hn && hn + 2 < n) {
                            sym.name = dll + "!" + readCString(p + hn + 2, n - hn - 2, 200);
                        } else sym.name = dll + "!?";
                    }
                    sym.kind = "FUNC"; sym.bind = "IMPORT"; sym.defined = false;
                    sym.addr = info.imageBase + iatSlot + u64(k) * (pe32p ? 8 : 4);
                    if (!sym.name.empty()) info.imports.push_back(sym);
                    toff += pe32p ? 8 : 4;
                }
                off += 20;
            }
        }
    }

    info.ok = true;
    return info;
}

u64 peVaToOff(const PeInfo& e, u64 va) {
    u32 rva = u32(va - e.imageBase);
    for (auto& s : e.sections) {
        u32 vaddr = u32(s.addr - e.imageBase);
        if (rva >= vaddr && rva < vaddr + s.size) {
            u64 delta = rva - vaddr;
            if (s.offset != ~u64(0)) return s.offset + delta;
        }
    }
    return ~u64(0);
}

} // namespace sako
