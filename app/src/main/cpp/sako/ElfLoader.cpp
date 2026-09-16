#include "Loaders.h"
#include <cstring>

namespace sako {

static const char* secTypeName(u32 t) {
    switch (t) {
        case 0: return "NULL"; case 1: return "PROGBITS"; case 2: return "SYMTAB";
        case 3: return "STRTAB"; case 4: return "RELA"; case 5: return "HASH";
        case 6: return "DYNAMIC"; case 7: return "NOTE"; case 8: return "NOBITS";
        case 9: return "REL"; case 11: return "DYNSYM"; case 14: return "INIT_ARRAY";
        case 15: return "FINI_ARRAY"; case 0x6FFFFFF6: return "GNU_HASH";
        case 0x6FFFFFFE: return "VERNEED"; case 0x6FFFFFFF: return "VERSYM";
        default: return "OTHER";
    }
}
static std::string secFlags(u64 f) {
    std::string s;
    if (f & 0x1) s += "W";
    if (f & 0x2) s += "A";
    if (f & 0x4) s += "X";
    if (f & 0x10) s += "M";
    if (f & 0x400) s += "T";
    return s.empty() ? "-" : s;
}
static const char* segTypeName(u32 t) {
    switch (t) {
        case 1: return "LOAD"; case 2: return "DYNAMIC"; case 3: return "INTERP";
        case 4: return "NOTE"; case 6: return "PHDR"; case 7: return "TLS";
        case 0x6474E550: return "GNU_EH_FRAME"; case 0x6474E551: return "GNU_STACK";
        case 0x6474E552: return "GNU_RELRO"; case 0x6474E553: return "GNU_PROPERTY";
        default: return "OTHER";
    }
}
static std::string segFlags(u32 f) {
    std::string s;
    if (f & 4) s += "R";
    if (f & 2) s += "W";
    if (f & 1) s += "X";
    return s.empty() ? "-" : s;
}

ElfInfo parseElf(const Binary& b) {
    ElfInfo info;
    const u8* p = b.data.data();
    size_t n = b.data.size();

    if (n < 64 || p[0] != 0x7F || p[1] != 'E' || p[2] != 'L' || p[3] != 'F') {
        info.error = "Not an ELF file";
        return info;
    }
    u8 eiClass = p[4], eiData = p[5];
    if (eiData != 1) { info.error = "Big-endian ELF not supported"; return info; }
    bool is64 = (eiClass == 2);
    info.bits = is64 ? 64 : 32;

    // ELF header fields follow EI_DATA, so every structural read has to respect
    // it — big-endian MIPS/PPC/S390 objects are otherwise parsed as garbage.
    info.bigEndian = (eiData == 2);
    const bool be = info.bigEndian;
    auto R16 = [be](const u8* q) -> u16 { return be ? rd16be(q) : rd16(q); };
    auto R32 = [be](const u8* q) -> u32 { return be ? rd32be(q) : rd32(q); };
    auto R64 = [be](const u8* q) -> u64 { return be ? rd64be(q) : rd64(q); };

    auto rd = [&](u64 off, int sz) -> u64 {
        if (off + u64(sz) > n) return 0;
        switch (sz) {
            case 1: return p[off];
            case 2: return R16(p + off);
            case 4: return R32(p + off);
            default: return R64(p + off);
        }
    };

    // e_machine -> (display name, disassembler arch id). The arch id carries
    // width and endianness because Capstone needs both to pick a mode.
    // Architectures Capstone 4.0.2 cannot decode get a name but no arch id, so
    // the rest of the loader still works and only disassembly is unavailable.
    u16 machine = u16(rd(18, 2));
    const char* beSuffix = be ? "BE" : "";
    auto setArch = [&](const char* name, const std::string& id) {
        info.archName = name;
        info.archEnum = id;
    };
    switch (machine) {
        case 2:   setArch("SPARC",        is64 ? "SPARCV9" : "SPARC");            break;
        case 3:   setArch("i386",         "X86");                                 break;
        case 4:   setArch("Motorola 68k", "M68K");                                break;
        case 8:   setArch(is64 ? "MIPS64" : "MIPS",
                          std::string(is64 ? "MIPS64" : "MIPS32") + beSuffix);    break;
        case 18:  setArch("SPARC32PLUS",  "SPARC");                               break;
        case 20:  setArch("PowerPC",      std::string("PPC32") + beSuffix);       break;
        case 21:  setArch("PowerPC64",    std::string("PPC64") + beSuffix);       break;
        case 22:  setArch("IBM S/390",    "SYSZ");                                break;
        case 40:  setArch("ARM",          std::string("ARM") + beSuffix);         break;
        case 43:  setArch("SPARC V9",     "SPARCV9");                             break;
        case 62:  setArch("x86-64",       "X86_64");                              break;
        case 140: setArch("TI C6000",     "TMS320C64X");                          break;
        case 183: setArch("AArch64",      std::string("ARM64") + beSuffix);       break;
        // Recognised, but Capstone 4.0.2 has no decoder for these.
        case 42:  setArch("SuperH",       "");                                    break;
        case 50:  setArch("IA-64",        "");                                    break;
        case 243: setArch("RISC-V",       "");                                    break;
        default: {
            char buf[32];
            snprintf(buf, sizeof buf, "machine_%u", machine);
            info.archName = buf;
            info.archEnum = "";
        }
    }

    const bool isArm32 = (machine == 40);

    info.entry  = rd(24, is64 ? 8 : 4);
    info.eFlags = u32(rd(is64 ? 48 : 36, 4));
    u64 shoff = rd(is64 ? 40 : 32, is64 ? 8 : 4);
    u16 shentsize = u16(rd(is64 ? 58 : 46, 2));
    u16 shnum     = u16(rd(is64 ? 60 : 48, 2));
    u16 shstrndx  = u16(rd(is64 ? 62 : 50, 2));
    u64 phoff     = rd(is64 ? 32 : 28, is64 ? 8 : 4);
    u16 phentsize = u16(rd(is64 ? 54 : 42, 2));
    u16 phnum     = u16(rd(is64 ? 56 : 44, 2));

    // ---- sections ----
    struct RawSec { u32 nameIdx, type, link; u64 flags, addr, offset, size; };
    std::vector<RawSec> raw;
    if (shoff && shnum && shentsize >= 40) {
        if (shnum > 4096) shnum = 4096;
        raw.reserve(shnum);
        for (u16 i = 0; i < shnum; ++i) {
            u64 base = shoff + u64(i) * shentsize;
            if (base + shentsize > n) break;
            RawSec s{};
            s.nameIdx = u32(rd(base, 4));
            s.type    = u32(rd(base + 4, 4));
            if (is64) {
                s.flags = rd(base + 8, 8);  s.addr = rd(base + 16, 8);
                s.offset = rd(base + 24, 8); s.size = rd(base + 32, 8);
                s.link = u32(rd(base + 40, 4));
            } else {
                s.flags = rd(base + 8, 4);  s.addr = rd(base + 12, 4);
                s.offset = rd(base + 16, 4); s.size = rd(base + 20, 4);
                s.link = u32(rd(base + 24, 4));
            }
            raw.push_back(s);
        }
        const u8* strBase = nullptr; size_t strLen = 0;
        if (shstrndx < raw.size()) {
            u64 so = raw[shstrndx].offset, sz = raw[shstrndx].size;
            if (so < n && so + sz <= n) { strBase = p + so; strLen = sz; }
        }
        for (auto& s : raw) {
            Section out;
            if (strBase && s.nameIdx < strLen)
                out.name = readCString(strBase + s.nameIdx, strLen - s.nameIdx, 128);
            out.type = secTypeName(s.type);
            out.flags = secFlags(s.flags);
            out.addr = s.addr; out.offset = s.offset; out.size = s.size;
            info.sections.push_back(out);
        }
    }

    // ---- program headers ----
    if (phoff && phnum && phentsize >= 32) {
        if (phnum > 128) phnum = 128;
        for (u16 i = 0; i < phnum; ++i) {
            u64 base = phoff + u64(i) * phentsize;
            if (base + phentsize > n) break;
            Segment sg;
            u32 type, flags;
            u64 vaddr, offset, filesz, memsz;
            if (is64) {
                type = u32(rd(base, 4)); flags = u32(rd(base + 4, 4));
                offset = rd(base + 8, 8); vaddr = rd(base + 16, 8);
                filesz = rd(base + 32, 8); memsz = rd(base + 40, 8);
            } else {
                type = u32(rd(base, 4)); offset = rd(base + 4, 4);
                vaddr = rd(base + 8, 4);  filesz = rd(base + 16, 4);
                memsz = rd(base + 20, 4); flags = u32(rd(base + 24, 4));
            }
            sg.type = segTypeName(type); sg.flags = segFlags(flags);
            sg.vaddr = vaddr; sg.offset = offset; sg.filesz = filesz; sg.memsz = memsz;
            info.segments.push_back(sg);
            if (type == 2) { info.dynamicOff = offset; info.dynamicSz = filesz; }
        }
    }

    u64 base = ~u64(0);
    for (auto& sg : info.segments)
        if (sg.type == "LOAD") base = std::min(base, sg.vaddr);
    info.base = (base == ~u64(0)) ? 0 : base;

    // ---- symbols (SYMTAB + DYNSYM) ----
    for (size_t i = 0; i < raw.size(); ++i) {
        auto& s = raw[i];
        if (s.type != 2 && s.type != 11) continue;
        if (s.offset >= n || s.offset + s.size > n) continue;
        size_t ent = is64 ? 24 : 16;
        size_t cnt = s.size / ent;
        if (cnt > 200000) cnt = 200000;
        const u8* stb = nullptr; size_t stl = 0;
        if (s.link < raw.size()) {
            u64 so = raw[s.link].offset, sz = raw[s.link].size;
            if (so < n && so + sz <= n) { stb = p + so; stl = sz; }
        }
        if (s.type == 11) {
            info.dynSymNames.clear();
            info.dynSymNames.reserve(cnt);
        }
        for (size_t j = 0; j < cnt; ++j) {
            const u8* sp = p + s.offset + j * ent;
            u32 nameIdx; u64 value, sz64; u8 infoB; u16 shndx;
            if (is64) {
                nameIdx = R32(sp); infoB = sp[4]; shndx = R16(sp + 6);
                value = R64(sp + 8); sz64 = R64(sp + 16);
            } else {
                nameIdx = R32(sp); value = R32(sp + 4); sz64 = R32(sp + 8);
                infoB = sp[12]; shndx = R16(sp + 14);
            }
            Symbol sym;
            if (stb && nameIdx < stl)
                sym.name = readCString(stb + nameIdx, stl - nameIdx, 256);
            if (s.type == 11) info.dynSymNames.push_back(sym.name);
            u8 kind = infoB & 0xF, bind = infoB >> 4;
            sym.kind = kind == 1 ? "OBJECT" : kind == 2 ? "FUNC" : kind == 0 ? "NOTYPE" : "OTHER";
            sym.bind = bind == 1 ? "GLOBAL" : bind == 2 ? "WEAK" : "LOCAL";
            sym.addr = value; sym.size = sz64; sym.defined = (shndx != 0);

            if (isArm32) {
                // ARM ELF encodes Thumb-ness in bit 0 of st_value; the bit is an
                // addressing convention, not part of the address.
                if (kind == 2 && (value & 1)) { sym.thumb = true; sym.addr = value & ~u64(1); }
                // $a / $t / $d mapping symbols delimit ARM, Thumb and literal-pool
                // regions. They are the authoritative source for decode mode, so
                // collect them rather than guessing from function symbols alone.
                if (sym.name.size() >= 2 && sym.name[0] == '$' && kind != 2) {
                    char m = sym.name[1];
                    if ((m == 'a' || m == 't' || m == 'd') &&
                        (sym.name.size() == 2 || sym.name[2] == '.'))
                        info.armMapping.emplace_back(value & ~u64(1), m);
                }
            }
            info.symbols.push_back(sym);
            if (s.type == 11) {
                if (sym.defined && (bind == 1 || bind == 2) && !sym.name.empty())
                    info.exports.push_back(sym);
                if (!sym.defined && value == 0 && !sym.name.empty())
                    info.imports.push_back(sym);
            }
        }
    }

    // ---- relocations (.rela.dyn + .rela.plt) -> GOT slot name map ----
    for (size_t i = 0; i < raw.size(); ++i) {
        auto& s = raw[i];
        if (s.type != 4 && s.type != 9) continue;          // RELA / REL
        if (s.offset >= n || s.offset + s.size > n) continue;
        size_t ent = is64 ? (s.type == 4 ? 24u : 16u) : (s.type == 4 ? 12u : 8u);
        size_t cnt = s.size / ent;
        if (cnt > 300000) cnt = 300000;
        for (size_t j = 0; j < cnt; ++j) {
            const u8* rp = p + s.offset + j * ent;
            u64 rOff, rInfo; i64 rAdd = 0;
            if (s.type == 4) {
                if (is64) {
                    rOff = R64(rp); rInfo = R64(rp + 8); rAdd = i64(R64(rp + 16));
                } else {
                    rOff = R32(rp); rInfo = R32(rp + 4); rAdd = i64(i32(R32(rp + 8)));
                }
            } else {
                if (is64) { rOff = R64(rp); rInfo = R64(rp + 8); }
                else { rOff = R32(rp); rInfo = R32(rp + 4); }
            }
            if (s.type == 4) info.relas.push_back(Rela{rOff, rInfo, rAdd});
            u32 symIdx = u32(rInfo >> 32);
            u32 rtype = u32(rInfo & 0xFFFFFFFFu);
            (void)rtype;
            // resolve GOT slot -> dynsym name (JUMP_SLOT/GLOB_DAT/COPY/IRELATIVE)
            if (symIdx > 0 && symIdx < info.dynSymNames.size()) {
                const std::string& nm = info.dynSymNames[symIdx];
                if (!nm.empty()) info.gotNames[rOff] = nm;
            }
        }
    }

    // ---- PLT entry -> import name (decode stub code) ----
    {
        // find candidate PLT sections
        for (auto& sec : info.sections) {
            if (sec.size == 0 || sec.offset == 0 || sec.offset + sec.size > n) continue;
            bool isPlt = sec.name == ".plt" || sec.name == ".plt.sec" ||
                         sec.name == ".iplt" || sec.name == ".iplat";
            if (!isPlt) continue;
            u64 entrySize = 16;
            if (info.archEnum == "X86_64") {
                // x86-64: entry begins with push (0xFF 0x35..) or endbr64+jmp / jmp *[rip+d]
                for (u64 o = 0; o + 6 <= sec.size; o += entrySize) {
                    u64 va = sec.addr + o;
                    const u8* q = p + sec.offset + o;
                    // search for ff 25 (jmp [rip+disp32]) within the entry
                    for (int k = 0; k + 6 <= 16; ++k) {
                        if (q[k] == 0xFF && q[k + 1] == 0x25) {
                            i32 disp = i32(rd32(q + k + 2));
                            u64 got = va + u64(k) + 6 + u64(i64(disp));
                            auto it = info.gotNames.find(got);
                            if (it != info.gotNames.end()) info.pltNames[va] = it->second;
                            break;
                        }
                    }
                }
            } else if (info.archEnum == "ARM64") {
                for (u64 o = 0; o + 16 <= sec.size; o += entrySize) {
                    u64 va = sec.addr + o;
                    const u8* q = p + sec.offset + o;
                    u32 w0 = rd32(q), w1 = rd32(q + 4);
                    // adrp x16, page   (0b1 immlo 10000 immhi 10000 10000 = 0x90000010 mask 0x9F00001F)
                    if ((w0 & 0x9F00001F) == 0x90000010) {
                        i64 immhi = i64((w0 >> 5) & 0x7FFFF);
                        i64 immlo = i64((w0 >> 29) & 0x3);
                        i64 imm = (immhi << 2) | immlo;
                        if (imm & (1 << 20)) imm -= (1 << 21);
                        u64 page = (va & ~u64(0xFFF)) + u64(imm << 12);
                        // ldr x17, [x16, #imm]  mask 0xFFC003FF == 0xF9400200 with rn=x16(16) rt=x17(17)
                        if ((w1 & 0xFFC00000) == 0xF9400000) {
                            u32 rn = (w1 >> 5) & 0x1F;
                            u32 imm12 = ((w1 >> 10) & 0xFFF) * 8;
                            if (rn == 16) {
                                u64 got = page + imm12;
                                auto it = info.gotNames.find(got);
                                if (it != info.gotNames.end()) info.pltNames[va] = it->second;
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- dynamic: DT_NEEDED / DT_SONAME ----
    if (info.dynamicOff && info.dynamicSz && info.dynamicOff < n) {
        size_t ent = is64 ? 16 : 8;
        size_t cnt = info.dynamicSz / ent;
        if (cnt > 20000) cnt = 20000;
        u64 strtabVa = 0;
        std::vector<std::pair<u64, u64>> entries;
        for (size_t j = 0; j < cnt; ++j) {
            const u8* dp = p + info.dynamicOff + j * ent;
            u64 tag, val;
            if (is64) { tag = R64(dp); val = R64(dp + 8); }
            else { tag = R32(dp); val = R32(dp + 4); }
            if (tag == 0) break;
            if (tag == 5) strtabVa = val;
            entries.emplace_back(tag, val);
        }
        // map strtab vaddr -> file offset via LOAD segments
        const u8* stb = nullptr; size_t stl = 0;
        if (strtabVa) {
            for (auto& sg : info.segments) {
                if (sg.type == "LOAD" && strtabVa >= sg.vaddr && strtabVa < sg.vaddr + sg.filesz) {
                    u64 off = sg.offset + (strtabVa - sg.vaddr);
                    u64 sz = sg.filesz - (strtabVa - sg.vaddr);
                    if (off < n && off + sz <= n) { stb = p + off; stl = sz; }
                    break;
                }
            }
        }
        if (stb) {
            for (auto& e : entries) {
                if (e.first == 1) {
                    if (e.second < stl) info.needed.push_back(readCString(stb + e.second, stl - e.second, 256));
                } else if (e.first == 14) {
                    if (e.second < stl) info.soName = readCString(stb + e.second, stl - e.second, 256);
                }
            }
        }
    }

    // Mapping symbols arrive in symtab order; the decoder binary-searches them.
    if (!info.armMapping.empty()) {
        std::sort(info.armMapping.begin(), info.armMapping.end(),
                  [](const std::pair<u64, char>& a, const std::pair<u64, char>& b) {
                      return a.first < b.first;
                  });
        auto last = std::unique(info.armMapping.begin(), info.armMapping.end(),
                                [](const std::pair<u64, char>& a, const std::pair<u64, char>& b) {
                                    return a.first == b.first;
                                });
        info.armMapping.erase(last, info.armMapping.end());
    }

    info.ok = true;
    return info;
}

u64 elfVaToOff(const ElfInfo& e, u64 va) {
    for (auto& s : e.sections) {
        if (s.type == "NOBITS" || s.offset == 0) continue;
        if (va >= s.addr && va < s.addr + s.size) return s.offset + (va - s.addr);
    }
    for (auto& sg : e.segments) {
        if (sg.type != "LOAD") continue;
        if (va >= sg.vaddr && va < sg.vaddr + sg.filesz) return sg.offset + (va - sg.vaddr);
    }
    return ~u64(0);
}

const Section* elfSectionAt(const ElfInfo& e, u64 va) {
    const Section* best = nullptr;
    for (auto& s : e.sections) {
        if (va >= s.addr && va < s.addr + s.size) {
            if (!best || s.size < best->size) best = &s;
        }
    }
    return best;
}

bool elfExecRange(const ElfInfo& e, u64& va, u64& size) {
    bool found = false;
    for (auto& s : e.sections) {
        if (s.flags.find('X') != std::string::npos && s.type == "PROGBITS" && s.size > 0) {
            if (!found || s.size > size) { va = s.addr; size = s.size; found = true; }
        }
    }
    if (found && size > size_t(64) * 1024 * 1024) size = size_t(64) * 1024 * 1024;
    return found;
}

bool peExecRange(const PeInfo& e, u64& va, u64& size) {
    bool found = false;
    for (auto& s : e.sections) {
        if (s.flags.find('X') != std::string::npos && s.size > 0) {
            if (!found || s.size > size) { va = s.addr; size = s.size; found = true; }
        }
    }
    if (found && size > size_t(64) * 1024 * 1024) size = size_t(64) * 1024 * 1024;
    return found;
}

} // namespace sako
