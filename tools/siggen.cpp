// siggen — generate a Nocturne library-function signature database from a real
// static library (.a) or relocatable object (.o), the way IDA's sigmake builds
// a FLIRT .sig from a .lib.
//
// This is the WRITER half of the recognition feature. It is a self-contained
// host tool (parses `ar` archives and ELF relocatable objects itself; needs
// only the C++ standard library and the shared format header) so it can run on
// a build machine — this host today, the NDK's bionic/libc++ static libs at CI
// in phase 2 — and emit a .nsig the engine's matcher (LibSigFormat.h, shared
// verbatim) reads.
//
// The idea, in one paragraph: the same function linked into two programs does
// not have the same bytes, because the linker fills relocations (call targets,
// PC-relative and absolute addresses) with values that depend on the layout.
// A relocatable object still carries its relocation table, so it says EXACTLY
// which byte ranges vary. We read those, wildcard precisely them, and build a
// signature from what is left: a 32-byte masked prefix, the exact length, and a
// CRC32 over the whole body with the variant bytes canonicalised to zero.
//
// Usage:
//   siggen <output.nsig> <input1.a|.o> [input2 ...] [--min-len N] [--verbose]
//
// Build (host):
//   g++ -std=c++17 -O2 siggen.cpp -o siggen
#include "../app/src/main/cpp/sako/LibSigFormat.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>

using namespace libsig;

// ------------------------------------------------------------------ ELF types
// ELF machine / section / symbol / relocation constants. Only what a
// relocatable object on x86-64/x86/arm64/arm needs.
enum { EM_386 = 3, EM_ARM = 40, EM_X86_64 = 62, EM_AARCH64 = 183 };
enum { SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4, SHT_REL = 9 };
enum { SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4 };
enum { STT_FUNC = 2, STT_GNU_IFUNC = 10 };
enum { SHN_UNDEF = 0, SHN_LORESERVE = 0xff00 };

static uint16_t rd16(const uint8_t* p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
static uint32_t rd32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
static uint64_t rd64(const uint8_t* p) { return uint64_t(rd32(p)) | (uint64_t(rd32(p + 4)) << 32); }

// How many bytes a relocation of this (machine,type) makes vary, and how many
// bytes BEFORE r_offset also vary. The pre-offset covers linker relaxation,
// which on x86-64 rewrites the opcode/modrm in front of a GOTPCREL displacement
// (mov ...@GOTPCREL(%rip) -> lea), i.e. bytes the reloc's own field does not name.
static void relocSpan(int machine, uint32_t type, uint32_t& width, uint32_t& pre, bool& known) {
    width = 4; pre = 0; known = true;
    if (machine == EM_X86_64) {
        switch (type) {
            case 1:  width = 8; break;                 // R_X86_64_64
            case 2:  width = 4; break;                 // R_X86_64_PC32
            case 4:  width = 4; break;                 // R_X86_64_PLT32
            case 9:  width = 4; pre = 2; break;        // R_X86_64_GOTPCREL
            case 10: case 11: width = 4; break;        // R_X86_64_32 / 32S
            case 12: width = 2; break;                 // R_X86_64_16
            case 14: width = 1; break;                 // R_X86_64_8
            case 13: width = 2; break;                 // R_X86_64_PC16
            case 15: width = 1; break;                 // R_X86_64_PC8
            case 19: case 20: width = 4; break;        // R_X86_64_TLSGD / TLSLD
            case 21: width = 4; break;                 // R_X86_64_DTPOFF32
            case 22: width = 4; pre = 3; break;        // R_X86_64_GOTTPOFF (IE->LE relaxable)
            case 23: width = 4; break;                 // R_X86_64_TPOFF32
            case 24: width = 8; break;                 // R_X86_64_PC64
            case 26: width = 4; break;                 // R_X86_64_GOTPC32
            case 41: width = 4; pre = 2; break;        // R_X86_64_GOTPCRELX
            case 42: width = 4; pre = 3; break;        // R_X86_64_REX_GOTPCRELX (REX before)
            default: known = false; break;
        }
    } else if (machine == EM_386) {
        switch (type) {
            case 1: case 2: case 3: case 4: case 9: case 10: case 11: width = 4; break;
            case 43: width = 4; pre = 1; break;        // R_386_GOT32X (may relax)
            case 20: width = 2; break;                 // R_386_16
            case 22: width = 1; break;                 // R_386_8
            default: known = false; break;
        }
    } else if (machine == EM_AARCH64) {
        // Every code relocation modifies exactly one 32-bit instruction word at
        // the (4-aligned) r_offset: CALL26, JUMP26, ADR_PREL_PG_HI21,
        // ADD_ABS_LO12_NC, LDST*_ABS_LO12_NC, ADR_GOT_PAGE, LD64_GOT_LO12_NC, TLS.
        // ABS64 (257) only appears in data words, never in .text instructions.
        width = 4;
        known = (type == 257 /*ABS64, data*/ || type == 258 /*ABS32*/ ||
                 (type >= 274 && type <= 320) /*the PREL/GOT/LDST/TLS instruction block*/ ||
                 type == 282 || type == 283);
        if (type == 257) width = 8;
    } else if (machine == EM_ARM) {
        width = 4;                                     // one word (ABS32 literal, CALL, MOVW/T, THM_CALL)
        known = (type == 1 || type == 2 || type == 3 || type == 10 || type == 28 ||
                 type == 29 || type == 42 || type == 43 || type == 44 ||
                 type == 48 || type == 49);
    } else {
        known = false;
    }
}

static ArchId archOf(int machine) {
    switch (machine) {
        case EM_X86_64:  return ARCH_X86_64;
        case EM_386:     return ARCH_X86;
        case EM_AARCH64: return ARCH_ARM64;
        case EM_ARM:     return ARCH_ARM;
        default:         return ARCH_UNKNOWN;
    }
}

// ------------------------------------------------------- per-location signature
// One function location in one object, with its aliases folded into a single
// chosen name.
struct RawSig {
    ArchId arch;
    uint32_t total_len;
    uint32_t full_crc;
    uint32_t pmask;
    uint8_t  plen;
    uint8_t  pat[kPatMax];
    std::vector<VarRange> vars;
    std::string name;
};

// Rank a symbol name for choosing among aliases at one location: prefer public
// names (fewer leading underscores, not glibc-internal __GI_/__EI_ aliases),
// then shorter, then lexicographic for determinism. A smaller score wins.
static long nameScore(const std::string& n) {
    long score = 0;
    size_t us = 0; while (us < n.size() && n[us] == '_') ++us;
    score += long(us) * 1000;                         // leading underscores dominate
    if (n.rfind("__GI_", 0) == 0) score += 5000;      // glibc internal alias
    if (n.rfind("__EI_", 0) == 0) score += 5000;
    score += long(n.size());                          // shorter is cleaner
    return score;
}
static bool betterName(const std::string& a, const std::string& b) {  // is a better than b?
    long sa = nameScore(a), sb = nameScore(b);
    if (sa != sb) return sa < sb;
    return a < b;
}

// Merge sorted variant ranges that touch or overlap.
static void mergeVars(std::vector<VarRange>& v) {
    if (v.empty()) return;
    std::sort(v.begin(), v.end(), [](const VarRange& a, const VarRange& b) { return a.off < b.off; });
    std::vector<VarRange> out;
    out.push_back(v[0]);
    for (size_t i = 1; i < v.size(); ++i) {
        VarRange& last = out.back();
        uint32_t lastEnd = last.off + last.len;
        if (v[i].off <= lastEnd) {
            uint32_t end = std::max(lastEnd, uint32_t(v[i].off) + v[i].len);
            last.len = uint16_t(end - last.off);
        } else out.push_back(v[i]);
    }
    v.swap(out);
}

// Counters, reported at the end — honest, two-number style.
struct Stats {
    size_t objects = 0, objSkipped = 0;
    size_t funcSyms = 0, locations = 0, emitted = 0;
    size_t tooShort = 0, tooFewFixed = 0, tooManyVars = 0, badArch = 0;
    size_t records = 0, ambiguous = 0, aliasesFolded = 0;
    std::map<std::string, size_t> unknownReloc;   // "arch:type" -> count
};

// ------------------------------------------------------------- ELF .o parser
// Parse one relocatable ELF object (64- or 32-bit little-endian) and append its
// per-location signatures. Reads section headers, the symbol table, and the
// relocation sections; masks the relocated byte ranges.
static void parseObject(const uint8_t* d, size_t n, uint32_t minLen, uint32_t minFixed,
                        std::vector<RawSig>& out, Stats& st, bool verbose) {
    if (n < 64 || std::memcmp(d, "\x7f""ELF", 4) != 0) { st.objSkipped++; return; }
    int cls = d[4];                     // 1 = 32-bit, 2 = 64-bit
    int data = d[5];                    // 1 = LE, 2 = BE
    if (data != 1) { st.objSkipped++; return; }         // these host libs are LE
    bool is64 = (cls == 2);
    int machine = rd16(d + 18);
    ArchId arch = archOf(machine);
    if (arch == ARCH_UNKNOWN) { st.objSkipped++; st.badArch++; return; }

    // section header table (the section-name string table index is not needed:
    // functions are found by section type/flags and the symbol table, not names)
    uint64_t shoff; uint16_t shentsize, shnum;
    if (is64) {
        shoff = rd64(d + 40); shentsize = rd16(d + 58); shnum = rd16(d + 60);
    } else {
        shoff = rd32(d + 32); shentsize = rd16(d + 46); shnum = rd16(d + 48);
    }
    if (!shoff || !shnum || shoff + uint64_t(shnum) * shentsize > n) { st.objSkipped++; return; }

    struct Sec { uint32_t type, link, info, name; uint64_t flags, off, size, entsize; };
    std::vector<Sec> secs(shnum);
    for (int i = 0; i < shnum; ++i) {
        const uint8_t* s = d + shoff + uint64_t(i) * shentsize;
        Sec& S = secs[i];
        S.name = rd32(s + 0);
        S.type = rd32(s + 4);
        if (is64) {
            S.flags = rd64(s + 8); S.off = rd64(s + 24); S.size = rd64(s + 32);
            S.link = rd32(s + 40); S.info = rd32(s + 44); S.entsize = rd64(s + 56);
        } else {
            S.flags = rd32(s + 8); S.off = rd32(s + 16); S.size = rd32(s + 20);
            S.link = rd32(s + 24); S.info = rd32(s + 28); S.entsize = rd32(s + 36);
        }
    }
    auto secBytes = [&](int i) -> const uint8_t* {
        if (i < 0 || i >= shnum) return nullptr;
        if (secs[i].off + secs[i].size > n) return nullptr;
        return d + secs[i].off;
    };

    // Which sections are executable code we build signatures from.
    auto isExecCode = [&](int i) {
        return i >= 0 && i < shnum && secs[i].type == SHT_PROGBITS &&
               (secs[i].flags & SHF_EXECINSTR) && secs[i].size > 0;
    };

    // Per-code-section relocation lists: (funcRel handled later), stored raw.
    struct Reloc { uint64_t off; uint32_t type; };
    std::unordered_map<int, std::vector<Reloc>> relocsBySec;
    for (int i = 0; i < shnum; ++i) {
        if (secs[i].type != SHT_RELA && secs[i].type != SHT_REL) continue;
        int target = int(secs[i].info);
        if (!isExecCode(target)) continue;
        const uint8_t* r = secBytes(i);
        if (!r) continue;
        bool rela = (secs[i].type == SHT_RELA);
        uint64_t ent = secs[i].entsize;
        if (!ent) ent = is64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
        uint64_t cnt = secs[i].size / ent;
        auto& vec = relocsBySec[target];
        for (uint64_t k = 0; k < cnt; ++k) {
            const uint8_t* e = r + k * ent;
            Reloc R;
            uint64_t info;
            if (is64) { R.off = rd64(e + 0); info = rd64(e + 8); R.type = uint32_t(info & 0xFFFFFFFFu); }
            else      { R.off = rd32(e + 0); info = rd32(e + 4); R.type = uint32_t(info & 0xFFu); }
            vec.push_back(R);
        }
        std::sort(vec.begin(), vec.end(), [](const Reloc& a, const Reloc& b) { return a.off < b.off; });
    }

    // symbol table + its string table
    int symIdx = -1;
    for (int i = 0; i < shnum; ++i) if (secs[i].type == SHT_SYMTAB) { symIdx = i; break; }
    if (symIdx < 0) { st.objSkipped++; return; }
    const uint8_t* symData = secBytes(symIdx);
    const uint8_t* strData = secBytes(int(secs[symIdx].link));
    uint64_t strSize = (int(secs[symIdx].link) < shnum) ? secs[secs[symIdx].link].size : 0;
    if (!symData || !strData) { st.objSkipped++; return; }
    uint64_t symEnt = is64 ? 24 : 16;
    uint64_t nsym = secs[symIdx].size / symEnt;
    auto symName = [&](uint32_t nameOff) -> std::string {
        if (nameOff >= strSize) return std::string();
        const char* s = reinterpret_cast<const char*>(strData + nameOff);
        size_t maxLen = size_t(strSize - nameOff);
        return std::string(s, strnlen(s, maxLen));
    };

    st.objects++;

    // Fold aliases: symbols at the same (section, value) are the same function.
    struct Loc { std::string best; };
    std::map<std::pair<int, uint64_t>, Loc> locs;         // (shndx,value) -> chosen name
    std::map<std::pair<int, uint64_t>, uint64_t> locSize; // (shndx,value) -> size

    for (uint64_t i = 0; i < nsym; ++i) {
        const uint8_t* s = symData + i * symEnt;
        uint32_t nameOff; uint8_t info; uint16_t shndx; uint64_t value, size;
        if (is64) {
            nameOff = rd32(s + 0); info = s[4]; shndx = rd16(s + 6); value = rd64(s + 8); size = rd64(s + 16);
        } else {
            nameOff = rd32(s + 0); value = rd32(s + 4); size = rd32(s + 8); info = s[12]; shndx = rd16(s + 14);
        }
        int type = info & 0xF;
        if (type != STT_FUNC && type != STT_GNU_IFUNC) continue;
        if (shndx == SHN_UNDEF || shndx >= SHN_LORESERVE) continue;
        if (!isExecCode(int(shndx))) continue;
        if (size == 0) continue;
        std::string nm = symName(nameOff);
        if (nm.empty()) continue;
        st.funcSyms++;
        auto key = std::make_pair(int(shndx), value);
        auto it = locs.find(key);
        if (it == locs.end()) { locs[key] = Loc{nm}; locSize[key] = size; }
        else { st.aliasesFolded++; if (betterName(nm, it->second.best)) it->second.best = nm;
               if (size > locSize[key]) locSize[key] = size; }
    }

    for (auto& kv : locs) {
        int shndx = kv.first.first;
        uint64_t value = kv.first.second;
        uint64_t size = locSize[kv.first];
        st.locations++;
        const uint8_t* secData = secBytes(shndx);
        if (!secData) continue;
        if (value + size > secs[shndx].size) continue;    // symbol runs past its section
        if (size < minLen) { st.tooShort++; continue; }
        const uint8_t* fn = secData + value;

        // variant ranges from this section's relocations that fall in the function
        std::vector<VarRange> vars;
        auto rit = relocsBySec.find(shndx);
        if (rit != relocsBySec.end()) {
            for (auto& R : rit->second) {
                if (R.off < value || R.off >= value + size) continue;
                uint32_t width, pre; bool known;
                relocSpan(machine, R.type, width, pre, known);
                if (!known) st.unknownReloc[std::string(archName(arch)) + ":" + std::to_string(R.type)]++;
                int64_t start = int64_t(R.off - value) - int64_t(pre);
                if (start < 0) start = 0;
                int64_t end = int64_t(R.off - value) + int64_t(width);
                if (end > int64_t(size)) end = int64_t(size);
                if (end > start) vars.push_back(VarRange{ uint32_t(start), uint16_t(end - start) });
            }
        }
        mergeVars(vars);
        if (vars.size() > kVarMax) { st.tooManyVars++; continue; }

        // Enough INVARIANT bytes to be discriminating. A short function that is
        // mostly a masked call (a thin wrapper) has few fixed bytes and is the
        // main source of false positives — its CRC constrains almost nothing.
        // Gating on fixed-byte count, not just total length, drops exactly those
        // while keeping short-but-solid leaf functions.
        uint64_t varBytes = 0;
        for (auto& vr : vars) varBytes += vr.len;
        if (size < varBytes || (size - varBytes) < minFixed) { st.tooFewFixed++; continue; }

        RawSig rs;
        rs.arch = arch;
        rs.total_len = uint32_t(size);
        rs.vars = vars;
        buildPattern(fn, rs.total_len, vars, rs.pat, rs.pmask, rs.plen);
        rs.full_crc = crc32Canon(fn, rs.total_len, vars);
        rs.name = kv.second.best;
        out.push_back(std::move(rs));
        st.emitted++;
    }
    if (verbose)
        fprintf(stderr, "  object: %s, %zu locations so far\n", archName(arch), st.locations);
}

// ------------------------------------------------------------- ar archive
// Minimal GNU `ar` reader: walk members, resolve the long-name string table,
// hand each ELF member to parseObject.
static bool parseArchive(const uint8_t* d, size_t n, uint32_t minLen, uint32_t minFixed,
                         std::vector<RawSig>& out, Stats& st, bool verbose) {
    static const char kAr[] = "!<arch>\n";
    if (n < 8 || std::memcmp(d, kAr, 8) != 0) return false;   // not an archive
    size_t p = 8;
    const uint8_t* longNames = nullptr; size_t longNamesSz = 0;
    while (p + 60 <= n) {
        const uint8_t* h = d + p;
        char name[17]; std::memcpy(name, h, 16); name[16] = 0;
        char sizeStr[11]; std::memcpy(sizeStr, h + 48, 10); sizeStr[10] = 0;
        uint64_t msize = strtoull(sizeStr, nullptr, 10);
        size_t body = p + 60;
        if (body + msize > n) break;
        const uint8_t* mdata = d + body;

        std::string mname(name);
        // trim trailing spaces
        while (!mname.empty() && mname.back() == ' ') mname.pop_back();

        if (mname == "//") {                       // GNU long-name string table
            longNames = mdata; longNamesSz = size_t(msize);
        } else if (mname == "/" || mname == "/SYM64/") {
            // symbol index — skip
        } else {
            std::string real = mname;
            if (!mname.empty() && mname[0] == '/' && mname.size() > 1 && longNames) {
                size_t off = strtoull(mname.c_str() + 1, nullptr, 10);
                if (off < longNamesSz) {
                    const char* s = reinterpret_cast<const char*>(longNames + off);
                    size_t mx = longNamesSz - off;
                    size_t len = 0; while (len < mx && s[len] != '\n' && s[len] != '/') ++len;
                    real.assign(s, len);
                }
            } else if (!real.empty() && real.back() == '/') {
                real.pop_back();                    // GNU appends '/' to short names
            }
            parseObject(mdata, size_t(msize), minLen, minFixed, out, st, verbose);
        }
        p = body + msize;
        if (msize & 1) ++p;                         // members are 2-byte aligned
    }
    return true;
}

// -------------------------------------------------------------------- main
static std::vector<uint8_t> readFile(const char* path) {
    std::vector<uint8_t> v;
    FILE* f = std::fopen(path, "rb");
    if (!f) return v;
    std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    if (sz > 0) { v.resize(size_t(sz)); if (std::fread(v.data(), 1, v.size(), f) != v.size()) v.clear(); }
    std::fclose(f);
    return v;
}

int main(int argc, char** argv) {
    std::vector<std::string> inputs;
    std::string outPath;
    uint32_t minLen = kDefaultMinLen;
    uint32_t minFixed = 16;   // minimum invariant (non-wildcard) bytes; the precision knob
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--min-len" && i + 1 < argc) minLen = uint32_t(atoi(argv[++i]));
        else if (a == "--min-fixed" && i + 1 < argc) minFixed = uint32_t(atoi(argv[++i]));
        else if (a == "--verbose") verbose = true;
        else if (outPath.empty()) outPath = a;
        else inputs.push_back(a);
    }
    if (outPath.empty() || inputs.empty()) {
        fprintf(stderr, "usage: siggen <out.nsig> <in.a|.o> [more...] "
                        "[--min-len N] [--min-fixed N] [--verbose]\n");
        return 2;
    }

    Stats st;
    std::vector<RawSig> raw;
    for (auto& in : inputs) {
        std::vector<uint8_t> buf = readFile(in.c_str());
        if (buf.empty()) { fprintf(stderr, "cannot read %s\n", in.c_str()); continue; }
        if (!parseArchive(buf.data(), buf.size(), minLen, minFixed, raw, st, verbose))
            parseObject(buf.data(), buf.size(), minLen, minFixed, raw, st, verbose);   // a lone .o
    }

    // Group per-location signatures by canonical form; fold same-named
    // duplicates, flag genuine collisions (same form, different function).
    struct Group { RawSig rep; std::vector<std::string> names; };
    std::map<std::string, Group> groups;
    for (auto& rs : raw) {
        std::string key;
        key.push_back(char(rs.arch));
        key.append(reinterpret_cast<const char*>(&rs.total_len), 4);
        key.append(reinterpret_cast<const char*>(&rs.full_crc), 4);
        key.append(reinterpret_cast<const char*>(&rs.pmask), 4);
        key.push_back(char(rs.plen));
        key.append(reinterpret_cast<const char*>(rs.pat), rs.plen);
        auto it = groups.find(key);
        if (it == groups.end()) { Group g; g.rep = rs; g.names.push_back(rs.name); groups[key] = std::move(g); }
        else {
            bool seen = false;
            for (auto& nm : it->second.names) if (nm == rs.name) { seen = true; break; }
            if (!seen) it->second.names.push_back(rs.name);
        }
    }

    // Serialise.
    std::vector<uint8_t> ser;
    for (auto& kv : groups) {
        Group& g = kv.second;
        RawSig& rs = g.rep;
        bool ambiguous = g.names.size() > 1;
        // pick the best chosen name deterministically (only used when not ambiguous)
        std::string best = g.names[0];
        for (auto& nm : g.names) if (betterName(nm, best)) best = nm;
        if (ambiguous) st.ambiguous++;
        st.records++;

        uint8_t nvar = uint8_t(rs.vars.size());
        ser.push_back(uint8_t(rs.arch));
        ser.push_back(uint8_t(rs.plen));
        ser.push_back(ambiguous ? uint8_t(FLAG_AMBIGUOUS) : 0);
        ser.push_back(nvar);
        wrLE32(ser, rs.total_len);
        wrLE32(ser, rs.full_crc);
        wrLE32(ser, rs.pmask);
        ser.insert(ser.end(), rs.pat, rs.pat + kPatMax);
        wrLE16(ser, uint16_t(best.size()));
        for (uint8_t v = 0; v < nvar; ++v) { wrLE32(ser, rs.vars[v].off); wrLE16(ser, rs.vars[v].len); }
        ser.insert(ser.end(), best.begin(), best.end());
    }

    std::vector<uint8_t> file;
    file.insert(file.end(), kMagic, kMagic + 8);
    wrLE32(file, kVersion);
    wrLE32(file, uint32_t(st.records));
    wrLE32(file, 0);   // flags
    wrLE32(file, 0);   // reserved
    file.insert(file.end(), ser.begin(), ser.end());

    FILE* out = std::fopen(outPath.c_str(), "wb");
    if (!out) { fprintf(stderr, "cannot write %s\n", outPath.c_str()); return 1; }
    std::fwrite(file.data(), 1, file.size(), out);
    std::fclose(out);

    // Report — two numbers, never one.
    fprintf(stderr,
        "siggen: objects=%zu (skipped %zu)  funcSyms=%zu  aliasesFolded=%zu\n"
        "        locations=%zu  emitted=%zu  (tooShort=%zu tooFewFixed=%zu tooManyVars=%zu badArch=%zu)\n"
        "        records=%zu of which ambiguous=%zu  minLen=%u minFixed=%u\n"
        "        file=%s  bytes=%zu\n",
        st.objects, st.objSkipped, st.funcSyms, st.aliasesFolded,
        st.locations, st.emitted, st.tooShort, st.tooFewFixed, st.tooManyVars, st.badArch,
        st.records, st.ambiguous, minLen, minFixed, outPath.c_str(), file.size());
    if (!st.unknownReloc.empty()) {
        fprintf(stderr, "        unknown reloc types (masked at default width): ");
        for (auto& u : st.unknownReloc) fprintf(stderr, "%s(x%zu) ", u.first.c_str(), u.second);
        fprintf(stderr, "\n");
    }
    return 0;
}
