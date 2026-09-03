// Sako RE Studio — common types & helpers
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <memory>

namespace sako {

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

// ---- little-endian readers ----
inline u16 rd16(const u8* p) { return u16(p[0]) | (u16(p[1]) << 8); }
inline u32 rd32(const u8* p) { return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24); }
inline u64 rd64(const u8* p) { return u64(rd32(p)) | (u64(rd32(p + 4)) << 32); }
inline u32 rd24(const u8* p) { return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16); }
inline u32 rd32be(const u8* p) { return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | p[3]; }

inline bool printable(u8 c) { return c >= 0x20 && c < 0x7F; }
// Sign-extend the low `bits` bits of v (masks first, so already-extended
// inputs are handled correctly — fixes the v1 off-by-2^32 xref bug).
inline i64  sext(i64 v, int bits) {
    u64 mask = (u64(1) << bits) - 1;
    u64 vv = u64(v) & mask;
    u64 m = u64(1) << (bits - 1);
    return i64((vv ^ m) - m);
}

std::string readCString(const u8* p, size_t avail, size_t maxLen = 512);
std::string hexAddr(u64 v);
std::string jsonEscape(const std::string& s);
std::string humanSize(u64 n);

// ---- loaded binary ----
struct Binary {
    std::vector<u8> data;
    std::string path, name;
    u64  fullSize = 0;
    bool truncated = false;
};

enum class Fmt { Unknown, ELF, PE, DEX, MachO, ZIP };
const char* fmtName(Fmt f);
Fmt detectFormat(const u8* p, size_t n);

struct FoundString { u64 addr = 0; std::string value; };

// ---- loader result types ----
struct Section { std::string name, type, flags; u64 addr = 0, offset = 0, size = 0; };
struct Segment { std::string type, flags; u64 vaddr = 0, offset = 0, filesz = 0, memsz = 0; };
struct Symbol  { std::string name, kind, bind; u64 addr = 0, size = 0; bool defined = false; };

struct Rela { u64 off = 0, info = 0; i64 addend = 0; };

struct ElfInfo {
    bool ok = false;
    std::string error;
    int bits = 64;
    std::string archName, archEnum;   // "AArch64"/"ARM64" etc
    u64 entry = 0, base = 0;
    u32 eFlags = 0;
    u64 dynamicOff = 0, dynamicSz = 0;
    std::vector<Section> sections;
    std::vector<Segment> segments;
    std::vector<Symbol>  symbols;     // symtab + dynsym
    std::vector<Symbol>  imports;     // undefined dynsym
    std::vector<Symbol>  exports;     // defined global/weak dynsym
    std::vector<std::string> needed;
    std::string soName;
    // v2: import resolution
    std::vector<Rela> relas;                    // .rela.dyn + .rela.plt
    std::vector<std::string> dynSymNames;       // dynsym index -> name
    std::map<u64, std::string> gotNames;        // GOT slot VA -> symbol
    std::map<u64, std::string> pltNames;        // PLT entry VA -> symbol
};

struct PeInfo {
    bool ok = false;
    std::string error;
    std::string archName, archEnum;   // "x86-64"/"X86_64"
    u64 entry = 0, imageBase = 0;
    std::vector<Section> sections;
    std::vector<Symbol>  imports;
    std::vector<Symbol>  exports;
};

struct DexMethod { std::string clazz, name, proto; u64 codeOff = 0; };
struct DexClass { std::string name, super; };
struct DexInfo {
    bool ok = false;
    std::string error;
    std::vector<std::string> strings;
    std::vector<DexMethod> methods;
    std::vector<DexClass>  classes;
};

// ---- analysis types ----
struct AsmLine { u64 addr = 0; std::string bytes, mnem, ops, comment; };
struct CfgBlock { int id = 0; u64 start = 0, end = 0; int nInstr = 0; std::vector<int> succ; };
struct Xref { u64 from = 0, to = 0; std::string type; };
struct FuncInfo { u64 addr = 0, size = 0; std::string name, from; };

struct FunctionDetail {
    bool ok = false;
    std::string error, name;
    u64 addr = 0, size = 0;
    std::vector<AsmLine> asmLines;
    std::string pseudo;
    std::vector<CfgBlock> blocks;
    std::vector<Xref> inRefs, outRefs;
};

// printable-ASCII string scan over a byte range
std::vector<FoundString> extractPrintableStrings(const u8* p, size_t n, u64 vaddrBase,
                                                 size_t cap = 3000, size_t minLen = 4);

} // namespace sako
