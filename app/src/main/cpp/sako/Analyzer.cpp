#include "Analysis.h"
#include <set>
#include <cstring>

namespace sako {

// ---------------- function discovery ----------------
// There is no cap here, by decision: the scan carries every function it finds,
// to the end of the binary. It used to stop at 4000, which on a real library
// (the 12631-function sample quoted in Analysis.h, or the 37801 of
// libLLVM-17.so) left two thirds of the image not truncated in one answer but
// ABSENT from the engine -- no xrefs, no call-graph node, no name for a
// pointer into it, and no way for the caller to learn any of that was missing.
//
// Nor is there a gate. The linear scan used to run only `if (byAddr.size() < 8)`
// -- and every real stripped Android .so keeps its .dynsym, so it has hundreds
// of symbols and the scan never ran at all. What the user saw was the export
// list wearing the name "functions": libcrypto.so.3 answered 5363 with its
// dynsym intact and 16984 with the symbol tables removed, from the same bytes.
// The scan now ALWAYS runs, and merges with the symbol table instead of
// standing in for it.
//
// What carrying all of them costs, per function, read off this code and
// measured on a host build (libLLVM-17.so.1, 123 MB, 37801 functions):
//
//   FuncInfo + the AddrNames entry   ~180 B of heap each -> 200k is ~36 MB
//   buildCallGraph                   funcAt/funcSet are ordered maps, so a
//                                    call site costs O(log F), not O(F)
//   analyze() JSON row               ~100 B stripped, ~210 B for C++ symbols
//                                    with a demangled form -- which is why the
//                                    JSON list is PAGED rather than capped
//                                    (see kFunctionsPerPage in Engine.cpp):
//                                    paging withholds nothing, a cap does
//   computeJniEnvArgs                ARM64, first decompile, background
//                                    thread: one disassembly pass over every
//                                    carried function, so it now covers .text
//   plugins                          a per-function plugin does as much work
//                                    as the binary has functions, which is
//                                    what it was asked to do
//
// `found` is still reported by both scans and still means "what the scan
// found". It equals the returned size today; it stays so that if a limit ever
// does come back it cannot come back silently.
//
// ---- what the scan accepts, and why ----
//
// A prologue-pattern scan over raw bytes finds things that are not functions:
// jump tables, literal pools, and data that happens to read as a frame setup.
// Measured on llvm8-aarch64.so -- 13 MB of .text, 27434 function symbols kept
// aside as ground truth, then every symbol table removed so only the scan
// speaks:
//
//   bl targets                          6555 found,    0 wrong
//   relative-relocation targets in code 5359 found,    0 wrong
//   adrp+add targets in code             723 found,    2 wrong
//   prologue word, anywhere            20465 found, 1218 wrong  (5.9%)
//   prologue word after a terminator   17511 found,  109 wrong  (0.6%)
//
// The last two lines are the whole design. A function's first instruction
// cannot be reached by falling through from the instruction before it: that
// instruction has to be a return, a branch, a trap, padding, or a call that
// does not come back. Requiring it costs 7 points of recall and removes 91% of
// the false positives. A plain linear sweep, for comparison, reaches 98%
// recall at 17% precision, which is not a function list.
//
// End to end, on four libraries with a full symbol table held back as truth:
//
//                                      functions   wrong   of truth
//   llvm8-aarch64      no symbols       23000      0.48%     83.4%
//   llvm8-aarch64      .dynsym only     27374      0.08%     99.7%
//   rellic-deps arm64  no symbols       48501      0.51%     85.5%
//   rellic-deps arm64  .dynsym only     56036      0.12%     99.2%
//   x86-64 C++ .so     no symbols         751      0.67%     81.9%
//   x86-64 C++ .so     no symbols        7440      0.85%     80.8%
//
// The ".dynsym only" rows are the case that matters: a stripped Android .so
// still exports, and those two rows are the difference between answering with
// the export list and answering with the binary.
//
// The x86 rules are not the AArch64 rules, because x86 has no instruction
// grid to scan. endbr64 looks like a function marker and is not one --
// -fcf-protection also plants one at every indirect-branch target, so on the
// 911-function object above it appears 2536 times for 468 function starts,
// 18% precision. Anchored to the inter-function padding in front of it, the
// same instruction is 99.6%. That anchor, not the opcode, is the signal.

namespace {

struct ExecSec { u64 va = 0, size = 0, off = 0; };

inline bool isPltSection(const std::string& n) {
    return n.rfind(".plt", 0) == 0 || n == ".iplt" || n == ".iplat";
}

// Every executable range the file actually maps, so the scan never reads a
// byte of .rodata and calls it a prologue. Sections first, because they name
// the PLT (whose entries are import stubs, not functions); PT_LOAD segments
// when the section headers are gone, which is what a hostile .so ships.
std::vector<ExecSec> elfExecSecs(const Binary& b, const ElfInfo& e) {
    std::vector<ExecSec> v;
    auto add = [&](u64 va, u64 size, u64 off) {
        if (!size || off == ~u64(0) || off + size > b.data.size()) return;
        v.push_back(ExecSec{va, size, off});
    };
    for (auto& s : e.sections) {
        if (s.type != "PROGBITS" || !s.size) continue;
        if (s.flags.find('X') == std::string::npos) continue;
        if (isPltSection(s.name)) continue;
        add(s.addr, s.size, s.offset ? s.offset : elfVaToOff(e, s.addr));
    }
    if (v.empty()) {
        for (auto& sg : e.segments) {
            if (sg.type != "LOAD" || !sg.filesz) continue;
            if (sg.flags.find('X') == std::string::npos) continue;
            add(sg.vaddr, sg.filesz, sg.offset);
        }
    }
    if (v.empty()) {   // last resort: whatever elfExecRange can still name
        u64 va = 0, size = 0;
        if (elfExecRange(e, va, size)) add(va, size, elfVaToOff(e, va));
    }
    std::sort(v.begin(), v.end(), [](const ExecSec& a, const ExecSec& c) { return a.va < c.va; });
    return v;
}

const ExecSec* execSecOf(const std::vector<ExecSec>& v, u64 a) {
    for (auto& s : v) if (a >= s.va && a < s.va + s.size) return &s;
    return nullptr;
}

// R_*_RELATIVE for the architectures this engine loads. 0 = "don't know", and
// then no relocation is trusted as a code pointer.
u32 relativeRelocType(const std::string& arch) {
    if (arch == "ARM64") return 1027;          // R_AARCH64_RELATIVE
    if (arch == "X86_64") return 8;            // R_X86_64_RELATIVE
    if (arch == "X86") return 8;               // R_386_RELATIVE
    if (arch == "ARM") return 23;              // R_ARM_RELATIVE
    if (arch.rfind("PPC", 0) == 0) return 22;  // R_PPC[64]_RELATIVE
    return 0;
}

// Addresses of functions nothing calls directly: vtable slots, .init_array,
// function-pointer tables. On a position-independent object -- every Android
// .so -- each of those is a relative relocation whose addend is the function.
// Without this a C++ library's virtual methods are invisible unless some call
// site happens to reach them statically.
void relocCodeTargets(const Binary& b, const ElfInfo& e,
                      const std::vector<ExecSec>& execs, std::set<u64>& out) {
    u32 want = relativeRelocType(e.archEnum);
    if (!want) return;
    const bool is64 = e.bits == 64;
    const bool be = e.bigEndian;
    auto rdN = [&](u64 off, int width) -> u64 {
        const u8* q = b.data.data() + off;
        if (width == 8) return be ? rd64be(q) : rd64(q);
        return be ? u64(rd32be(q)) : u64(rd32(q));
    };

    // RELA: the addend is the target outright. The loader already parsed these.
    for (auto& r : e.relas) {
        u32 t = is64 ? u32(r.info & 0xFFFFFFFFu) : u32(r.info & 0xFFu);
        if (t != want) continue;
        u64 target = u64(r.addend);
        if (execSecOf(execs, target)) out.insert(target);
    }

    // REL has no addend field: the target is the word already stored at
    // r_offset. ARM32 shared objects use .rel.dyn, so skipping this would drop
    // every vtable on the architecture half of Android still ships.
    for (auto& s : e.sections) {
        if (s.type != "REL" || !s.size || !s.offset) continue;
        u64 ent = is64 ? 16u : 8u;
        if (s.offset + s.size > b.data.size()) continue;
        u64 cnt = s.size / ent;
        if (cnt > 2000000) cnt = 2000000;
        for (u64 j = 0; j < cnt; ++j) {
            u64 base = s.offset + j * ent;
            u64 info = rdN(base + (is64 ? 8 : 4), is64 ? 8 : 4);
            u32 t = is64 ? u32(info & 0xFFFFFFFFu) : u32(info & 0xFFu);
            if (t != want) continue;
            u64 where = elfVaToOff(e, rdN(base, is64 ? 8 : 4));
            if (where == ~u64(0) || where + (is64 ? 8u : 4u) > b.data.size()) continue;
            u64 target = rdN(where, is64 ? 8 : 4);
            if (execSecOf(execs, target)) out.insert(target);
        }
    }
}

// ---- AArch64 ----
inline bool a64IsTerminator(u32 w) {
    if (w == 0xD65F03C0) return true;                    // ret
    if ((w & 0xFFFFFBFF) == 0xD65F0BFF) return true;     // retaa / retab
    if ((w & 0xFC000000) == 0x14000000) return true;     // b
    if ((w & 0xFFFFFC1F) == 0xD61F0000) return true;     // br
    if ((w & 0xFC000000) == 0x94000000) return true;     // bl to a noreturn
    if ((w & 0xFFE0001F) == 0xD4200000) return true;     // brk
    if (w == 0 || w == 0xD503201F) return true;          // padding / nop
    return false;
}
inline bool a64IsPrologue(u32 w) {
    if (w == 0xD503237F || w == 0xD503233F) return true; // pacibsp / paciasp
    if ((w & 0xFFC003E0) == 0xA98003E0) return true;     // stp _,_,[sp,#-N]!
    if ((w & 0xFFE00FE0) == 0xF8000FE0) return true;     // str _,[sp,#-N]!
    if ((w & 0xFFC003FF) == 0xD10003FF) return true;     // sub sp, sp, #N
    return false;
}

// ---- x86 ----
inline bool x86IsPadByte(u8 c) { return c == 0x90 || c == 0xCC; }
// True when the bytes ending at p[i] are inter-function padding. Anchors the
// x86 rules the way "previous word is a terminator" anchors the AArch64 ones:
// endbr64 alone is useless here, because -fcf-protection also plants one at
// every indirect-branch target, i.e. at every switch case. Measured on a
// 911-function x86-64 object: endbr64 anywhere is 18% precision, endbr64 after
// padding is 99.6%.
bool x86PrevIsPad(const u8* p, u64 i) {
    if (!i) return false;
    if (x86IsPadByte(p[i - 1])) return true;
    static const char* kNops[] = {
        "\x66\x90", "\x0f\x1f\x00", "\x0f\x1f\x40\x00", "\x0f\x1f\x44\x00\x00",
        "\x66\x0f\x1f\x44\x00\x00", "\x0f\x1f\x80\x00\x00\x00\x00",
        "\x0f\x1f\x84\x00\x00\x00\x00\x00", "\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
        "\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
        "\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00" };
    static const size_t kNopLen[] = { 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    for (size_t k = 0; k < sizeof(kNopLen) / sizeof(kNopLen[0]); ++k) {
        size_t L = kNopLen[k];
        if (i >= L && memcmp(p + i - L, kNops[k], L) == 0) return true;
    }
    return false;
}
bool x86PrevEndsFunction(const u8* p, u64 i) {
    if (!i) return false;
    u8 b = p[i - 1];
    if (b == 0xC3 || b == 0xCC || b == 0x90) return true;   // ret / int3 / nop
    if (i >= 3 && p[i - 3] == 0xC2) return true;            // ret imm16
    if (i >= 5 && p[i - 5] == 0xE9) return true;            // jmp rel32
    if (i >= 2 && p[i - 2] == 0xEB) return true;            // jmp rel8
    return x86PrevIsPad(p, i);
}
// Frame setups that open a function on x86-64/x86. Only ever consulted at an
// address that already follows padding, so these do not have to be unambiguous
// on their own -- `push rbx` certainly is not.
bool x86IsPrologue(const u8* p, u64 i, u64 n) {
    if (i + 4 > n) return false;
    if (p[i] == 0x55 && p[i + 1] == 0x48 && p[i + 2] == 0x89 && p[i + 3] == 0xE5) return true;
    if (p[i] == 0x55 && p[i + 1] == 0x89 && p[i + 2] == 0xE5) return true;   // 32-bit
    if (p[i] == 0x48 && (p[i + 1] == 0x83 || p[i + 1] == 0x81) && p[i + 2] == 0xEC) return true;
    if (p[i] == 0x41 && p[i + 1] >= 0x54 && p[i + 1] <= 0x57) return true;   // push r12..r15
    if (p[i] == 0x55 || p[i] == 0x53) return true;                            // push rbp/rbx
    return false;
}

// ---- ARM32 ----
inline bool armIsTerminator(u32 w) {
    if (w == 0xE12FFF1E) return true;                    // bx lr
    if ((w & 0x0FFFFFFF) == 0x01A0F00E) return true;     // mov pc, lr
    if ((w & 0x0F000000) == 0x0A000000) return true;     // b
    if ((w & 0x0FFF8000) == 0x08BD8000) return true;     // pop {..., pc}
    if (w == 0 || w == 0xE320F000) return true;          // padding / nop
    return false;
}
inline bool armIsPrologue(u32 w) {
    if ((w & 0x0FFF4000) == 0x092D4000) return true;     // push {..., lr}
    if ((w & 0x0FFFFFFF) == 0x052DE004) return true;     // push {lr}
    if ((w & 0x0FFFF000) == 0x024DD000) return true;     // sub sp, sp, #N
    return false;
}

} // namespace

std::vector<FuncInfo> discoverFunctionsElf(const Binary& b, const ElfInfo& e, size_t* found) {
    std::map<u64, FuncInfo> byAddr;

    // PLT ranges: call targets landing here are import stubs, not functions
    std::vector<std::pair<u64, u64>> pltRanges;
    for (auto& s : e.sections) {
        if (isPltSection(s.name) || s.name == ".iplat")
            pltRanges.push_back({s.addr, s.addr + s.size});
    }
    auto inPlt = [&](u64 a) -> bool {
        for (auto& r : pltRanges) if (a >= r.first && a < r.second) return true;
        return false;
    };

    for (auto& s : e.symbols) {
        if (s.kind != "FUNC" || s.addr == 0 || !s.defined) continue;
        if (inPlt(s.addr)) continue;
        FuncInfo f;
        f.addr = s.addr;
        f.size = s.size;
        f.thumb = s.thumb;
        f.name = s.name.empty() ? "SUB_" + hexAddr(s.addr).substr(2) : s.name;
        f.from = "symtab";
        auto it = byAddr.find(s.addr);
        if (it == byAddr.end()) byAddr[s.addr] = f;
        else if (it->second.size < f.size) it->second = f;
    }

    // The scan runs on every binary, symbols or not. What it finds is merged
    // into the same map, so an address a symbol already named stays named --
    // the symbol wins over SUB_xxxxxxxx -- and cannot be counted twice.
    std::vector<ExecSec> execs = elfExecSecs(b, e);
    std::set<u64> starts;
    relocCodeTargets(b, e, execs, starts);

    for (auto& es : execs) {
        const u8* p = b.data.data() + es.off;
        const u64 va = es.va, size = es.size;

        if (e.archEnum == "ARM64") {
            u64 n4 = size / 4;
            u64 adrpPage[32] = {0};
            u64 adrpAt[32];
            bool adrpOk[32] = {false};
            for (int r = 0; r < 32; ++r) adrpAt[r] = 0;
            for (u64 i = 0; i < n4; ++i) {
                u32 w = rd32(p + i * 4);
                if ((w & 0xFC000000) == 0x94000000) {            // bl
                    starts.insert(va + i * 4 + u64(sext(i64(w & 0x03FFFFFF), 26)) * 4);
                } else if ((w & 0x9F000000) == 0x90000000) {     // adrp
                    i64 imm = (i64((w >> 5) & 0x7FFFF) << 2) | i64((w >> 29) & 3);
                    u32 rd = w & 0x1F;
                    adrpPage[rd] = (((va + i * 4) & ~u64(0xFFF)) + u64(sext(imm, 21)) * 4096);
                    adrpAt[rd] = i;
                    adrpOk[rd] = true;
                } else if ((w & 0xFFC00000) == 0x91000000) {     // add xd, xn, #imm12
                    u32 rn = (w >> 5) & 0x1F;
                    if (rn < 32 && adrpOk[rn] && i - adrpAt[rn] <= 8)
                        starts.insert(adrpPage[rn] + ((w >> 10) & 0xFFF));
                } else if ((w & 0x9F000000) == 0x10000000) {     // adr
                    i64 imm = (i64((w >> 5) & 0x7FFFF) << 2) | i64((w >> 29) & 3);
                    u64 t = va + i * 4 + u64(sext(imm, 21));
                    const ExecSec* ts = execSecOf(execs, t);
                    if (ts && ((t - ts->va) & 3) == 0 &&
                        a64IsPrologue(rd32(b.data.data() + ts->off + (t - ts->va))))
                        starts.insert(t);
                }
                if (a64IsPrologue(w) && (i == 0 || a64IsTerminator(rd32(p + (i - 1) * 4))))
                    starts.insert(va + i * 4);
            }
        } else if (e.archEnum == "X86_64" || e.archEnum == "X86") {
            std::map<u64, u32> callCount;
            for (u64 i = 0; i + 5 <= size; ++i) {
                if (p[i] == 0xE8)
                    ++callCount[va + i + 5 + u64(sext(i64(i32(rd32(p + i + 1))), 32))];
                if (p[i] == 0xF3 && p[i + 1] == 0x0F && p[i + 2] == 0x1E && p[i + 3] == 0xFA) {
                    if (x86PrevIsPad(p, i)) starts.insert(va + i);   // endbr64
                } else if (((va + i) & 15) == 0 && x86PrevIsPad(p, i) &&
                           x86IsPrologue(p, i, size)) {
                    starts.insert(va + i);
                }
            }
            // A call target is a function entry by construction -- but a byte
            // scan finds 0xE8 inside operands too, so take the target only
            // when something independent agrees: more than one call site, or
            // an instruction before it that does not fall through.
            for (auto& kv : callCount) {
                const ExecSec* ts = execSecOf(execs, kv.first);
                if (!ts) continue;
                if (kv.second >= 2 || x86PrevEndsFunction(b.data.data() + ts->off,
                                                          kv.first - ts->va))
                    starts.insert(kv.first);
            }
        } else if (e.archEnum == "ARM") {
            u64 n4 = size / 4;
            for (u64 i = 0; i < n4; ++i) {
                u32 w = rd32(p + i * 4);
                if ((w & 0x0F000000) == 0x0B000000)              // bl
                    starts.insert(va + i * 4 + 8 + u64(sext(i64(w & 0x00FFFFFF), 24)) * 4);
                if (armIsPrologue(w) && (i == 0 || armIsTerminator(rd32(p + (i - 1) * 4))))
                    starts.insert(va + i * 4);
            }
        }
    }

    // A symbol that gives a size also gives the extent of its function, and a
    // candidate inside that extent is a false positive by definition -- a
    // second frame setup, a jump-table entry, a misread 0xE8. Drop those
    // rather than publish a SUB_ in the middle of a named function.
    std::vector<std::pair<u64, u64>> spans;
    for (auto& kv : byAddr)
        if (kv.second.size > 0) spans.push_back({kv.first, kv.first + kv.second.size});
    auto insideNamed = [&](u64 a) -> bool {
        if (spans.empty()) return false;
        auto it = std::upper_bound(spans.begin(), spans.end(), std::make_pair(a, ~u64(0)));
        if (it == spans.begin()) return false;
        --it;
        return a > it->first && a < it->second;
    };

    for (u64 s : starts) {
        if (!s || byAddr.count(s)) continue;     // the symbol's name wins
        if (inPlt(s)) continue;                  // PLT stubs are imports
        const ExecSec* sec = execSecOf(execs, s);
        if (!sec) continue;                      // never outside executable code
        u64 align = (e.archEnum == "ARM64" || e.archEnum == "ARM") ? 4 : 1;
        if ((s - sec->va) % align) continue;
        if (insideNamed(s)) continue;
        FuncInfo f;
        f.addr = s; f.size = 0; f.name = "SUB_" + hexAddr(s).substr(2); f.from = "scan";
        byAddr[s] = f;
    }

    // fill zero sizes with gap to next function (capped)
    std::vector<FuncInfo> out;
    out.reserve(byAddr.size());
    for (auto& kv : byAddr) out.push_back(kv.second);
    std::sort(out.begin(), out.end(), [](const FuncInfo& a, const FuncInfo& b) { return a.addr < b.addr; });
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i].size == 0) {
            u64 end = (i + 1 < out.size()) ? out[i + 1].addr : out[i].addr + 512;
            u64 gap = end - out[i].addr;
            out[i].size = std::min<u64>(gap, 65536);
        }
        if (out[i].size > 1024 * 1024) out[i].size = 1024 * 1024;
    }
    if (found) *found = out.size();
    return out;
}

std::vector<FuncInfo> discoverFunctionsPe(const Binary& b, const PeInfo& e, size_t* found) {
    std::map<u64, FuncInfo> byAddr;
    for (auto& s : e.exports) {
        FuncInfo f;
        f.addr = s.addr; f.size = s.size; f.name = s.name; f.from = "export";
        byAddr[s.addr] = f;
    }
    if (e.entry) {
        FuncInfo f;
        f.addr = e.entry; f.size = 0; f.name = "entry_point"; f.from = "entry";
        if (!byAddr.count(e.entry)) byAddr[e.entry] = f;
    }
    // prologue scan when sparse
    if (byAddr.size() < 4) {
        u64 va = 0, size = 0;
        if (peExecRange(e, va, size)) {
            u64 off = peVaToOff(e, va);
            if (off != ~u64(0) && off + size <= b.data.size()) {
                const u8* p = b.data.data() + off;
                std::set<u64> starts;
                for (u64 i = 0; i + 5 <= size; ++i) {
                    if (p[i] == 0x55 && i + 4 <= size &&
                        p[i + 1] == 0x48 && p[i + 2] == 0x89 && p[i + 3] == 0xE5)
                        starts.insert(va + i);
                }
                for (u64 s : starts) {
                    if (byAddr.count(s)) continue;
                    FuncInfo f;
                    f.addr = s; f.size = 0; f.name = "SUB_" + hexAddr(s).substr(2); f.from = "scan";
                    byAddr[s] = f;
                }
            }
        }
    }
    std::vector<FuncInfo> out;
    out.reserve(byAddr.size());
    for (auto& kv : byAddr) out.push_back(kv.second);
    std::sort(out.begin(), out.end(), [](const FuncInfo& a, const FuncInfo& b2) { return a.addr < b2.addr; });
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i].size == 0) {
            u64 end = (i + 1 < out.size()) ? out[i + 1].addr : out[i].addr + 512;
            out[i].size = std::min<u64>(end - out[i].addr, 65536);
        }
    }
    if (found) *found = out.size();
    return out;
}

// ---------------- XREF scan ----------------
std::map<u64, std::vector<Xref>> buildXrefs(const std::string& arch, const u8* code, size_t size,
                                            u64 va, size_t cap, size_t* found) {
    std::map<u64, std::vector<Xref>> out;
    size_t total = 0;

    // The cap is on what is STORED -- a million references is a map the size
    // of the binary -- but the scan runs to the end either way and counts
    // every one, because the first thing a full map buys you is knowing when
    // it is not full. `found` is that count; out.size() is what fits.
    auto push = [&](u64 from, u64 to, const char* type) {
        if (!to) return;
        ++total;
        if (total > cap) return;
        out[to].push_back(Xref{from, to, type});
    };

    if (arch == "X86_64" || arch == "X86") {
        for (size_t i = 0; i + 5 <= size; ++i) {
            u8 c = code[i];
            if (c == 0xE8 || c == 0xE9) {
                u64 target = va + i + 5 + u64(sext(i64(i32(rd32(code + i + 1))), 32));
                push(va + i, target, c == 0xE8 ? "call" : "jmp");
                i += 4;
            }
        }
    } else if (arch == "ARM64") {
        for (size_t i = 0; i + 4 <= size; i += 4) {
            u32 w = rd32(code + i);
            u32 op = w & 0xFC000000;
            if (op == 0x94000000 || op == 0x14000000) {
                u64 target = va + i + u64(sext(i64(w & 0x03FFFFFF), 26)) * 4;
                push(va + i, target, op == 0x94000000 ? "call" : "jmp");
            }
        }
    } else if (arch == "ARM") {
        for (size_t i = 0; i + 4 <= size; i += 4) {
            u32 w = rd32(code + i);
            u32 op = w & 0xFF000000;
            if (op == 0xEB000000 || op == 0xEA000000) {
                u64 target = va + i + 8 + u64(sext(i64(w & 0x00FFFFFF), 24)) * 4;
                push(va + i, target, op == 0xEB000000 ? "call" : "jmp");
            }
        }
    }
    if (found) *found = total;
    return out;
}

} // namespace sako
