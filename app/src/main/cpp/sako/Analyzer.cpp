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

std::vector<FuncInfo> discoverFunctionsElf(const Binary& b, const ElfInfo& e, size_t* found) {
    std::map<u64, FuncInfo> byAddr;

    // PLT ranges: call targets landing here are import stubs, not functions
    std::vector<std::pair<u64, u64>> pltRanges;
    for (auto& s : e.sections) {
        if (s.name.rfind(".plt", 0) == 0 || s.name == ".iplat" || s.name == ".iplt")
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

    // When symbol table is sparse (stripped or partially stripped), augment
    // with prologue/BL linear scan.
    if (byAddr.size() < 8) {
        u64 va = 0, size = 0;
        if (elfExecRange(e, va, size)) {
            u64 off = elfVaToOff(e, va);
            if (off != ~u64(0) && off + size <= b.data.size()) {
                const u8* p = b.data.data() + off;
                std::set<u64> starts;

                if (e.archEnum == "ARM64") {
                    // An address taken with adr is only a function start if it
                    // reads like one; adr also materialises jump tables and
                    // literals that live inside .text.
                    auto looksLikePrologue = [&](u64 target) -> bool {
                        if (target < va || target + 4 > va + size) return false;
                        u32 w0 = rd32(p + (target - va));
                        if (w0 == 0xD503237F || w0 == 0xD503233F) return true;  // pacibsp/paciasp
                        if ((w0 & 0xFFC003E0) == 0xA98003E0) return true;       // stp _,_,[sp,#-N]!
                        if ((w0 & 0xFFC003FF) == 0xD10003FF) return true;       // sub sp, sp, #N
                        return false;
                    };
                    std::vector<u64> adrTargets;
                    for (u64 i = 0; i + 4 <= size; i += 4) {
                        u32 w = rd32(p + i);
                        if (w == 0xD503237F) starts.insert(va + i);                 // pacibsp
                        else if ((w & 0xFC000000) == 0x94000000) {                  // bl
                            u64 target = va + i + u64(sext(i64(w & 0x03FFFFFF), 26)) * 4;
                            starts.insert(target);
                        } else if ((w & 0x9F000000) == 0x10000000) {                // adr
                            i64 imm = i64(((w >> 5) & 0x7FFFF) << 2) | i64((w >> 29) & 3);
                            adrTargets.push_back(va + i + u64(sext(imm, 21)));
                        }
                    }
                    for (u64 t : adrTargets)
                        if (looksLikePrologue(t)) starts.insert(t);
                } else if (e.archEnum == "X86_64" || e.archEnum == "X86") {
                    for (u64 i = 0; i + 5 <= size; ++i) {
                        if (p[i] == 0x55 && i + 4 <= size &&
                            p[i + 1] == 0x48 && p[i + 2] == 0x89 && p[i + 3] == 0xE5)
                            starts.insert(va + i);                                  // push rbp; mov rbp,rsp
                        if (p[i] == 0xE8) {                                         // call rel32
                            if (i + 5 <= size) {
                                u64 target = va + i + 5 + u64(sext(i64(i32(rd32(p + i + 1))), 32));
                                starts.insert(target);
                            }
                        }
                    }
                } else if (e.archEnum == "ARM") {
                    for (u64 i = 0; i + 4 <= size; i += 4) {
                        u32 w = rd32(p + i);
                        if ((w & 0xFF000000) == 0xEB000000) {                       // bl
                            u64 target = va + i + 8 + u64(sext(i64(w & 0x00FFFFFF), 24)) * 4;
                            starts.insert(target);
                        }
                    }
                }
                for (u64 s : starts) {
                    if (!s || byAddr.count(s)) continue;
                    if (inPlt(s)) continue;   // PLT stubs are imports, not functions
                    FuncInfo f;
                    f.addr = s; f.size = 0; f.name = "SUB_" + hexAddr(s).substr(2); f.from = "scan";
                    byAddr[s] = f;
                }
            }
        }
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
