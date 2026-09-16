#include "Analysis.h"
#include <set>
#include <cstring>

namespace sako {

// ---------------- function discovery ----------------
std::vector<FuncInfo> discoverFunctionsElf(const Binary& b, const ElfInfo& e) {
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
        f.name = s.name.empty() ? "SUB_" + hexAddr(s.addr) : s.name;
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
                    for (u64 i = 0; i + 4 <= size; i += 4) {
                        u32 w = rd32(p + i);
                        if (w == 0xD503237F) starts.insert(va + i);                 // pacibsp
                        else if ((w & 0xFC000000) == 0x94000000) {                  // bl
                            u64 target = va + i + u64(sext(i64(w & 0x03FFFFFF), 26)) * 4;
                            starts.insert(target);
                        }
                    }
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
    if (out.size() > 4000) out.resize(4000);
    return out;
}

std::vector<FuncInfo> discoverFunctionsPe(const Binary& b, const PeInfo& e) {
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
    if (out.size() > 4000) out.resize(4000);
    return out;
}

// ---------------- XREF scan ----------------
std::map<u64, std::vector<Xref>> buildXrefs(const std::string& arch, const u8* code, size_t size,
                                            u64 va, size_t cap) {
    std::map<u64, std::vector<Xref>> out;
    size_t total = 0;

    auto push = [&](u64 from, u64 to, const char* type) {
        if (!to || total >= cap) return;
        out[to].push_back(Xref{from, to, type});
        ++total;
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
    return out;
}

} // namespace sako
