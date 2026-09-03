// Deep analysis v2: address-name resolution (imports/PLT/GOT/exports/symbols),
// call graph construction, and automatic per-instruction comments.
#pragma once
#include "Types.h"
#include <map>
#include <string>

namespace sako {

// Address -> display name (functions, demangled C++ names, imports via
// GOT/PLT/IAT, exports, symbols). Later calls must not overwrite earlier
// (higher-priority) entries: pass priority=true to keep existing.
class AddrNames {
public:
    void add(u64 addr, const std::string& name, bool keepExisting = true);
    // resolve with optional offset suffix (name+0x10)
    std::string lookup(u64 addr) const;
    bool contains(u64 addr) const { return map_.count(addr) != 0; }
    const std::map<u64, std::string>& raw() const { return map_; }
private:
    std::map<u64, std::string> map_;
};

AddrNames buildAddrNamesElf(const Binary& b, const ElfInfo& e);
AddrNames buildAddrNamesPe(const Binary& b, const PeInfo& e);

// ---------------- call graph ----------------
struct CallEdge {
    u64 from = 0, to = 0;
    std::string fromName, toName;
    std::string kind;   // "internal" | "import" | "unknown"
};

struct CallGraph {
    std::vector<CallEdge> edges;
    std::map<u64, std::vector<u64>> callees;   // func -> callees (funcs only)
    std::map<u64, std::vector<u64>> callers;   // func -> callers
    std::map<u64, int> callCount;              // func -> #outgoing calls (all kinds)
    bool ok = false;
};

// Build from the engine xref map + address names. Only "call" edges.
CallGraph buildCallGraph(const std::map<u64, std::vector<Xref>>& xrefs,
                         const std::vector<FuncInfo>& funcs,
                         const AddrNames& names);

// DEX: promote methods that have bytecode into first-class functions and
// build a call graph by scanning invoke-kind instructions in each code item.
void buildDexFuncsAndCalls(const std::vector<u8>& data, const DexInfo& dex,
                           std::vector<FuncInfo>& funcs, CallGraph& cg);

// "Lcom/foo/Bar;" -> "Bar"
std::string dexShortClass(const std::string& desc);

// ---------------- auto comments ----------------
// Annotates lines: call targets, string references (adrp+add / lea rip),
// GOT loads, dangerous APIs, loop back-edges, stack-frame setup.
void autoComment(const std::string& arch, std::vector<AsmLine>& lines,
                 const AddrNames& names,
                 const std::vector<FoundString>& strings,
                 u64 funcStart, u64 funcEnd);

// dangerous / notable import classification for comments + AI panel
const char* classifyImport(const std::string& plainName);

// strip "libc.so!malloc" / "KERNEL32.dll!CreateFileW" -> plain symbol
std::string plainSymbol(const std::string& importName);

} // namespace sako
