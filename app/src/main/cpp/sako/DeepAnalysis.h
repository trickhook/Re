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
    bool contains(u64 addr) const { return map_.count(addr) != 0 || overrides_.count(addr) != 0; }
    const std::map<u64, std::string>& raw() const { return map_; }

    // User-annotation overlay. A rename the analyst made wins over the name the
    // engine recovered, in every place that resolves a call target or a
    // cross-reference through lookup() (disassembly auto-comments, the pseudo-C
    // call sites, plugin builtins). setOverrides REPLACES the whole overlay, so
    // a rename the analyst removed disappears again. It is empty by default, and
    // lookup() below is byte-for-byte unchanged while it stays empty -- the
    // override is only ever consulted when at least one entry is present.
    void setOverrides(const std::map<u64, std::string>& ov) { overrides_ = ov; }
    bool hasOverrides() const { return !overrides_.empty(); }
private:
    std::map<u64, std::string> map_;
    std::map<u64, std::string> overrides_;
};

AddrNames buildAddrNamesElf(const Binary& b, const ElfInfo& e);
AddrNames buildAddrNamesPe(const Binary& b, const PeInfo& e);

// ---------------- call graph ----------------
// ONE definition of "a call", used by every consumer (the JSON edge list, the
// per-function degrees, the DEX builder). Do not re-split it:
//
//   * A node is a function start address, or a call target that is not a known
//     function (an import stub, or an address the scan could not attribute).
//   * An edge is one distinct (calling function -> target) pair, whatever the
//     target is. Import and unresolved targets are edges like any other; the
//     difference is carried by `kind`, never by leaving the edge out of a map.
//   * Several call sites between the same pair are ONE edge: `sites` counts
//     them, `site` is the lowest one.
//
// The invariant that follows, and the reason for this comment:
//     callees[f].size() == #edges with from == f   (== nCallees in the JSON)
//     callers[g].size() == #edges with to   == g   (== nCallers in the JSON)
// always, for every format. It used to be false in two ways at once: `edges`
// counted imports while `callees`/`callers` did not, and `callees` was keyed by
// call-site address instead of by function, so nCallees was 0 for every
// function in every ELF. Three screens each showed a different out-degree for
// the same function, and each one looked like a measurement.
struct CallEdge {
    // Start address of the CALLING FUNCTION — not the call site. When a call
    // site falls outside every function the analysis found, `from` is the call
    // site itself and `fromName` is "sub_<addr>": the edge is still reported,
    // because "something outside a known function calls this" is information.
    u64 from = 0;
    u64 to = 0;         // call target
    u64 site = 0;       // lowest call-site address for this (from, to) pair
    u32 sites = 1;      // how many call sites this pair has
    std::string fromName, toName;
    // "internal" = target is a function in this binary
    // "import"   = target is not a function but resolves to a name (PLT/import)
    // "unknown"  = target is neither
    std::string kind;
};

struct CallGraph {
    // Sorted by (from, to). The xref map is keyed by TARGET address, so its
    // natural iteration order is "calls into low addresses first" — capping
    // that order silently deleted every caller of the top half of the binary.
    // Sorting by caller makes the array stable across runs and makes any
    // truncation a documented suffix rather than an invisible slice.
    std::vector<CallEdge> edges;
    std::map<u64, std::vector<u64>> callees;   // caller func -> targets
    std::map<u64, std::vector<u64>> callers;   // target      -> caller funcs
    size_t callSites = 0;                      // raw call sites behind `edges`
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
