// Engine facade — analysis context + JSON API used by JNI.
#pragma once
#include "Types.h"
#include "Loaders.h"
#include "Analysis.h"
#include "DeepAnalysis.h"
#include "Debugger.h"
#include <atomic>
#include <iosfwd>
#include <mutex>

namespace bindiff { struct Func; }   // BinDiff.h — the diff matcher's descriptor

namespace sako {

class Engine {
public:
    static Engine& instance();

    // Where the SLEIGH specifications were extracted to. The app copies them
    // out of assets on first run and tells the engine once; until it does,
    // the Ghidra backend reports itself unavailable and the IR lifter is used.
    void setSleighDir(const std::string& dir);

    // "ghidra" or "ir". An unknown value, or "ghidra" where no specification
    // covers the architecture, falls back to the IR lifter per function.
    void setDecompiler(const std::string& which);
    std::string decompilerStatus(const std::string& path);

    // Path to a library-function signature database (a .nsig produced by
    // tools/siggen). When set and the file loads, analysis of a binary of a
    // matching architecture names the functions that would otherwise be
    // SUB_xxxxxxxx (see LibSig.h). Empty (the default) disables the pass, so
    // the engine is unchanged until a database is installed. Phase 2 points
    // this at the bundled bionic/libc++ database extracted from assets, the
    // same way setSleighDir installs the SLEIGH specifications.
    void setLibSigDb(const std::string& path);

    // Full-file analysis → JSON (meta: format, sections, functions, strings,
    // imports, exports, callgraph, notes...)
    //
    // The function list in that answer is the FIRST PAGE of the functions, not
    // all of them: nothing caps the analysis any more, but 200000 rows is 40 MB
    // of JSON (measured: 204 bytes a row for C++ symbols with a demangled
    // form), and one jstring of that size is an OOM on the way to the parser.
    // functionsTotal says how many there are; functions() below serves the
    // rest. Nothing is withheld -- a page you have not asked for yet is not a
    // truncation.
    std::string analyze(const std::string& path);

    // One page of the function list: [offset, offset+count) of exactly the
    // rows analyze() emits. count == 0 asks for the default page; anything
    // larger than kFunctionsPageMax is clamped, and the answer's own `count`
    // field says what came back, so a caller can always walk to the end:
    //
    //   {"ok":true,"functionsTotal":98022,"offset":12000,"count":12000,
    //    "functions":[...],"demangleFailed":31}
    std::string functions(const std::string& path, u64 offset, u64 count);

    // Per-function detail (asm + comments + IR pseudo-C + CFG + xrefs) → JSON
    std::string functionDetail(const std::string& path, u64 addr);

    // Cross-references TO one address, data included. functionDetail answers
    // "who references this FUNCTION" by walking the slice of c.xrefs that lands
    // inside a function body; this answers "who references this ADDRESS" for
    // one exact target key — the string/datum case that has no function to
    // resolve to. It reads the SAME c.xrefs store the script builtin
    // count_xrefs_to reads, so the total here and count_xrefs_to(addr,"any")
    // are the same number; every referencing site is mapped to the function
    // that contains it. The point is the data case: the address behind a
    // string like "pinned public key" resolves to no function, so
    // functionDetail either fails or answers for the wrong one, while this
    // returns the functions that reference the string. If the address is
    // itself inside a function it degenerates honestly to that function's
    // code callers. Returns:
    //   {ok, target, targetKind ("string"|"data"|"code"), value?,
    //    total, shown, refs:[{from, funcAddr, funcName, funcDisplay?, type}]}
    // `total` is the honest count; `refs` is capped and `shown` says how many
    // it carries.
    std::string xrefsTo(const std::string& path, u64 addr);

    // Anti-analysis & pinning scan — the capstone on xrefsTo. Ensures the
    // context for `path`, then runs the pattern database in Detections.h over
    // exactly what the analysis already holds: the string table, the function
    // list and the reference map. A category's token names a string, the SAME
    // c.xrefs store xrefsTo reads maps that string's referencing sites to their
    // containing functions, and a referencing function under a category is a
    // detection; a function whose own name contains a token is a direct
    // detection. A matched string that nothing references is an unattributed
    // hit, still reported. Attributed detections are deduped by (functionAddr,
    // category). Naming is resolved the SAME way as xrefsTo — the raw symbol
    // plus a demangled `funcDisplay` when it looks mangled — so the two can
    // never disagree. READ-ONLY: it changes nothing in the context. Returns:
    //   {ok, total, shown, counts:{<category>:N,...}, unattributed,
    //    detections:[{category, confidence ("high"|"medium"|"low"),
    //      funcAddr, funcName, funcDisplay?, evidence, tokens:[...],
    //      source ("string"|"name"|"mixed"), site, stringAddr?, value?, hits}]}
    // `total` is the honest count; `detections` is capped and `shown` says how
    // many it carries. `funcAddr` is 0x0 for an unattributed hit.
    std::string detect(const std::string& path);

    // ------------------------------------------------------------ DEX / smali
    // The Dalvik half of the engine. The native disassembler decodes machine
    // code and cannot touch DEX bytecode, so these three surface the .dex the
    // analyst opened the app for: read a method's bytecode as smali, search the
    // DEX string pool, and see who invokes a method. Each takes the same lock
    // and the same ensureCtx error path as xrefsTo/detect, answers only when the
    // open file is a DEX, and serialises through the same q()/hq()/num() helpers
    // with honest total/shown caps.

    // Smali disassembly of ONE method — the code_item at `addr` (a method's
    // codeOff, exactly the value analyze() emits in dexMethods[].codeOff and the
    // address a promoted DEX method carries in the function list). Decodes the
    // Dalvik instructions with the format-driven decoder in DexSmali.h and
    // resolves index operands (string@/type@/field@/meth@/proto@) through the
    // dex pools; an opcode it does not know renders as "<unknown-op 0xNN>", never
    // a guess. nCallers/nCallees come straight off the call graph
    // buildDexFuncsAndCalls already built, so a method's smali view and its xref
    // count agree. Returns:
    //   {ok, addr, class, classShort, method, proto, name, registers, ins, outs,
    //    tries, insnsUnits, insnBytes, total, shown, truncated,
    //    smali:[{off, unit, bytes, mnem, ops, comment}],
    //    nCallers, nCallees} or {ok:false,error}.
    std::string dexSmali(const std::string& path, u64 addr);

    // DEX string pool search — case-insensitive substring over the string_ids
    // the loader read, paginated with an honest total, the same shape as every
    // other list endpoint. Where list_strings/analyze carry the first 3000 that
    // pass the printable floor, this reaches the whole (loader-capped) string_ids
    // pool, which is the point: a DEX carries far more strings than the general
    // string scan surfaces. `addr` on each row is the string's index in the
    // pool, the same key the DEX strings use everywhere else. Returns:
    //   {ok, query, total, matched, offset, shown,
    //    strings:[{addr, value, truncated?, length?}], poolTotal, poolRead}
    // where `matched` is the honest match count over the pool and `poolRead` <
    // `poolTotal` says the loader capped the pool.
    std::string dexStrings(const std::string& path, const std::string& query,
                           u64 offset, u64 count);

    // DEX method xrefs — who invokes the method at `addr` (callers) and who it
    // invokes (callees). This does NOT scan: buildDexFuncsAndCalls already built
    // the call graph by walking every method's invoke instructions, so this
    // surfaces that existing data for one method, resolving each end to its
    // Class.method name. `addr` is a method codeOff. Returns:
    //   {ok, addr, name, callersTotal, callers:[{addr,name,site,sites}],
    //    calleesTotal, callees:[{addr,name,site,sites}]} or {ok:false,error}.
    std::string dexMethodXrefs(const std::string& path, u64 addr);

    // Binary diff — compare two LINKED binaries (typically two versions of the
    // same library) and classify every function identical / changed / added /
    // removed, with a similarity score for the changed ones. `pathA` is the
    // binary already open/analysed (A); `pathB` is a second path the caller
    // supplies (B). A's analysis context is NOT disturbed: B is analysed into a
    // scratch context, compared, and thrown away, so a diff leaves the open
    // binary exactly as it was. Matching (see BinDiff.h) is by exact bytes, then
    // symbol name, then a normalized-instruction fingerprint that masks
    // addresses/immediates so relocation noise is not read as a change, then a
    // structural fallback. Returns JSON:
    //   {ok, aName, bName, aArch, bArch, identical:N,
    //    changed:[{nameA,addrA,nameB,addrB,similarity}],
    //    added:[{name,addr}], removed:[{name,addr}],
    //    counts:{...}, notes:[...]}
    // The three lists are capped for the UI; counts carries the honest totals.
    std::string diff(const std::string& pathA, const std::string& pathB);

    // Call graph (optionally centered on one function) → JSON
    std::string callGraph(const std::string& path, u64 focus);

    // Interactive debugger session command (JSON in, JSON out)
    std::string dbgCmd(const std::string& json);

    // Run one function under Ghidra's p-code emulator. JSON in, JSON out;
    // NativeBridge.nativeEmulate documents both shapes. This is the one call
    // in the engine that executes the analysed binary's own instructions, so
    // it is also the one with a hard instruction budget, a wall clock and a
    // memory cap — see GhidraEmu.h.
    std::string emulate(const std::string& path, const std::string& reqJson);

    // Produce a source listing from the analysis — the equivalent of IDA's
    // "produce file". Writes to outPath (a real filesystem path, not a content
    // URI) so a whole-binary listing never has to be held in memory as a
    // Java string, and returns a small JSON status.
    //   kind: "c-one" (function at addr) | "c-all" | "h-all" | "asm-all"
    std::string exportSource(const std::string& path, const std::string& kind,
                             u64 addr, const std::string& outPath);

    // Progress of the export running right now:
    //   {"running":true,"done":12431,"total":98022,"failed":17,"cancelling":false}
    // Reads atomics and takes NO lock, so it answers while exportSource() is
    // holding the engine mutex -- which is the only time the answer is useful.
    std::string exportProgress();

    // Ask that export to stop at the next function boundary. The file it has
    // written is flushed and closed as it stands, ends with a comment saying
    // it is partial, and exportSource() returns "cancelled":true. Also lock-
    // free, for the same reason.
    void exportStop();

    // Run a SakoScript plugin; effects (rename/comment/bookmark) returned as
    // JSON list for the app to persist. Analysis context from path (optional).
    std::string scriptRun(const std::string& source, const std::string& path);

    // Legacy syscall tracer (blocking; call from background thread)
    std::string debugRun(const std::vector<std::string>& argv, int maxEvents);
    void debugStop();

private:
    Engine() = default;

    struct Ctx {
        Binary bin;
        Fmt fmt = Fmt::Unknown;
        ElfInfo elf;
        PeInfo pe;
        DexInfo dex;
        std::string arch;         // disassembler arch key
        std::string backend;      // disassembler backend name ("" = not ready)
        Disasm dis;
        std::vector<FuncInfo> funcs;
        // What discovery FOUND. Nothing caps `funcs` any more, so this equals
        // its size today; it is kept and reported because the number used to be
        // thrown away, and a list that is a page of a larger whole has to be
        // able to say how large that whole is. The JSON takes max() of the two,
        // because functionDetail appends a synthetic entry for an address no
        // symbol covers.
        size_t funcsFound = 0;
        std::map<u64, std::vector<Xref>> xrefs;
        // References the scans SAW, code and data together. `xrefs` holds the
        // first 200000 of them -- a map of a million is the size of the binary
        // -- and this is the number that says whether that bit. Every xref
        // answer in the engine is a slice of that map, so when the two differ
        // the per-function counts are floors and analyze() says so.
        size_t xrefsFound = 0;
        std::vector<FoundString> strings;
        // Strings the scan found. For DEX this is string_ids_size out of the
        // header, which is exact; for ELF/PE the scan stops AT its cap instead
        // of counting past it, so it is a floor and a note says so.
        size_t stringsFound = 0;
        std::vector<std::string> notes;
        double loadMs = 0;
        // v2
        AddrNames names;
        CallGraph cg;
        // Function address -> index of the parameter carrying a JNIEnv*.
        // Computed once, the first time a decompiler backend asks for it.
        std::map<u64, int> jniEnvArg;
        bool jniEnvArgDone = false;
    };

    bool ensureCtx(const std::string& path);
    // Build a fresh analysis context for `path` into `c` WITHOUT touching the
    // engine's open context (ctx_/ctxPath_). ensureCtx is this plus the one-slot
    // cache; diff() calls it directly to analyse binary B into a scratch context
    // while binary A stays loaded. Returns false when the file cannot be read.
    bool buildCtx(const std::string& path, Ctx& c);
    // Reduce a context's functions to bindiff::Func descriptors — a raw-byte
    // hash plus the normalized instruction stream — for the diff matcher.
    void buildDiffFuncs(Ctx& c, std::vector<bindiff::Func>& out);
    u64 vaToOff(const Ctx& c, u64 va);

    // One row of the function list. analyze() and functions() both go through
    // this, so a paged row and a first-page row cannot drift into two
    // dialects. `undemangled` counts the names that look mangled and that the
    // demangler could not read, which the caller reports as demangleFailed.
    void emitFunctionRow(std::ostringstream& out, const Ctx& c, const FuncInfo& f,
                         size_t& undemangled) const;

    // Bind the Ghidra backend to the current context, if it can be. Returns
    // false when it is unavailable for any reason, which is not an error:
    // every caller falls back to the IR lifter.
    bool ghidraReady(Ctx& c, const std::string& path);
    // The same for the emulator, whose failure is an error: nothing else in
    // the engine can run code, so there is nothing to fall back to. `why` is
    // filled in with a sentence for the user.
    bool ghidraEmuReady(Ctx& c, const std::string& path, std::string& why);
    // Work out which functions are handed a JNIEnv*, and in which argument,
    // by following the pointer across calls until nothing new is learned.
    void computeJniEnvArgs(Ctx& c);
    // Decompiled text for one function, or "" when the backend cannot serve it.
    std::string ghidraPseudo(Ctx& c, const std::string& path, const FuncInfo& fn,
                             const std::vector<AsmLine>& lines);

    Ctx ctx_;
    std::string ctxPath_;
    std::string sleighDir_;
    std::string libSigDbPath_;    // library-signature database path ("" = off)
    std::string decompiler_ = "ghidra";
    std::string ghidraNote_;
    // The image the decompiler backend is currently bound to, so a rebuild
    // can be told apart from a cache hit.
    std::string ghidraKey_;
    std::mutex mutex_;
    std::atomic<bool> dbgStop_{false};
    std::mutex scriptMutex_;
    // Export progress and cancellation. Atomics, not state under mutex_:
    // exportSource() holds that mutex for the whole run, so anything that
    // waited for it could neither report progress nor stop the run.
    std::atomic<bool> exportRunning_{false};
    std::atomic<bool> exportCancel_{false};
    std::atomic<u64> exportDone_{0};
    std::atomic<u64> exportTotal_{0};
    std::atomic<u64> exportFailed_{0};
};

} // namespace sako
