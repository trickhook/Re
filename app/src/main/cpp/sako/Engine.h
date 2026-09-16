// Engine facade — analysis context + JSON API used by JNI.
#pragma once
#include "Types.h"
#include "Loaders.h"
#include "Analysis.h"
#include "DeepAnalysis.h"
#include "Debugger.h"
#include <atomic>
#include <mutex>

namespace sako {

class Engine {
public:
    static Engine& instance();

    // Full-file analysis → JSON (meta: format, sections, functions, strings,
    // imports, exports, callgraph, notes...)
    std::string analyze(const std::string& path);

    // Per-function detail (asm + comments + IR pseudo-C + CFG + xrefs) → JSON
    std::string functionDetail(const std::string& path, u64 addr);

    // Call graph (optionally centered on one function) → JSON
    std::string callGraph(const std::string& path, u64 focus);

    // Interactive debugger session command (JSON in, JSON out)
    std::string dbgCmd(const std::string& json);

    // Produce a source listing from the analysis — the equivalent of IDA's
    // "produce file". Writes to outPath (a real filesystem path, not a content
    // URI) so a whole-binary listing never has to be held in memory as a
    // Java string, and returns a small JSON status.
    //   kind: "c-one" (function at addr) | "c-all" | "h-all" | "asm-all"
    std::string exportSource(const std::string& path, const std::string& kind,
                             u64 addr, const std::string& outPath);

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
        std::map<u64, std::vector<Xref>> xrefs;
        std::vector<FoundString> strings;
        std::vector<std::string> notes;
        double loadMs = 0;
        // v2
        AddrNames names;
        CallGraph cg;
    };

    bool ensureCtx(const std::string& path);
    u64 vaToOff(const Ctx& c, u64 va);

    Ctx ctx_;
    std::string ctxPath_;
    std::mutex mutex_;
    std::atomic<bool> dbgStop_{false};
    std::mutex scriptMutex_;
};

} // namespace sako
