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

    // Where the SLEIGH specifications were extracted to. The app copies them
    // out of assets on first run and tells the engine once; until it does,
    // the Ghidra backend reports itself unavailable and the IR lifter is used.
    void setSleighDir(const std::string& dir);

    // "ghidra" or "ir". An unknown value, or "ghidra" where no specification
    // covers the architecture, falls back to the IR lifter per function.
    void setDecompiler(const std::string& which);
    std::string decompilerStatus(const std::string& path);

    // Full-file analysis → JSON (meta: format, sections, functions, strings,
    // imports, exports, callgraph, notes...)
    std::string analyze(const std::string& path);

    // Per-function detail (asm + comments + IR pseudo-C + CFG + xrefs) → JSON
    std::string functionDetail(const std::string& path, u64 addr);

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
        // Function address -> index of the parameter carrying a JNIEnv*.
        // Computed once, the first time a decompiler backend asks for it.
        std::map<u64, int> jniEnvArg;
        bool jniEnvArgDone = false;
    };

    bool ensureCtx(const std::string& path);
    u64 vaToOff(const Ctx& c, u64 va);

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
    std::string decompiler_ = "ghidra";
    std::string ghidraNote_;
    // The image the decompiler backend is currently bound to, so a rebuild
    // can be told apart from a cache hit.
    std::string ghidraKey_;
    std::mutex mutex_;
    std::atomic<bool> dbgStop_{false};
    std::mutex scriptMutex_;
};

} // namespace sako
