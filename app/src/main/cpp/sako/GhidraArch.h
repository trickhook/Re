// Ghidra's p-code decompiler, driven from an image already held in memory.
//
// Nothing here exposes a Ghidra type. The decompiler's headers put everything
// in `namespace ghidra` with `using namespace std` inside it, and they are
// C++11; keeping them behind this wall means the rest of the engine is not
// compiled against them.
#pragma once
#include "Types.h"
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace sako {

// One mapped region of the image: enough to answer "what byte is at this
// virtual address", which is all the decompiler asks of a loader.
struct GhidraSeg {
    u64 vaddr = 0, fileoff = 0, filesz = 0, memsz = 0;
    bool writable = true;   // a read-only segment lets constants be folded
};

class GhidraDecomp {
public:
    static GhidraDecomp& instance();

    // False when the engine was built without the vendored decompiler.
    static bool compiledIn();

    // Directory holding the .ldefs/.sla/.pspec/.cspec set, extracted from
    // assets. Until this is set nothing else here will succeed.
    void setSpecDir(const std::string& dir);
    const std::string& specDir() const { return specDir_; }

    // The Ghidra language id for one of our arch keys, or "" when we do not
    // ship a specification for it.
    static std::string languageFor(const std::string& arch);

    // Bind to an image. `key` identifies it so re-binding the same image is a
    // no-op: building an Architecture parses the whole .sla and is expensive.
    // `funcs` are addresses to publish as functions, which is what makes a
    // call print as a name instead of func_0x1234.
    bool open(const std::string& key, const std::string& arch,
              const u8* image, size_t size,
              const std::vector<GhidraSeg>& segs,
              // Address ranges the image says are not written at runtime.
              // Sections, not segments: a linker routinely puts .rodata in a
              // writable PT_LOAD, and constants are only folded through memory
              // the decompiler believes is read-only.
              const std::vector<std::pair<u64, u64>>& readOnly,
              const std::vector<std::pair<u64, std::string>>& funcs,
              const std::vector<FoundString>& strings,
              // ARM32 only: ($a|$t|$d, address) mapping symbols, sorted. The
              // ARM specification decodes Thumb only where TMode says so, so
              // without these every Thumb region would decode as ARM.
              const std::vector<std::pair<u64, char>>& armMapping,
              std::string& err);
    void close();

    bool ready() const;
    std::string backendName() const;

    // The analysis pipelines this build can run, most useful first. Ghidra
    // derives every one of them from the same universal action by filtering
    // it down to a list of rule groups, so all three are already compiled in;
    // only "decompile" was ever reachable.
    static const std::vector<std::string>& pipelines();
    // One sentence about a pipeline, for the picker. "" for an unknown id.
    static std::string pipelineDescription(const std::string& id);

    // Decompiled C for one function, or "" with `err` set. Never throws.
    // `jniEnvArg` is the index of the parameter that carries a JNIEnv*, or
    // -1 for none. Typing it is what turns an Android library's most common
    // line into a named call. The caller decides: only it has the call graph.
    // `pipeline` is one of pipelines(); anything else is an error rather than
    // a silent fall back to the default, because the difference between these
    // is exactly what the caller asked for.
    std::string decompile(u64 addr, const std::string& name, std::string& err,
                          int jniEnvArg = -1,
                          const std::string& pipeline = "decompile");

private:
    // Takes a ghidra::Funcdata* as void* so this header stays Ghidra-free.
    void applyJniPrototype(void* fd, const std::string& name, int jniEnvArg);

    GhidraDecomp() = default;
    ~GhidraDecomp();
    GhidraDecomp(const GhidraDecomp&) = delete;
    GhidraDecomp& operator=(const GhidraDecomp&) = delete;

    struct Impl;
    Impl* impl_ = nullptr;
    std::string specDir_;
};

} // namespace sako
