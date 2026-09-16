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
              const std::vector<std::pair<u64, std::string>>& funcs,
              const std::vector<FoundString>& strings,
              std::string& err);
    void close();

    bool ready() const;
    std::string backendName() const;

    // Decompiled C for one function, or "" with `err` set. Never throws.
    std::string decompile(u64 addr, const std::string& name, std::string& err);

private:
    GhidraDecomp() = default;
    ~GhidraDecomp();
    GhidraDecomp(const GhidraDecomp&) = delete;
    GhidraDecomp& operator=(const GhidraDecomp&) = delete;

    struct Impl;
    Impl* impl_ = nullptr;
    std::string specDir_;
};

} // namespace sako
