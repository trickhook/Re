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
              // ARM32 only: ($a|$t|$d, address) mapping symbols, sorted. The
              // ARM specification decodes Thumb only where TMode says so, so
              // without these every Thumb region would decode as ARM.
              const std::vector<std::pair<u64, char>>& armMapping,
              std::string& err);
    void close();

    bool ready() const;
    std::string backendName() const;

    // Decompiled C for one function, or "" with `err` set. Never throws.
    // `jniEnvArg0` types the first parameter as JNIEnv*, which is what turns
    // this library's most common line into a named call. The caller decides:
    // only it has the disassembly to recognise the pattern.
    std::string decompile(u64 addr, const std::string& name, std::string& err,
                          bool jniEnvArg0 = false);

private:
    // Takes a ghidra::Funcdata* as void* so this header stays Ghidra-free.
    void applyJniPrototype(void* fd, const std::string& name, bool jniEnvArg0);

    GhidraDecomp() = default;
    ~GhidraDecomp();
    GhidraDecomp(const GhidraDecomp&) = delete;
    GhidraDecomp& operator=(const GhidraDecomp&) = delete;

    struct Impl;
    Impl* impl_ = nullptr;
    std::string specDir_;
};

} // namespace sako
