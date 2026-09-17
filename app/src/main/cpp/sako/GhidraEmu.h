// Ghidra's p-code emulator, driven from the same in-memory image the
// decompiler reads.
//
// The decompiler answers "what does this code say". This answers "what does
// this code do to memory" — run a string-decryption routine and read the
// plaintext out, resolve a computed branch, fold an anti-debug check. On an
// obfuscated library that is a different kind of fact, not a second opinion.
//
// Same wall as GhidraArch.h: nothing here exposes a Ghidra type, because the
// decompiler headers put everything in `namespace ghidra` with
// `using namespace std` inside it and are compiled as C++11.
#pragma once
#include "Types.h"
#include "GhidraArch.h"     // GhidraSeg
#include <string>
#include <utility>
#include <vector>

namespace sako {

// A block of bytes at an address. Used both to seed memory before a run and
// to hand back what the run wrote.
struct EmuBytes {
    u64 addr = 0;
    std::vector<u8> bytes;
    std::string label;      // "arg0", "dirty", "window" — why it is in the answer
};

// One argument. The point of the non-scalar kinds is that the interesting
// call — decrypt(ciphertext, out, len) — needs somewhere for the output to
// go, and the caller has no address to give: the sandbox has to make one.
struct EmuArg {
    enum Kind {
        Value,      // a scalar, passed as-is
        Buffer,     // allocate `len` zeroed bytes, pass the address
        Data        // allocate a block holding `data`, pass the address
    };
    Kind kind = Value;
    u64 value = 0;          // Value: the scalar. Others: the address chosen.
    u32 len = 0;            // Buffer: bytes to allocate
    std::vector<u8> data;   // Data: bytes to place (already NUL-terminated if a string)
    std::string reg;        // filled in by run(): where it was actually passed
};

// Everything that stops a runaway. None of these is optional: this runs in
// the UI process on a binary built to resist analysis, and an emulator that
// hangs is worse than no emulator because the user cannot tell it from a
// crash.
struct EmuLimits {
    u64 maxInstructions = 200000;  // same order as GhidraArch's decompile cap
    u32 timeoutMs = 3000;          // wall clock, checked every 512 instructions
    u32 maxPages = 1024;           // 4 KiB pages the guest may dirty => 4 MiB
    u32 maxCalls = 4096;           // stubbed calls; a loop over one is a loop
    bool strictUserops = false;    // stop on the first p-code op we model as 0
};

struct EmuRequest {
    u64 entry = 0;
    std::vector<EmuArg> args;
    std::vector<std::pair<std::string, u64>> regs;  // raw register overrides
    std::vector<EmuBytes> seeds;                    // raw memory to write first
    std::vector<std::pair<u64, u32>> windows;       // memory to read back at exit
    u64 stopAt = 0;                                 // extra halt address, 0 = none
    EmuLimits limits;
};

enum class EmuStop {
    Completed,      // returned to the caller
    StopAddress,    // reached the address the caller asked to stop at
    Budget,         // instruction budget exhausted
    Timeout,        // wall clock exhausted
    MemoryCap,      // dirtied more pages than allowed
    CallCap,        // called stubs more times than allowed
    Unimplemented,  // an instruction or operand width we do not model
    Fault,          // executed unmapped memory, or the machine state is impossible
    Aborted,        // the code itself called abort / __stack_chk_fail / exit
    Setup           // never started
};

// One call the emulator intercepted instead of executing.
struct EmuCall {
    std::string name;
    u64 site = 0;                 // the stub address that was entered
    std::vector<u64> args;        // as many as the model looked at
    u64 ret = 0;
    bool modelled = false;        // false => we returned 0 and moved on
    std::string note;             // e.g. the log line, or the allocation size
};

// A user-defined p-code op (CALLOTHER) the specification emits and the
// emulator has no semantics for.
struct EmuUserop {
    std::string name;
    u32 count = 0;
    bool harmless = false;        // a barrier or a hint: zero really is right
};

struct EmuResult {
    bool ok = false;
    EmuStop stop = EmuStop::Setup;
    std::string detail;           // specific and honest, e.g.
                                  // "instruction budget exhausted after 200000 instructions"
    // True when something was modelled as zero that might not be zero, so the
    // memory below is a plausible answer rather than a certain one.
    bool approximate = false;

    u64 instructions = 0;
    double ms = 0;
    u64 entry = 0;

    std::vector<std::pair<std::string, u64>> regs;  // the ABI's reportable set
    std::string retReg;
    u64 ret = 0;

    std::vector<EmuArg> args;      // echoed, with the addresses the sandbox chose
    std::vector<EmuBytes> memory;  // buffers, requested windows, dirtied ranges
    u64 dirtyBytes = 0;
    u32 dirtyRanges = 0;
    bool memoryTruncated = false;  // more was written than we hand back

    std::vector<EmuCall> calls;
    u64 callsTotal = 0;
    std::vector<EmuUserop> userops;
    // Userop executions that did not fit the 64-name table above. Not itemised
    // and not counted per name, but not invisible either: "approximate" tells
    // you a model returned zero, and this tells you how much of that the list
    // does not show.
    u64 useropsDropped = 0;

    std::vector<u64> tail;         // the last addresses executed, oldest first

    std::string backend;           // "Ghidra p-code (AARCH64:LE:64:v8A)"
    u64 stackBase = 0, heapBase = 0, heapUsed = 0;
};

const char* emuStopName(EmuStop s);

class GhidraEmu {
public:
    static GhidraEmu& instance();

    // False when the engine was built without the vendored decompiler: the
    // emulator is the same object file set.
    static bool compiledIn();

    // Bind to an image. Same shape as GhidraDecomp::open and the same
    // re-binding rule: building an Architecture parses the whole .sla.
    //
    // `stubs` are addresses that must not be executed — PLT entries and any
    // other import thunk — paired with the imported name. A call to one is
    // answered by a model instead of by the code behind it, which for an
    // import in a shared library is not even present in the file.
    bool open(const std::string& key, const std::string& arch,
              const u8* image, size_t size,
              const std::vector<GhidraSeg>& segs,
              const std::vector<std::pair<u64, std::string>>& stubs,
              // ARM32 only, same reason as the decompiler: without the
              // mapping symbols a Thumb region decodes as ARM.
              const std::vector<std::pair<u64, char>>& armMapping,
              std::string& err);
    void close();

    // SleighArchitecture keeps one Sleigh per language in a process-wide
    // static map and rebinds it to the loader and context of whichever
    // Architecture was built last. The decompiler builds one of those. Call
    // this whenever it binds itself to a different image, and the next run()
    // rebuilds this architecture instead of reading bytes through the
    // decompiler's loader.
    void translatorRebound();

    bool ready() const;
    std::string backendName() const;

    // Run one function. Never throws; every failure comes back as a stop
    // reason with a specific message.
    EmuResult run(const EmuRequest& req);

    // The libc names this build actually models, for the UI to say so.
    static std::vector<std::string> modelledImports();

private:
    GhidraEmu() = default;
    ~GhidraEmu();
    GhidraEmu(const GhidraEmu&) = delete;
    GhidraEmu& operator=(const GhidraEmu&) = delete;

    struct Impl;
    Impl* impl_ = nullptr;
};

} // namespace sako
