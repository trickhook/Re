// LibSig — engine integration for library-function recognition.
//
// LibSigFormat.h defines the signature database and the byte-level matcher with
// no dependency on the rest of the engine (so the host generator in tools/ can
// share it verbatim). This header adds the thin engine-facing layer: load a
// database from a file path, and run it over the functions the discovery pass
// produced, naming the ones that are still SUB_xxxxxxxx.
//
// It is header-only ON PURPOSE for phase 1. The matcher is thereby compiled
// into the engine (Engine.cpp includes it) with no change to the build system:
// no new source in CMakeLists, no asset, no JNI. Until a database path is set
// the pass is a no-op, so the shipped app is byte-for-byte unchanged. Phase 2
// turns it on by generating the bionic/libc++ database at CI, bundling it as an
// asset, pointing the engine at it, and surfacing the names.
#pragma once
#include "Types.h"
#include "Loaders.h"
#include "LibSigFormat.h"
#include <cstdio>
#include <chrono>

namespace sako {

struct LibMatchStats {
    size_t unknownBefore = 0;   // functions still named SUB_ when the pass began
    size_t attempted = 0;       // SUB_ functions we tried to identify
    size_t named = 0;           // uniquely, confidently identified -> renamed
    size_t collisions = 0;      // matched but ambiguous -> deliberately left SUB_
    double ms = 0;              // wall time of the pass
};

// A loaded database plus the arch guard is just libsig::Db; this loads it from
// a filesystem path. Returns false (and leaves the Db empty) when the path
// cannot be read or is malformed — every caller treats that as "no database",
// which is not an error.
inline bool loadLibSigDb(const std::string& path, libsig::Db& db, std::string* err = nullptr) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) { if (err) *err = "cannot open " + path; return false; }
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz <= 0) { std::fclose(f); if (err) *err = "empty file"; return false; }
    std::vector<uint8_t> buf;
    buf.resize(size_t(sz));
    size_t got = std::fread(buf.data(), 1, buf.size(), f);
    std::fclose(f);
    if (got != buf.size()) { if (err) *err = "short read"; return false; }
    return db.loadFromMemory(buf.data(), buf.size(), err);
}

// Locate the code bytes for a virtual address in a loaded ELF image: the file
// pointer to the byte at `va`, and how many contiguous bytes are readable from
// there to the end of the enclosing executable section (or LOAD segment when
// section headers are stripped). Returns nullptr when `va` is not in mapped
// executable code. This bounds the matcher so it never reads past a function's
// section — the discovered SUB_ size is a gap estimate, so it is NOT used here.
inline const u8* elfCodeAt(const Binary& b, const ElfInfo& e, u64 va, size_t& avail) {
    avail = 0;
    // Prefer real executable PROGBITS sections.
    for (auto& s : e.sections) {
        if (s.type != "PROGBITS" || !s.size) continue;
        if (s.flags.find('X') == std::string::npos) continue;
        if (va >= s.addr && va < s.addr + s.size) {
            u64 off = (s.offset ? s.offset : elfVaToOff(e, s.addr)) + (va - s.addr);
            if (off == ~u64(0) || off >= b.data.size()) return nullptr;
            avail = size_t(std::min<u64>(s.addr + s.size - va, b.data.size() - off));
            return b.data.data() + off;
        }
    }
    // Section headers gone: fall back to executable LOAD segments.
    for (auto& sg : e.segments) {
        if (sg.type != "LOAD" || !sg.filesz) continue;
        if (sg.flags.find('X') == std::string::npos) continue;
        if (va >= sg.vaddr && va < sg.vaddr + sg.filesz) {
            u64 off = sg.offset + (va - sg.vaddr);
            if (off >= b.data.size()) return nullptr;
            avail = size_t(std::min<u64>(sg.vaddr + sg.filesz - va, b.data.size() - off));
            return b.data.data() + off;
        }
    }
    return nullptr;
}

// Run the database over an ELF's discovered functions. For every function still
// named SUB_ (i.e. no symbol and no user rename), read its bytes and try to
// identify it. On a unique, confident, architecture-matched hit, set the name
// and mark f.from = "lib". A real symbol or a user rename is never touched
// (they are not SUB_); an ambiguous hit is deliberately left SUB_ and counted.
// Returns the number named; fills `st` when given.
inline size_t applyLibSignaturesElf(const Binary& b, const ElfInfo& e,
                                    std::vector<FuncInfo>& funcs, const libsig::Db& db,
                                    LibMatchStats* st = nullptr) {
    LibMatchStats local;
    auto t0 = std::chrono::steady_clock::now();
    uint8_t arch = libsig::archIdFromEnum(e.archEnum);
    // Architecture guard at the top: if the binary's arch is unknown to us, or
    // the database holds nothing for it, do not run — an arm64 signature must
    // never be tried against x86 bytes.
    if (arch == libsig::ARCH_UNKNOWN || db.size() == 0 || db.countForArch(arch) == 0) {
        if (st) { *st = local; }
        return 0;
    }
    for (auto& f : funcs) {
        // Only functions with no name of their own. "SUB_" is exactly the marker
        // discovery assigns to an unnamed function (Analyzer.cpp), so this both
        // skips real symbols and cannot clobber a user rename.
        if (f.name.rfind("SUB_", 0) != 0) continue;
        local.unknownBefore += 1;
        size_t avail = 0;
        const u8* code = elfCodeAt(b, e, f.addr, avail);
        if (!code || avail < 4) continue;
        local.attempted += 1;
        libsig::MatchResult m = db.match(code, avail, arch);
        if (m.named) {
            f.name = m.name;
            f.from = "lib";
            local.named += 1;
        } else if (m.collision) {
            local.collisions += 1;
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    local.ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    if (st) *st = local;
    return local.named;
}

} // namespace sako
