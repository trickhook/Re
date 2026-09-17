// LibSigFormat — FLIRT-style library-function signatures: the on-disk format,
// the CRC, and the byte-level matcher. Deliberately self-contained (only the C++
// standard library) so it is shared, byte-for-byte, by two programs that must
// agree exactly: the host generator in tools/ that WRITES a database from a
// static library, and the engine matcher (LibSig.h) that READS one and names
// functions in a stripped binary. Nothing here depends on the rest of the
// engine; the engine-facing glue lives in LibSig.h.
//
// ---------------------------------------------------------------------------
// Why a signature is not raw bytes
// ---------------------------------------------------------------------------
// The same library function, compiled once and linked into two different
// programs, does not have the same bytes: every call target, PC-relative data
// reference and absolute address is a RELOCATION the linker fills in with a
// value that depends on where everything landed. FLIRT's insight is that a
// relocatable object (.o, and thus .a) still carries its relocation table, so
// it tells you EXACTLY which bytes vary. The generator masks precisely those
// byte ranges; everything else is invariant and is what a signature is made of.
//
// ---------------------------------------------------------------------------
// The record (what identifies one function)
// ---------------------------------------------------------------------------
//   * arch        the architecture, so an arm64 signature can never name an x86
//                 function (and vice versa) — a hard guard, checked first.
//   * pattern     the first min(32,len) bytes, variant bytes zeroed, plus a
//                 32-bit mask saying which of those bytes are fixed. This is a
//                 cheap pre-filter and the index key.
//   * total_len   the exact function length, from the .o symbol's st_size.
//   * full_crc    CRC32 over the WHOLE function body [0,total_len), with every
//                 variant (relocated) byte replaced by 0x00. This is the strong
//                 check: it covers the entire function, not just the prefix.
//   * var[]       the variant byte ranges over the whole function, so the
//                 matcher can reproduce that same canonicalisation on a
//                 candidate's bytes before CRCing them.
//   * flags       AMBIGUOUS when two genuinely different library functions
//                 share this exact canonical form (see the collision note).
//
// ---------------------------------------------------------------------------
// Collisions — a wrong name is worse than no name
// ---------------------------------------------------------------------------
// Two functions can share a prefix (memcpy/memmove) — the full CRC and length
// separate those. The harder case: two DIFFERENT functions that are identical
// except in bytes we (correctly) wildcarded, e.g. two wrappers that differ only
// in which function they tail-call. After canonicalisation they are the same
// record. The generator detects that at build time and marks the record
// AMBIGUOUS; the matcher refuses to name on it and counts a collision. Aliases
// (memcpy and __memcpy — the SAME code at the SAME location) are folded to a
// single non-ambiguous record at generation, so they do NOT count as a
// collision; see the generator.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>

namespace libsig {

// ---- architecture guard ----------------------------------------------------
enum ArchId : uint8_t {
    ARCH_UNKNOWN = 0,
    ARCH_X86_64  = 1,
    ARCH_X86     = 2,
    ARCH_ARM64   = 3,
    ARCH_ARM     = 4,
};

// Maps the engine's archEnum string ("X86_64", "ARM64", ...) to an ArchId.
inline ArchId archIdFromEnum(const std::string& a) {
    if (a == "X86_64") return ARCH_X86_64;
    if (a == "X86")    return ARCH_X86;
    if (a == "ARM64")  return ARCH_ARM64;
    if (a == "ARM")    return ARCH_ARM;
    return ARCH_UNKNOWN;
}
inline const char* archName(ArchId a) {
    switch (a) {
        case ARCH_X86_64: return "X86_64";
        case ARCH_X86:    return "X86";
        case ARCH_ARM64:  return "ARM64";
        case ARCH_ARM:    return "ARM";
        default:          return "UNKNOWN";
    }
}

// ---- on-disk constants -----------------------------------------------------
// Header: magic[8] "NOCTSIG1", u32 version, u32 count, u32 flags, u32 reserved.
static const char    kMagic[8]   = { 'N','O','C','T','S','I','G','1' };
static const uint32_t kVersion   = 1;
static const uint32_t kHeaderLen = 8 + 4 * 4;   // 24 bytes

// Sizing limits — a signature shorter than this is too collision-prone to be
// worth a name; a pattern is at most 32 bytes; variant ranges are capped so one
// pathological object cannot blow up a record.
static const uint32_t kPatMax        = 32;
static const uint32_t kDefaultMinLen = 16;
static const uint32_t kVarMax        = 255;

// Per-record flags.
enum RecFlags : uint8_t {
    FLAG_AMBIGUOUS = 1u << 0,   // >1 distinct library function shares this form
};

// ---- little-endian helpers (format is LE regardless of host) ---------------
inline uint16_t rdLE16(const uint8_t* p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
inline uint32_t rdLE32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t rdLE64(const uint8_t* p) { return uint64_t(rdLE32(p)) | (uint64_t(rdLE32(p + 4)) << 32); }
inline void wrLE16(std::vector<uint8_t>& o, uint16_t v) { o.push_back(v & 0xFF); o.push_back((v >> 8) & 0xFF); }
inline void wrLE32(std::vector<uint8_t>& o, uint32_t v) {
    o.push_back(v & 0xFF); o.push_back((v >> 8) & 0xFF); o.push_back((v >> 16) & 0xFF); o.push_back((v >> 24) & 0xFF);
}

// ---- CRC32 (zlib/PNG polynomial 0xEDB88420) --------------------------------
// One shared implementation so the generator and the matcher compute the same
// value bit-for-bit. Table built once on first use.
inline const uint32_t* crc32Table() {
    static uint32_t t[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88420u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        init = true;
    }
    return t;
}

// A variant byte range within a function: [off, off+len).
struct VarRange { uint32_t off; uint16_t len; };

// CRC32 over buf[0,len), substituting 0x00 for any byte that falls inside a
// variant range. `vars` must be sorted by off and non-overlapping (the
// generator guarantees this). This is THE canonicalisation both sides run.
inline uint32_t crc32Canon(const uint8_t* buf, uint32_t len, const std::vector<VarRange>& vars) {
    const uint32_t* t = crc32Table();
    uint32_t crc = 0xFFFFFFFFu;
    size_t vi = 0;
    for (uint32_t i = 0; i < len; ++i) {
        while (vi < vars.size() && i >= uint32_t(vars[vi].off) + vars[vi].len) ++vi;
        uint8_t b = buf[i];
        if (vi < vars.size() && i >= vars[vi].off && i < uint32_t(vars[vi].off) + vars[vi].len) b = 0;
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// ---- in-memory record ------------------------------------------------------
struct Sig {
    uint8_t  arch = ARCH_UNKNOWN;
    uint8_t  plen = 0;
    uint8_t  flags = 0;
    uint32_t total_len = 0;
    uint32_t full_crc = 0;
    uint32_t pmask = 0;          // bit i set => pat[i] is a fixed (non-variant) byte
    uint8_t  pat[kPatMax] = {0};
    std::vector<VarRange> vars;
    std::string name;
};

// Derive pattern + mask for the first min(32,len) bytes from a function body
// and its (sorted, merged) variant ranges. Shared so both sides agree.
inline void buildPattern(const uint8_t* buf, uint32_t len, const std::vector<VarRange>& vars,
                         uint8_t pat[kPatMax], uint32_t& pmask, uint8_t& plen) {
    plen = uint8_t(len < kPatMax ? len : kPatMax);
    pmask = 0;
    for (uint32_t i = 0; i < kPatMax; ++i) pat[i] = 0;
    size_t vi = 0;
    for (uint32_t i = 0; i < plen; ++i) {
        while (vi < vars.size() && i >= uint32_t(vars[vi].off) + vars[vi].len) ++vi;
        bool variant = (vi < vars.size() && i >= vars[vi].off && i < uint32_t(vars[vi].off) + vars[vi].len);
        if (!variant) { pat[i] = buf[i]; pmask |= (1u << i); }
    }
}

// ---- the matcher database --------------------------------------------------
struct MatchResult {
    bool named = false;         // a single confident name was found
    bool collision = false;     // a match existed but was ambiguous -> not named
    std::string name;
};

class Db {
public:
    // Parse a database image (the whole file, already read into memory).
    // Returns false with `err` set on a malformed file. On success the records
    // are indexed by their first four fixed pattern bytes for bucket lookup.
    bool loadFromMemory(const uint8_t* data, size_t n, std::string* err = nullptr) {
        auto fail = [&](const char* m) { if (err) *err = m; return false; };
        sigs_.clear(); idx12_.clear(); idx4_.clear(); weak_.clear();
        if (n < kHeaderLen || std::memcmp(data, kMagic, 8) != 0) return fail("bad magic");
        uint32_t ver = rdLE32(data + 8);
        if (ver != kVersion) return fail("unsupported version");
        uint32_t count = rdLE32(data + 12);
        size_t p = kHeaderLen;
        sigs_.reserve(count);
        for (uint32_t r = 0; r < count; ++r) {
            if (p + 50 > n) return fail("truncated record header");
            Sig s;
            s.arch = data[p + 0];
            s.plen = data[p + 1];
            s.flags = data[p + 2];
            uint8_t nvar = data[p + 3];
            s.total_len = rdLE32(data + p + 4);
            s.full_crc  = rdLE32(data + p + 8);
            s.pmask     = rdLE32(data + p + 12);
            std::memcpy(s.pat, data + p + 16, kPatMax);
            uint16_t name_len = rdLE16(data + p + 48);
            p += 50;
            if (p + size_t(nvar) * 6 + name_len > n) return fail("truncated record body");
            s.vars.resize(nvar);
            for (uint8_t v = 0; v < nvar; ++v) {
                s.vars[v].off = rdLE32(data + p); p += 4;
                s.vars[v].len = rdLE16(data + p); p += 2;
            }
            s.name.assign(reinterpret_cast<const char*>(data + p), name_len);
            p += name_len;
            sigs_.push_back(std::move(s));
        }
        buildIndex();
        return true;
    }

    size_t size() const { return sigs_.size(); }
    const std::vector<Sig>& records() const { return sigs_; }

    // How many records of a given arch this DB holds — used for the guard and
    // for honest "of M" reporting.
    size_t countForArch(uint8_t arch) const {
        size_t c = 0;
        for (auto& s : sigs_) if (s.arch == arch) c += 1;
        return c;
    }

    // Try to identify the function whose bytes begin at `code` and of which
    // `avail` bytes are readable (up to the end of its section). Only records of
    // `arch` are considered — the architecture guard. Returns a decision:
    //   named=true            exactly one library function matches -> use .name
    //   collision=true        a match existed but >1 distinct function claims
    //                         it (ambiguous record, or two records disagree)
    //   both false            nothing matched
    MatchResult match(const uint8_t* code, size_t avail, uint8_t arch) const {
        MatchResult out;
        if (avail < 4) return out;
        bool haveName = false, ambiguous = false;
        std::string theName;

        auto consider = [&](uint32_t idx) {
            const Sig& s = sigs_[idx];
            if (s.arch != arch) return;
            if (s.total_len > avail) return;                 // not enough bytes to be this
            // cheap prefix pre-filter
            for (uint32_t i = 0; i < s.plen; ++i)
                if ((s.pmask >> i) & 1u) { if (code[i] != s.pat[i]) return; }
            // strong check: full-body canonical CRC
            if (crc32Canon(code, s.total_len, s.vars) != s.full_crc) return;
            // a confirmed match
            if (s.flags & FLAG_AMBIGUOUS) { ambiguous = true; return; }
            if (!haveName) { haveName = true; theName = s.name; }
            else if (theName != s.name) ambiguous = true;   // two records disagree
        };

        // Two-level bucket lookup, so no path is ever a linear scan of the
        // database — which matters at the scale of the shipped bionic DB. The
        // primary key is a hash of the first 12 fixed bytes: 12 rather than 4
        // because the 4-byte endbr64 prologue, and even the 8-byte
        // endbr64;push rbp;mov rsp,rbp, are shared by a huge fraction of
        // functions and would collapse into one bucket. Records with a wildcard
        // inside those 12 bytes (e.g. endbr64 then a rip-relative load whose
        // displacement is relocated) fall to a 4-byte secondary index; the tiny
        // remainder (no fixed first 4 bytes) is the weak list. A candidate
        // probes all three — a record lives in exactly one.
        if (avail >= 12) {
            auto it = idx12_.find(hash12(code));
            if (it != idx12_.end())
                for (uint32_t idx : it->second) consider(idx);
        }
        auto it4 = idx4_.find(rdLE32(code));
        if (it4 != idx4_.end())
            for (uint32_t idx : it4->second) consider(idx);
        for (uint32_t idx : weak_) consider(idx);

        if (haveName && !ambiguous) { out.named = true; out.name = theName; }
        else if (haveName || ambiguous) { out.collision = true; }
        return out;
    }

private:
    // Hash of the first 12 bytes. A 12-byte key does not fit a machine word, so
    // it is mixed to 64 bits; a hash collision only adds a few candidates that
    // the prefix check then rejects, so correctness does not depend on it.
    static uint64_t hash12(const uint8_t* p) {
        uint64_t a = rdLE64(p);
        uint32_t b = rdLE32(p + 8);
        uint64_t h = a * 0x100000001B3ull;
        h ^= (uint64_t(b) + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2));
        return h;
    }

    void buildIndex() {
        idx12_.clear(); idx4_.clear(); weak_.clear();
        idx12_.reserve(sigs_.size() * 2);
        for (uint32_t i = 0; i < sigs_.size(); ++i) {
            const Sig& s = sigs_[i];
            if (s.plen >= 12 && (s.pmask & 0xFFFu) == 0xFFFu)
                idx12_[hash12(s.pat)].push_back(i);
            else if (s.plen >= 4 && (s.pmask & 0xFu) == 0xFu)
                idx4_[rdLE32(s.pat)].push_back(i);
            else
                weak_.push_back(i);
        }
    }

    std::vector<Sig> sigs_;
    std::unordered_map<uint64_t, std::vector<uint32_t>> idx12_;
    std::unordered_map<uint32_t, std::vector<uint32_t>> idx4_;
    std::vector<uint32_t> weak_;
};

} // namespace libsig
