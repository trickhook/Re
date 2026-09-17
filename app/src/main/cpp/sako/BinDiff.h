// BinDiff — binary-to-binary function diffing (patch analysis / variant tracking).
//
// Two LINKED binaries are compared and every function is classified identical,
// changed, added (new only) or removed (old only), with a similarity score for
// the changed ones. This is the "what did this update change" workflow.
//
// This header is dependency-free ON PURPOSE (only the standard library): it
// knows nothing about the engine's own types, so it compiles into Engine.cpp
// with no new source in CMakeLists (the same reasoning as LibSig.h) and can be
// exercised by a host harness directly. Engine.cpp reduces each of its analysed
// functions to a bindiff::Func — an address, a name, a raw-byte hash and the
// NORMALIZED instruction stream — and hands two vectors of them to diffFunctions.
//
// The matcher is deliberately ordered so a confident match wins first and a
// wrong pairing is never forced: an honestly-unmatched function reported as
// added/removed is better than a bad pair.
//
//   1. exact bytes        — byte-identical function bodies -> identical
//   2. symbol name        — a real name present on both sides pairs them
//   3. normalized stream  — the BinDiff idea: the sequence of mnemonics with
//                           operands/immediates/branch targets MASKED, so the
//                           same function matches across versions even though
//                           addresses and relocated operands differ. This is
//                           what pairs a function that lost its symbol or moved,
//                           AND what keeps address/relocation noise from being
//                           reported as a change.
//   4. structural         — for the leftovers, pair by normalized-instruction
//                           overlap gated on CFG size, above a conservative
//                           threshold; the rest stay added/removed.
//
// CLASSIFICATION RULE (and its one deliberate subtlety). A pair is `identical`
// when its raw bytes are equal OR its normalized instruction SEQUENCE is equal.
// The second half is the whole point: two versions of a leaf function that were
// only relocated (call targets, RIP-relative displacements and absolute
// addresses re-encoded) have DIFFERENT bytes but the SAME normalized stream, and
// calling those "changed" is exactly the false positive this design exists to
// avoid. A pair that is matched (by name or structure) but whose normalized
// streams differ is `changed`, with a similarity score. The cost of masking
// every immediate is that a change touching ONLY a constant value (and no
// instruction) is normalized away and reported identical; any change that adds,
// removes or alters an instruction is caught. That tradeoff is chosen on purpose
// — robustness against relocation noise first — and stated in the report.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <deque>
#include <algorithm>

namespace bindiff {

using u64 = uint64_t;

// ---- FNV-1a 64-bit, used for byte hashes, per-instruction token hashes and the
// normalized-sequence hash. A 64-bit hash over function bodies has a negligible
// collision rate at the scale of a binary (tens of thousands of functions), and
// every byte-hash comparison is additionally guarded by the byte LENGTH.
static const u64 kFnvOffset = 1469598103934665603ULL;
static const u64 kFnvPrime  = 1099511628211ULL;
inline u64 fnv1a(const void* data, size_t n, u64 h = kFnvOffset) {
    const unsigned char* p = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= kFnvPrime; }
    return h;
}
inline u64 fnvMix(u64 h, u64 v) {
    for (int i = 0; i < 8; ++i) { h ^= (v & 0xff); h *= kFnvPrime; v >>= 8; }
    return h;
}

// Normalize one instruction's operand text: replace every numeric literal
// (hex or decimal immediate, branch target, memory displacement) with a single
// placeholder, while leaving register names — which embed digits, r8/x30/xmm0 —
// untouched. A digit only masks when it does not continue an identifier, so
// "r8"/"x30" survive but "0x2f01", "#2" and a bare "16" become 'K'. This is what
// makes an unchanged-but-relocated function normalize to the same token stream
// as its earlier version: every address the linker re-encoded is a K on both
// sides.
inline std::string maskOperands(const std::string& ops) {
    std::string out;
    out.reserve(ops.size());
    size_t i = 0, n = ops.size();
    auto isIdent = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '_';
    };
    while (i < n) {
        char c = ops[i];
        // 0x....  hex literal
        if (c == '0' && i + 1 < n && (ops[i + 1] == 'x' || ops[i + 1] == 'X') &&
            (i == 0 || !isIdent(ops[i - 1]))) {
            i += 2;
            while (i < n) {
                char h = ops[i];
                bool hex = (h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F');
                if (!hex) break;
                ++i;
            }
            out += 'K';
            continue;
        }
        // decimal literal that starts a token (not the tail of a register name)
        if (c >= '0' && c <= '9' && (i == 0 || !isIdent(ops[i - 1]))) {
            while (i < n && ops[i] >= '0' && ops[i] <= '9') ++i;
            out += 'K';
            continue;
        }
        out += c;
        ++i;
    }
    return out;
}

// One normalized instruction token: the mnemonic verbatim (je and jne stay
// distinct, add and imul stay distinct) plus the masked operand shape.
inline u64 tokenHash(const std::string& mnem, const std::string& ops) {
    u64 h = fnv1a(mnem.data(), mnem.size());
    h ^= 0x9e3779b97f4a7c15ULL; h *= kFnvPrime;   // separator so "a"+"bc" != "ab"+"c"
    std::string m = maskOperands(ops);
    h = fnv1a(m.data(), m.size(), h);
    return h;
}

// A function reduced to what the matcher needs. Engine.cpp fills this from its
// disassembly; nothing here depends on the engine's own types.
struct Func {
    u64 addr = 0;
    std::string name;      // symbol / recovered / display name, or "SUB_xxxx"
    std::string from;      // provenance tag (symbol / lib / scan / ...)
    bool hasName = false;  // a real name, not SUB_xxxx / empty
    u64 byteHash = 0;      // FNV over the raw function bytes
    size_t byteLen = 0;    // length hashed (0 = bytes unavailable)
    u64 normHash = 0;      // FNV over the normalized token SEQUENCE (order-sensitive)
    std::vector<u64> tokens;  // per-instruction token hashes, in program order
    int cfgBlocks = 0;     // basic-block count (structural signal)

    void finish() {
        u64 h = kFnvOffset;
        for (u64 t : tokens) h = fnvMix(h, t);
        normHash = h;
    }
    size_t instrs() const { return tokens.size(); }
};

// Bag (multiset) similarity over normalized instruction tokens:
//     2 * |A ∩ B| / (|A| + |B|)          (Dice), in [0,1]
// i.e. the fraction of normalized instructions the two functions have in common.
// 1.0 iff the two multisets are equal; returns 0.0 when either side has no
// disassembly, which is "no measured overlap", not "identical".
inline double bagSim(const std::vector<u64>& a, const std::vector<u64>& b) {
    if (a.empty() || b.empty()) return 0.0;
    std::unordered_map<u64, int> ca;
    ca.reserve(a.size() * 2);
    for (u64 t : a) ++ca[t];
    size_t inter = 0;
    for (u64 t : b) {
        auto it = ca.find(t);
        if (it != ca.end() && it->second > 0) { --it->second; ++inter; }
    }
    return (2.0 * double(inter)) / double(a.size() + b.size());
}

struct ChangedPair { size_t ia = 0, ib = 0; double similarity = 0; };

struct Result {
    size_t identical = 0;          // total identical (exact + fingerprint)
    size_t identicalExact = 0;     // byte-identical bodies
    size_t identicalFingerprint = 0; // equal normalized stream, different bytes
    std::vector<ChangedPair> changed;  // matched, normalized streams differ
    std::vector<size_t> added;     // indices into B with no counterpart in A
    std::vector<size_t> removed;   // indices into A with no counterpart in B
    size_t nameMatched = 0;        // pairs established by symbol name
    size_t fpMatched = 0;          // pairs established by normalized stream
    size_t structMatched = 0;      // pairs established by the structural step
    bool structuralRun = true;     // false when the leftover set was too large
};

// Pair below this normalized-instruction overlap are never joined by the
// structural step — an unmatched function is reported honestly rather than
// forced into a wrong pair.
static const double kStructThreshold = 0.60;
// The structural step is O(leftoverA * leftoverB); skip it (leftovers stay
// added/removed) when either side's leftover count exceeds this, so a diff of
// two huge stripped binaries stays bounded. Reported via Result::structuralRun.
static const size_t kStructMaxLeftover = 3000;

// The diff. A is the OLD binary's functions, B the NEW binary's; identical,
// changed, added and removed are reported from that orientation (added = in B
// only, removed = in A only). Deterministic: inputs are processed in the order
// given, so two runs on the same inputs produce the same pairing.
inline Result diffFunctions(const std::vector<Func>& A, const std::vector<Func>& B) {
    Result r;
    std::vector<char> mA(A.size(), 0), mB(B.size(), 0);

    auto record = [&](size_t ia, size_t ib) {
        // Reproduce classifyPair but capture indices for the changed list.
        const Func& a = A[ia];
        const Func& b = B[ib];
        if (a.byteLen && a.byteLen == b.byteLen && a.byteHash == b.byteHash) {
            ++r.identical; ++r.identicalExact; return;
        }
        if (a.instrs() && b.instrs() && a.normHash == b.normHash) {
            ++r.identical; ++r.identicalFingerprint; return;
        }
        r.changed.push_back(ChangedPair{ ia, ib, bagSim(a.tokens, b.tokens) });
    };

    // ---- step 1: exact bytes. A byte-identical body is the same code, whatever
    // its name; pair them 1:1 (any surplus on one side falls through to later
    // steps or to added/removed). Key on (hash,len) so a hash collision across
    // differing lengths cannot pair.
    {
        std::unordered_map<u64, std::deque<size_t>> byHash;
        byHash.reserve(B.size() * 2);
        for (size_t j = 0; j < B.size(); ++j) {
            if (!B[j].byteLen) continue;
            byHash[B[j].byteHash ^ (u64(B[j].byteLen) * kFnvPrime)].push_back(j);
        }
        for (size_t i = 0; i < A.size(); ++i) {
            if (!A[i].byteLen) continue;
            u64 key = A[i].byteHash ^ (u64(A[i].byteLen) * kFnvPrime);
            auto it = byHash.find(key);
            if (it == byHash.end()) continue;
            // Skip B entries already matched (they linger in the deque).
            while (!it->second.empty() && mB[it->second.front()]) it->second.pop_front();
            if (it->second.empty()) continue;
            size_t j = it->second.front();
            if (A[i].byteLen != B[j].byteLen || A[i].byteHash != B[j].byteHash) continue;
            it->second.pop_front();
            mA[i] = mB[j] = 1;
            ++r.identical; ++r.identicalExact;
        }
    }

    // ---- step 2: symbol name. A real name on both sides is the strongest pair
    // after exact bytes; equal name + different bytes is a candidate change.
    {
        std::unordered_map<std::string, std::deque<size_t>> byName;
        for (size_t j = 0; j < B.size(); ++j)
            if (!mB[j] && B[j].hasName) byName[B[j].name].push_back(j);
        for (size_t i = 0; i < A.size(); ++i) {
            if (mA[i] || !A[i].hasName) continue;
            auto it = byName.find(A[i].name);
            if (it == byName.end()) continue;
            while (!it->second.empty() && mB[it->second.front()]) it->second.pop_front();
            if (it->second.empty()) continue;
            size_t j = it->second.front();
            it->second.pop_front();
            mA[i] = mB[j] = 1;
            ++r.nameMatched;
            record(i, j);
        }
    }

    // ---- step 3: normalized instruction stream. Pairs a function that lost its
    // symbol or whose name changed, and (the no-false-positive case) recognises
    // a relocated-but-unchanged function whose bytes differ. Only functions with
    // real disassembly take part (instrs() > 0), so the FNV-of-nothing seed can
    // never collapse every no-disasm function onto one key.
    {
        std::unordered_map<u64, std::deque<size_t>> byNorm;
        for (size_t j = 0; j < B.size(); ++j)
            if (!mB[j] && B[j].instrs()) byNorm[B[j].normHash].push_back(j);
        for (size_t i = 0; i < A.size(); ++i) {
            if (mA[i] || !A[i].instrs()) continue;
            auto it = byNorm.find(A[i].normHash);
            if (it == byNorm.end()) continue;
            while (!it->second.empty() && mB[it->second.front()]) it->second.pop_front();
            if (it->second.empty()) continue;
            size_t j = it->second.front();
            it->second.pop_front();
            mA[i] = mB[j] = 1;
            ++r.fpMatched;
            record(i, j);   // equal normHash -> classified identical (fingerprint)
        }
    }

    // ---- step 4: structural. Greedy over the remaining pairs by normalized
    // overlap, gated on a CFG-size ratio and a conservative threshold so a lone
    // added and a lone removed function are not forced together.
    std::vector<size_t> leftA, leftB;
    for (size_t i = 0; i < A.size(); ++i) if (!mA[i]) leftA.push_back(i);
    for (size_t j = 0; j < B.size(); ++j) if (!mB[j]) leftB.push_back(j);

    if (leftA.size() <= kStructMaxLeftover && leftB.size() <= kStructMaxLeftover) {
        struct Cand { double sim; size_t i, j; };
        std::vector<Cand> cands;
        for (size_t i : leftA) {
            if (!A[i].instrs()) continue;
            for (size_t j : leftB) {
                if (!B[j].instrs()) continue;
                // Symbol evidence beats structure: if BOTH sides carry a real,
                // distinct name and step 2 still did not pair them, they are a
                // removal and an addition, not a rename — never fold two named
                // functions together on shape alone (tiny leaf functions are
                // ~75% prologue/epilogue and would mis-pair). Structural pairing
                // is for recovering a function that LOST its symbol, so require
                // at least one unnamed side.
                if (A[i].hasName && B[j].hasName) continue;
                // CFG-size guard: skip obviously different shapes cheaply.
                int ba = A[i].cfgBlocks, bb = B[j].cfgBlocks;
                if (ba && bb) {
                    int lo = std::min(ba, bb), hi = std::max(ba, bb);
                    if (double(lo) < 0.5 * double(hi)) continue;
                }
                double s = bagSim(A[i].tokens, B[j].tokens);
                if (s >= kStructThreshold) cands.push_back(Cand{ s, i, j });
            }
        }
        std::sort(cands.begin(), cands.end(), [](const Cand& x, const Cand& y) {
            if (x.sim != y.sim) return x.sim > y.sim;
            if (x.i != y.i) return x.i < y.i;
            return x.j < y.j;
        });
        for (const Cand& c : cands) {
            if (mA[c.i] || mB[c.j]) continue;
            mA[c.i] = mB[c.j] = 1;
            ++r.structMatched;
            record(c.i, c.j);
        }
    } else {
        r.structuralRun = false;
    }

    // ---- leftovers: honest added / removed.
    for (size_t i = 0; i < A.size(); ++i) if (!mA[i]) r.removed.push_back(i);
    for (size_t j = 0; j < B.size(); ++j) if (!mB[j]) r.added.push_back(j);
    return r;
}

} // namespace bindiff
