// Control Flow Graph builder — partitions a linear instruction list into
// basic blocks and connects fall-through / branch / jump edges.
#include "Analysis.h"
#include <cstdlib>
#include <set>

namespace sako {

namespace {

enum class Kind { Other, Ret, Ujmp, Cjmp, Call };

struct Branch {
    Kind kind = Kind::Other;
    u64 target = 0;
    bool hasTarget = false;
};

Branch classify(const AsmLine& l, const std::string& arch) {
    Branch br;
    const std::string& m = l.mnem;

    auto parseTarget = [&](u64 pc, size_t instrLen) -> bool {
        // find first "0x..." token in ops
        size_t p = l.ops.find("0x");
        if (p == std::string::npos) return false;
        char* end = nullptr;
        unsigned long long v = strtoull(l.ops.c_str() + p + 2, &end, 16);
        if (end == l.ops.c_str() + p + 2) return false;
        // heuristic sanity: direct branch targets must be close to pc OR anywhere in func
        (void)pc; (void)instrLen;
        br.target = u64(v);
        return true;
    };

    if (arch == "ARM64") {
        if (m == "ret" || m == "retaa" || m == "retab") { br.kind = Kind::Ret; return br; }
        if (m == "b" || m == "br") {
            br.kind = Kind::Ujmp;
            if (m == "b") { br.hasTarget = parseTarget(l.addr, 4); if (!br.hasTarget) br.kind = Kind::Ret; }
            return br;
        }
        if (m.rfind("b.", 0) == 0 || m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz") {
            br.kind = Kind::Cjmp;
            br.hasTarget = parseTarget(l.addr, 4);
            return br;
        }
        if (m == "bl" || m == "blr") { br.kind = Kind::Call; return br; }
        return br;
    }

    // x86
    if (m == "ret" || m == "retn" || m == "retq" || m == "retf") { br.kind = Kind::Ret; return br; }
    if (m == "jmp") {
        br.kind = Kind::Ujmp;
        br.hasTarget = parseTarget(l.addr, 0);
        if (!br.hasTarget) br.kind = Kind::Ret; // indirect jmp → treat as block end
        return br;
    }
    if (!m.empty() && m[0] == 'j' && m != "jmp") {
        br.kind = Kind::Cjmp;
        br.hasTarget = parseTarget(l.addr, 0);
        return br;
    }
    if (m == "call") { br.kind = Kind::Call; return br; }
    return br;
}

} // namespace

std::vector<CfgBlock> buildCfg(const std::vector<AsmLine>& lines, u64 funcStart, u64 funcEnd,
                               const std::string& arch, size_t* found) {
    std::vector<CfgBlock> blocks;
    if (lines.empty()) return blocks;

    const size_t cap = 512;
    std::map<u64, size_t> lineAt;
    for (size_t i = 0; i < lines.size(); ++i) lineAt[lines[i].addr] = i;

    std::set<size_t> leaders;
    leaders.insert(0);
    std::vector<Branch> brs(lines.size());

    for (size_t i = 0; i < lines.size(); ++i) {
        brs[i] = classify(lines[i], arch);
        if (brs[i].kind == Kind::Ujmp || brs[i].kind == Kind::Cjmp || brs[i].kind == Kind::Ret) {
            if (i + 1 < lines.size()) leaders.insert(i + 1);
            if (brs[i].hasTarget && brs[i].target >= funcStart && brs[i].target < funcEnd) {
                auto it = lineAt.find(brs[i].target);
                if (it != lineAt.end()) leaders.insert(it->second);
            }
        }
    }

    // build blocks
    //
    // The walk runs to the end of the listing whatever the cap does, and only
    // the PUSH is capped: `found` then carries how many blocks the function
    // has, so a graph drawn from 512 of them can say so. Stopping the walk
    // instead is what made the cap invisible -- the caller got 512 blocks and
    // no way to tell them from a function that has exactly 512.
    size_t i = 0;
    size_t nFound = 0;
    std::vector<size_t> ends; // last line index of each block
    while (i < lines.size()) {
        size_t start = i;
        while (i < lines.size()) {
            if (brs[i].kind != Kind::Other) { ++i; break; }
            // stop before next leader
            if (i + 1 < lines.size() && leaders.count(i + 1)) { ++i; break; }
            ++i;
        }
        ++nFound;
        if (blocks.size() >= cap) continue;   // counted, not carried
        CfgBlock blk;
        blk.id = int(blocks.size());
        blk.start = lines[start].addr;
        blk.end = (i < lines.size()) ? lines[i].addr : (lines.back().addr + 4);
        blk.nInstr = int(i - start);
        if (blk.end <= blk.start) blk.end = blk.start + 4;
        blocks.push_back(blk);
        ends.push_back(i - 1);
    }
    if (found) *found = nFound;
    if (blocks.empty()) return blocks;

    auto blockOfAddr = [&](u64 a) -> int {
        if (blocks.size() > 1) {
            // binary search by start
            size_t lo = 0, hi = blocks.size() - 1;
            while (lo < hi) {
                size_t mid = (lo + hi + 1) / 2;
                if (blocks[mid].start <= a) lo = mid; else hi = mid - 1;
            }
            if (blocks[lo].start <= a && a < blocks[lo].end) return blocks[lo].id;
            return -1;
        }
        return blocks[0].start <= a && a < blocks[0].end ? 0 : -1;
    };

    for (size_t b = 0; b < blocks.size(); ++b) {
        size_t last = ends[b];
        const Branch& br = brs[last];
        int self = blocks[b].id;
        int fall = (last + 1 < lines.size()) ? blockOfAddr(lines[last + 1].addr) : -1;
        if (fall < 0 && last + 1 < lines.size()) fall = (last + 1 < lines.size() && b + 1 < blocks.size()) ? blocks[b + 1].id : -1;

        switch (br.kind) {
            case Kind::Ret:
                break;
            case Kind::Ujmp:
                if (br.hasTarget && br.target >= funcStart && br.target < funcEnd) {
                    int t = blockOfAddr(br.target);
                    if (t >= 0 && t != self) blocks[b].succ.push_back(t);
                }
                break;
            case Kind::Cjmp: {
                if (br.hasTarget && br.target >= funcStart && br.target < funcEnd) {
                    int t = blockOfAddr(br.target);
                    if (t >= 0) blocks[b].succ.push_back(t);
                }
                if (fall >= 0 && fall != self) blocks[b].succ.push_back(fall);
                break;
            }
            default:
                if (fall >= 0 && fall != self && fall != int(b)) blocks[b].succ.push_back(fall);
                break;
        }
        // dedupe
        auto& v = blocks[b].succ;
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
    return blocks;
}

} // namespace sako
