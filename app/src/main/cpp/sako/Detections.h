// Detections — anti-analysis & pinning scanner over an already-built context.
//
// This is the capstone on find_string_xrefs (Engine::xrefsTo). It reuses the
// exact same reference machinery: a token names a string, the string is found
// in the string table, and the sites that reference it are mapped to their
// containing functions through the SAME c.xrefs store xrefsTo/count_xrefs_to
// read. A referencing function under a category is a detection; a matched
// string with no reference is an unattributed hit that is still reported.
//
// It is header-only ON PURPOSE, exactly like the library recogniser (LibSig.h)
// and the diff matcher (BinDiff.h): the pattern DB and the scan compile into
// the engine with NO change to the build system — no new source in CMakeLists,
// no asset, no JNI of its own. Engine::detect (Engine.cpp) ensures the analysis
// context and calls scan() with the three things it already holds — the string
// table, the function list and the reference map — then serialises the result.
//
// Nothing here parses the binary or emits JSON. The site -> containing-function
// resolution mirrors Engine::xrefsTo byte for byte (the sorted (start,index)
// table binary-searched per site); the demangled DISPLAY name is applied by the
// caller at serialisation time, the same demangle(looksMangled(...)) xrefsTo
// uses, so the two features can never name one function two different ways.
#pragma once
#include "Types.h"
#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace sako {
namespace detections {

// How much a single matched token is worth on its own. Some tokens are broad
// ("frida", "qemu", "gmain") and match far more than the routine they name;
// they are still reported, but at Low so the user weighs them accordingly,
// while a token that all but names the routine ("re.frida.server",
// "CertificatePinner", "/system/bin/su") is High. Ordered so max() upgrades.
enum class Confidence { Low = 0, Medium = 1, High = 2 };

inline const char* confidenceName(Confidence c) {
    switch (c) {
        case Confidence::High:   return "high";
        case Confidence::Medium: return "medium";
        default:                 return "low";
    }
}

// ---- the pattern database: ONE place, easy to extend --------------------
// Each category is a name and a list of (token, confidence). A token is matched
// case-insensitively against the string table and (case-sensitively) as a
// substring of a function/symbol name. Adding a category or a token is a line
// here and nothing else — the scan, the JSON, the MCP tool and the UI all read
// this table. Paths like the su binaries live here as STRING literals, never in
// a comment, so they cannot open a nested block comment.
struct Sig { const char* token; Confidence conf; };
struct Category { const char* name; std::vector<Sig> tokens; };

inline const std::vector<Category>& database() {
    static const std::vector<Category> db = {
        { "ssl-pinning", {
            { "pinned", Confidence::Medium },
            { "pinning", Confidence::Medium },
            { "CertificatePinner", Confidence::High },
            { "X509TrustManager", Confidence::High },
            { "checkServerTrusted", Confidence::High },
            { "SSL_get_verify_result", Confidence::High },
            { "X509_verify_cert", Confidence::High },
            { "SSL_CTX_set_custom_verify", Confidence::High },
            { "public key pin", Confidence::High },
            { "sha256/", Confidence::Medium },
        } },
        { "root-detection", {
            { "/system/bin/su", Confidence::High },
            { "/system/xbin/su", Confidence::High },
            { "/sbin/su", Confidence::High },
            { "magisk", Confidence::High },
            { "MagiskSU", Confidence::High },
            { "com.topjohnwu.magisk", Confidence::High },
            { "Superuser.apk", Confidence::High },
            { "test-keys", Confidence::Medium },
            { "which su", Confidence::High },
            { "eu.chainfire.supersu", Confidence::High },
        } },
        { "anti-debug", {
            { "ptrace", Confidence::Medium },
            { "TracerPid", Confidence::High },
            { "/proc/self/status", Confidence::High },
            { "PTRACE_TRACEME", Confidence::High },
        } },
        { "anti-frida", {
            { "frida", Confidence::Low },
            { "gum-js-loop", Confidence::High },
            { "gmain", Confidence::Low },
            { "re.frida.server", Confidence::High },
            { "frida-agent", Confidence::High },
            { "linjector", Confidence::High },
            { "frida-gadget", Confidence::High },
            { "27042", Confidence::Medium },
        } },
        { "emulator-detection", {
            { "goldfish", Confidence::High },
            { "ranchu", Confidence::High },
            { "qemu", Confidence::Low },
            { "ro.kernel.qemu", Confidence::High },
            { "generic_x86", Confidence::Medium },
            { "genymotion", Confidence::High },
            { "bluestacks", Confidence::High },
            { "/dev/socket/qemud", Confidence::High },
        } },
        { "tamper-detection", {
            { "isDebuggerConnected", Confidence::High },
            { "GET_SIGNATURES", Confidence::High },
            { "signingInfo", Confidence::Medium },
            { "getInstallerPackageName", Confidence::High },
        } },
    };
    return db;
}

// ---- one detection ------------------------------------------------------
// A category-under-a-function finding, or (funcAddr == 0) an unattributed hit
// on a string that nothing references. `evidence` is the representative matched
// token and `tokens` carries every distinct token that folded into this row, so
// no match is ever hidden. `source` is "string" (a referenced string), "name"
// (a function/symbol name) or "mixed" (both). `site` is the instruction to land
// on — a referencing site for a string match, the function start for a name
// match; `stringAddr`/`value` describe the string when one drove the match.
struct Detection {
    std::string category;
    Confidence  confidence = Confidence::Low;
    u64         funcAddr = 0;           // 0 = unattributed (no containing function)
    std::string funcName;               // raw symbol; caller demangles for display
    std::string evidence;               // representative matched token
    std::vector<std::string> tokens;    // every distinct token, first-seen order
    std::string source;                 // "string" | "name" | "mixed"
    u64         site = 0;               // instruction to jump to (string match), else funcAddr
    u64         stringAddr = 0;         // matched string address, when a string drove it
    std::string value;                  // matched string text, when a string drove it
    int         hits = 0;               // token x site matches folded into this row
};

struct ScanResult {
    std::vector<Detection> detections;  // sorted by (category order, confidence, funcAddr)
    size_t stringMatches = 0;           // matched (string, token) pairs seen
    size_t nameMatches = 0;             // matched (function, token) pairs seen
    size_t unattributed = 0;            // detections with no containing function
};

// ---- internals ----------------------------------------------------------
namespace detail {

inline std::string toLowerAscii(const std::string& s) {
    std::string out(s.size(), '\0');
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        out[i] = (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
    }
    return out;
}

// A token flattened out of the database once, with its category index and a
// lowercased copy for the case-insensitive string pass.
struct FlatTok { int cat; std::string raw; std::string lower; Confidence conf; };

inline std::vector<FlatTok> flatten() {
    std::vector<FlatTok> flat;
    const auto& db = database();
    for (int ci = 0; ci < int(db.size()); ++ci) {
        for (const auto& s : db[ci].tokens) {
            std::string raw = s.token;
            flat.push_back({ ci, raw, toLowerAscii(raw), s.conf });
        }
    }
    return flat;
}

// One aggregated finding, keyed by (place, category) while it is being built.
struct Agg {
    int cat = 0;
    Confidence conf = Confidence::Low;
    u64 funcAddr = 0;
    std::string funcName;
    u64 site = 0;
    u64 stringAddr = 0;
    std::string value;
    std::vector<std::string> tokens;
    bool fromString = false;
    bool fromName = false;
    int hits = 0;
};

inline void addToken(Agg& a, const std::string& token, Confidence conf) {
    ++a.hits;
    bool higher = int(conf) > int(a.conf);
    if (higher) a.conf = conf;
    auto it = std::find(a.tokens.begin(), a.tokens.end(), token);
    if (it == a.tokens.end()) {
        // A new token: the strongest one seen leads the list, so front() is
        // always the representative `evidence`.
        if (higher) a.tokens.insert(a.tokens.begin(), token);
        else a.tokens.push_back(token);
    } else if (higher) {
        a.tokens.erase(it);
        a.tokens.insert(a.tokens.begin(), token);
    }
}

} // namespace detail

// ---- the scan -----------------------------------------------------------
// strings/funcs/xrefs are exactly the fields Engine's Ctx already holds. The
// site -> function step is the same sorted-table binary search Engine::xrefsTo
// runs, for the same reason (a linear scan per site is O(functions) each time).
//
// Source 1 (strings): each string is matched case-insensitively against every
// token; a matched string is looked up ONCE in the reference map and every
// referencing site becomes a detection under the token's category, attributed
// to the function that contains the site. A matched string with no references
// is kept as an unattributed hit — never dropped.
// Source 2 (names): a function whose own name contains a token (substring) is a
// direct detection under that category.
// Attributed detections are deduped by (functionAddr, category); unattributed
// hits by (stringAddr, category). Every distinct matched token is preserved on
// the row it folds into, so the count can rise without any match going silent.
inline ScanResult scan(const std::vector<FoundString>& strings,
                       const std::vector<FuncInfo>& funcs,
                       const std::map<u64, std::vector<Xref>>& xrefs) {
    using namespace detail;
    ScanResult result;
    const auto& db = database();
    std::vector<FlatTok> flat = flatten();

    // Sorted (start, index) table for site -> containing function, built once
    // and binary-searched per site — identical in shape to Engine::xrefsTo's
    // `containing`, so a detection and an xref resolve one site the same way.
    std::vector<std::pair<u64, size_t>> byAddr;
    byAddr.reserve(funcs.size());
    for (size_t i = 0; i < funcs.size(); ++i) byAddr.push_back({ funcs[i].addr, i });
    std::sort(byAddr.begin(), byAddr.end());
    auto containing = [&funcs, &byAddr](u64 a) -> const FuncInfo* {
        auto it = std::upper_bound(byAddr.begin(), byAddr.end(), a,
                                   [](u64 v, const std::pair<u64, size_t>& e) {
                                       return v < e.first;
                                   });
        if (it == byAddr.begin()) return nullptr;
        size_t idx = (it - 1)->second;
        if (idx >= funcs.size()) return nullptr;
        const FuncInfo& f = funcs[idx];
        if (f.addr != (it - 1)->first) return nullptr;
        if (f.size ? (a < f.addr + f.size) : (a == f.addr)) return &f;
        return nullptr;
    };

    std::map<std::pair<u64, int>, Agg> attr;    // (funcAddr, cat) -> attributed
    std::map<std::pair<u64, int>, Agg> unattr;  // (stringAddr, cat) -> unattributed

    // Source 1: string table -> reference map -> containing function.
    for (const auto& s : strings) {
        std::string lower = toLowerAscii(s.value);
        for (const auto& t : flat) {
            if (lower.find(t.lower) == std::string::npos) continue;
            ++result.stringMatches;
            auto xi = xrefs.find(s.addr);
            if (xi == xrefs.end() || xi->second.empty()) {
                // No reference: an unattributed hit, still reported.
                Agg& a = unattr[{ s.addr, t.cat }];
                a.cat = t.cat;
                a.stringAddr = s.addr;
                a.value = s.value;
                a.fromString = true;
                addToken(a, t.raw, t.conf);
                continue;
            }
            for (const auto& x : xi->second) {
                const FuncInfo* f = containing(x.from);
                if (!f) {
                    // A site outside every known function is unattributed too,
                    // keyed on the string so it groups with the string's hits.
                    Agg& a = unattr[{ s.addr, t.cat }];
                    a.cat = t.cat;
                    a.stringAddr = s.addr;
                    a.value = s.value;
                    a.fromString = true;
                    addToken(a, t.raw, t.conf);
                    continue;
                }
                Agg& a = attr[{ f->addr, t.cat }];
                a.cat = t.cat;
                a.funcAddr = f->addr;
                a.funcName = f->name;
                if (a.site == 0) a.site = x.from;          // first referencing site
                if (a.stringAddr == 0) { a.stringAddr = s.addr; a.value = s.value; }
                a.fromString = true;
                addToken(a, t.raw, t.conf);
            }
        }
    }

    // Source 2: a function whose own name contains a token.
    for (const auto& f : funcs) {
        if (f.name.empty()) continue;
        for (const auto& t : flat) {
            if (f.name.find(t.raw) == std::string::npos) continue;
            ++result.nameMatches;
            Agg& a = attr[{ f.addr, t.cat }];
            a.cat = t.cat;
            a.funcAddr = f.addr;
            a.funcName = f.name;
            a.fromName = true;
            addToken(a, t.raw, t.conf);
        }
    }

    // Materialise. attributed first, then unattributed; within each, the
    // database's category order, then confidence high->low, then address.
    auto emit = [&](const Agg& a, bool attributed) {
        Detection d;
        d.category = db[a.cat].name;
        d.confidence = a.conf;
        d.funcAddr = a.funcAddr;
        d.funcName = a.funcName;
        d.tokens = a.tokens;
        d.evidence = a.tokens.empty() ? std::string() : a.tokens.front();
        d.source = (a.fromString && a.fromName) ? "mixed"
                 : (a.fromName ? "name" : "string");
        d.site = a.site ? a.site : a.funcAddr;   // name-only lands on the function
        d.stringAddr = a.stringAddr;
        d.value = a.value;
        d.hits = a.hits;
        if (!attributed) ++result.unattributed;
        result.detections.push_back(std::move(d));
    };
    for (const auto& kv : attr) emit(kv.second, true);
    for (const auto& kv : unattr) emit(kv.second, false);

    std::stable_sort(result.detections.begin(), result.detections.end(),
                     [&db](const Detection& x, const Detection& y) {
        int cx = 0, cy = 0;
        for (int i = 0; i < int(db.size()); ++i) {
            if (x.category == db[i].name) cx = i;
            if (y.category == db[i].name) cy = i;
        }
        if (cx != cy) return cx < cy;
        bool ax = x.funcAddr != 0, ay = y.funcAddr != 0;
        if (ax != ay) return ax;                       // attributed before unattributed
        if (x.confidence != y.confidence)
            return int(x.confidence) > int(y.confidence);
        return x.funcAddr != y.funcAddr ? x.funcAddr < y.funcAddr
                                        : x.stringAddr < y.stringAddr;
    });
    return result;
}

} // namespace detections
} // namespace sako
