// Deep analysis v2 implementation.
#include "DeepAnalysis.h"
#include "Demangle.h"
#include <cstring>
#include <cstdlib>
#include <set>
#include <unordered_set>
#include <unordered_map>

namespace sako {

// ---------------------------------------------------------- AddrNames --
void AddrNames::add(u64 addr, const std::string& name, bool keepExisting) {
    if (addr == 0 || name.empty()) return;
    if (keepExisting && map_.count(addr)) return;
    map_[addr] = name;
}

std::string AddrNames::lookup(u64 addr) const {
    auto exact = map_.find(addr);
    if (exact != map_.end()) return exact->second;
    // nearby (name+off) — search first symbol below addr within 4KB
    auto it = map_.upper_bound(addr);
    if (it != map_.begin()) {
        --it;
        u64 base = it->first;
        if (addr - base <= 4096 && addr >= base) {
            return it->second + "+0x" + hexAddr(addr - base).substr(2);
        }
    }
    return "";
}

// ------------------------------------------------------------ helpers --
static std::string lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return r;
}

std::string plainSymbol(const std::string& importName) {
    size_t bang = importName.rfind('!');
    return bang == std::string::npos ? importName : importName.substr(bang + 1);
}

const char* classifyImport(const std::string& importName) {
    std::string n = lower(plainSymbol(importName));
    // dangerous
    if (n == "strcpy" || n == "strcat" || n == "sprintf" || n == "gets" ||
        n == "vsprintf" || n == "wcscpy" || n == "wcscat" || n == "lstrcpya")
        return "dangerous";      // no bounds checking
    if (n == "system" || n == "popen" || n == "execl" || n == "execve" || n == "execlp")
        return "exec";           // process execution
    if (n == "dlopen" || n == "dlsym" || n == "loadlibrarya" || n == "loadlibraryw"
        || n == "getprocaddress")
        return "dynload";        // dynamic loading (packers/hooking)
    if (n == "mmap" || n == "mprotect" || n == "virtualalloc" || n == "virtualprotect")
        return "memory-prot";    // self-modifying code potential
    if (n == "fork" || n == "clone" || n == "createthread" || n == "pthread_create")
        return "thread";
    if (n == "socket" || n == "connect" || n == "send" || n == "recv" ||
        n == "wsastartup" || n == "sendto" || n == "recvfrom")
        return "network";
    if (n == "malloc" || n == "calloc" || n == "realloc" || n == "free" ||
        n == "operatornew" || n == "heapalloc" || n == "virtualallocex")
        return "heap";
    if (n == "memcpy" || n == "memset" || n == "memmove" || n == "strncpy")
        return "memop";
    if (n == "strlen" || n == "strcmp" || n == "strncmp" || n == "strstr" ||
        n == "strchr" || n == "strcasecmp")
        return "string";
    if (n == "open" || n == "openat" || n == "read" || n == "write" || n == "fopen" ||
        n == "createfilea" || n == "createfilew" || n == "readfile" || n == "writefile")
        return "file-io";
    if (n == "rand" || n == "srand" || n == "getrandom" || n == "cryptgenrandom")
        return "random";
    if (n.find("android_log") != std::string::npos || n == "printf" || n == "puts" ||
        n == "fprintf" || n == "snprintf" || n == "cout")
        return "log";
    if (n.find("jni") != std::string::npos || n == "getenv" || n == "java_vm" ||
        n == "register_natives")
        return "jni";
    return nullptr;
}

// --------------------------------------------------------- ELF names --
AddrNames buildAddrNamesElf(const Binary& b, const ElfInfo& e) {
    (void)b;
    AddrNames an;

    // 1. PLT entries (highest priority for code targets)
    for (auto& kv : e.pltNames) {
        std::string nm = plainSymbol(kv.second);
        an.add(kv.first, nm, false);
    }

    // 2. functions from symtab (demangled)
    for (auto& s : e.symbols) {
        if (s.kind != "FUNC" || s.addr == 0 || !s.defined || s.name.empty()) continue;
        an.add(s.addr, s.name, false);
        if (looksMangled(s.name)) {
            std::string d = demangle(s.name);
            if (d != s.name) an.add(s.addr, d, true);
        }
    }
    // 3. exports
    for (auto& s : e.exports) {
        an.add(s.addr, plainSymbol(s.name), false);
        if (looksMangled(s.name)) an.add(s.addr, demangle(s.name), true);
    }
    // 4. GOT slots (data imports)
    for (auto& kv : e.gotNames) {
        std::string nm = plainSymbol(kv.second);
        an.add(kv.first, nm + "@GOT", false);
        an.add(kv.first, nm, true);
    }
    // 5. other named symbols (OBJECT/NOTYPE with value)
    for (auto& s : e.symbols) {
        if (s.kind == "FUNC" || s.addr == 0 || s.name.empty() || !s.defined) continue;
        an.add(s.addr, s.name, false);
    }
    return an;
}

AddrNames buildAddrNamesPe(const Binary& b, const PeInfo& e) {
    (void)b;
    AddrNames an;
    for (auto& s : e.imports) {
        std::string plain = plainSymbol(s.name);
        an.add(s.addr, plain, false);          // IAT slot
    }
    for (auto& s : e.exports) {
        if (s.addr == 0 || s.name.empty()) continue;
        an.add(s.addr, s.name, false);
    }
    return an;
}

// ------------------------------------------------------- call graph --
CallGraph buildCallGraph(const std::map<u64, std::vector<Xref>>& xrefs,
                         const std::vector<FuncInfo>& funcs,
                         const AddrNames& names) {
    CallGraph g;
    std::set<u64> funcSet;
    for (auto& f : funcs) funcSet.insert(f.addr);

    std::map<u64, std::string> nameOf;
    for (auto& f : funcs) nameOf[f.addr] = f.name;

    std::set<std::pair<u64, u64>> seen;
    for (auto& kv : xrefs) {
        for (auto& x : kv.second) {
            if (x.type != "call") continue;
            u64 from = x.from, to = x.to;
            auto key = std::make_pair(from, to);
            if (!seen.insert(key).second) continue;

            CallEdge e;
            e.from = from; e.to = to;
            e.kind = funcSet.count(to) ? "internal" : "import";
            std::string nm = names.lookup(to);
            if (nm.empty()) nm = "sub_" + hexAddr(to).substr(2);
            e.toName = nm;
            // from name: function containing 'from'
            auto fit = nameOf.upper_bound(from);
            if (fit != nameOf.begin()) {
                --fit;
                e.fromName = fit->second;
            } else {
                e.fromName = "sub_" + hexAddr(from).substr(2);
            }
            g.edges.push_back(e);
            if (funcSet.count(to)) {
                g.callees[from].push_back(to);
                g.callers[to].push_back(from);
            }
        }
    }
    // per-function call counts (from linear scan of edges)
    for (auto& e : g.edges) g.callCount[e.from]++;
    g.ok = true;
    return g;
}

// ------------------------------------------------------- DEX analysis --
// Dalvik instruction width in 16-bit code units (best effort; unknown -> 1)
static u32 dexInsnWidth(u16 op) {
    auto in = [](u16 v, u16 a, u16 b) { return v >= a && v <= b; };
    if (op == 0x02 || op == 0x05 || op == 0x08) return 2;               // move*/from16
    if (op == 0x03 || op == 0x06 || op == 0x09) return 3;               // move*/16
    if (op == 0x13 || op == 0x15 || op == 0x16 || op == 0x19) return 2; // const/16, const/high16
    if (op == 0x14 || op == 0x17) return 3;                             // const, const-wide/32
    if (op == 0x18) return 5;                                           // const-wide (51l)
    if (op == 0x1a) return 2;                                           // const-string
    if (op == 0x1b) return 3;                                           // const-string/jumbo
    if (op == 0x1c || op == 0x1f || op == 0x20 || op == 0x22 || op == 0x23) return 2;
    if (op == 0x24 || op == 0x25 || op == 0x26) return 3;               // filled-new-array, fill-array-data
    if (op == 0x29) return 2;                                           // goto/16
    if (op == 0x2a) return 3;                                           // goto/32
    if (in(op, 0x2b, 0x2c)) return 3;                                   // packed/sparse-switch
    if (in(op, 0x2d, 0x31)) return 2;                                   // cmp*
    if (in(op, 0x32, 0x37)) return 2;                                   // if-cc
    if (in(op, 0x38, 0x3d)) return 2;                                   // if-ccz
    if (in(op, 0x44, 0x51)) return 2;                                   // aget/aput
    if (in(op, 0x52, 0x5f)) return 2;                                   // iget/iput
    if (in(op, 0x60, 0x6d)) return 2;                                   // sget/sput
    if (in(op, 0x6e, 0x72)) return 3;                                   // invoke-kind (35c)
    if (in(op, 0x74, 0x78)) return 3;                                   // invoke-kind/range (3rc)
    if (in(op, 0x90, 0xaf)) return 2;                                   // binop
    if (in(op, 0xd0, 0xd7)) return 2;                                   // binop/lit16
    if (in(op, 0xd8, 0xe2)) return 2;                                   // binop/lit8
    if (op == 0xfa || op == 0xfb) return 4;                             // invoke-polymorphic
    if (op == 0xfc || op == 0xfd) return 3;                             // invoke-custom
    if (op == 0xfe || op == 0xff) return 2;                             // const-method-handle/type
    return 1;
}

std::string dexShortClass(const std::string& desc) {
    std::string s = desc;
    if (!s.empty() && s.front() == 'L') s = s.substr(1);
    if (!s.empty() && s.back() == ';') s.pop_back();
    size_t sl = s.find_last_of('/');
    if (sl != std::string::npos) s = s.substr(sl + 1);
    return s;
}

void buildDexFuncsAndCalls(const std::vector<u8>& data, const DexInfo& dex,
                           std::vector<FuncInfo>& funcs, CallGraph& cg) {
    if (data.size() < 16) return;
    const u8* p = data.data();
    size_t n = data.size();

    // methods with bytecode -> first-class functions (dedup by code offset)
    std::unordered_map<u32, u64> codeOf;
    codeOf.reserve(dex.methods.size());
    std::map<u64, std::string> nameByAddr;
    for (u32 i = 0; i < dex.methods.size(); ++i) {
        const DexMethod& m = dex.methods[i];
        if (!m.codeOff || m.codeOff + 16 > n) continue;
        codeOf.emplace(i, m.codeOff);
        auto fit = nameByAddr.emplace(m.codeOff, std::string());
        if (!fit.second) continue;                          // duplicate code item
        FuncInfo f;
        f.addr = m.codeOff;
        f.name = dexShortClass(m.clazz) + "." + m.name;
        f.from = "dex";
        f.size = 16 + u64(rd32(p + m.codeOff + 12)) * 2;
        funcs.push_back(f);
        fit.first->second = f.name;
    }

    // call edges by walking each method body for invoke instructions
    std::set<std::pair<u64, u64>> seen;
    for (u32 i = 0; i < dex.methods.size(); ++i) {
        const DexMethod& m = dex.methods[i];
        if (!m.codeOff || m.codeOff + 16 > n) continue;
        u32 insns = rd32(p + m.codeOff + 12);
        u64 io = m.codeOff + 16;
        if (!insns || io + u64(insns) * 2 > n) continue;
        for (u32 k = 0; k < insns; ) {
            u16 op = rd16(p + io + u64(k) * 2) & 0xFF;
            bool invoke = (op >= 0x6E && op <= 0x72) || (op >= 0x74 && op <= 0x78)
                       || op == 0xFA || op == 0xFB;
            if (invoke && k + 1 < insns) {
                u32 midx = rd16(p + io + u64(k + 1) * 2);
                auto it = codeOf.find(midx);
                if (it != codeOf.end() && it->second != m.codeOff
                    && seen.emplace(m.codeOff, it->second).second) {
                    CallEdge e;
                    e.from = m.codeOff; e.to = it->second;
                    e.kind = "internal";
                    auto fn = nameByAddr.find(e.from);
                    auto tn = nameByAddr.find(e.to);
                    e.fromName = fn != nameByAddr.end() ? fn->second : "";
                    e.toName = tn != nameByAddr.end() ? tn->second : "";
                    cg.edges.push_back(e);
                }
            }
            k += dexInsnWidth(op);
        }
    }
    for (auto& e : cg.edges) {
        cg.callees[e.from].push_back(e.to);
        cg.callers[e.to].push_back(e.from);
        cg.callCount[e.from]++;
    }
    cg.ok = !funcs.empty();
}

// ---------------------------------------------------- auto comments --
namespace {

std::map<u64, std::string> stringMap(const std::vector<FoundString>& strings) {
    std::map<u64, std::string> m;
    for (auto& s : strings) if (m.find(s.addr) == m.end()) m[s.addr] = s.value;
    return m;
}

// rip-relative target for x86: operand like [rip + 0x1234] or [rip - 0x20]
bool ripTarget(const AsmLine& l, u64& target) {
    size_t rp = l.ops.find("rip");
    if (rp == std::string::npos) return false;
    size_t hx = l.ops.find("0x", rp);
    if (hx == std::string::npos) { target = l.addr + 8; return true; }
    i64 disp = i64(strtoll(l.ops.c_str() + hx + 2, nullptr, 16));
    if (hx > rp + 3 && l.ops[hx - 2] == '-') disp = -disp;
    // instruction length approximation from bytes field
    int len = 0;
    for (size_t i = 0; i + 1 < l.bytes.size(); i += 3) ++len;
    target = l.addr + u64(len) + u64(disp);
    return true;
}

} // namespace

void autoComment(const std::string& arch, std::vector<AsmLine>& lines,
                 const AddrNames& names,
                 const std::vector<FoundString>& strings,
                 u64 funcStart, u64 funcEnd) {
    (void)funcStart; (void)funcEnd;
    auto strs = stringMap(strings);
    bool arm = (arch == "ARM64" || arch == "ARM");

    // ARM64: track adrp registers for adrp+add / adrp+ldr pairs
    std::map<std::string, u64> adrpPage;

    for (auto& l : lines) {
        std::string m = lower(l.mnem);
        std::string c;

        if (arm) {
            if (m == "bl" || m == "b") {
                size_t hx = l.ops.find("0x");
                if (hx != std::string::npos) {
                    u64 t = strtoull(l.ops.c_str() + hx + 2, nullptr, 16);
                    std::string nm = names.lookup(t);
                    if (m == "bl" && !nm.empty()) c = nm;
                    else if (m == "bl") c = "sub_" + hexAddr(t).substr(2);
                }
            } else if (m == "adrp") {
                size_t c1 = l.ops.find(',');
                size_t hx = l.ops.find("0x");
                if (c1 != std::string::npos && hx != std::string::npos) {
                    std::string reg = l.ops.substr(0, c1);
                    u64 page = strtoull(l.ops.c_str() + hx + 2, nullptr, 16);
                    adrpPage[reg] = page;
                    auto it = strs.find(page);
                    if (it != strs.end()) c = "\"" + it->second.substr(0, 48) + "\"";
                    else {
                        std::string nm = names.lookup(page);
                        if (!nm.empty()) c = nm;
                    }
                }
            } else if (m == "add" && l.ops.find("0x") != std::string::npos) {
                size_t c1 = l.ops.find(','), c2 = l.ops.find(',', c1 + 1);
                if (c1 != std::string::npos && c2 != std::string::npos) {
                    std::string dst = l.ops.substr(0, c1);
                    std::string src = l.ops.substr(c1 + 2, c2 - c1 - 2);
                    u64 imm = strtoull(l.ops.c_str() + c2 + 2, nullptr, 16);
                    auto it = adrpPage.find(src);
                    if (it != adrpPage.end()) {
                        u64 full = it->second + imm;
                        adrpPage[dst] = full;
                        auto sit = strs.find(full);
                        if (sit != strs.end()) c = "\"" + sit->second.substr(0, 64) + "\"";
                        else {
                            std::string nm = names.lookup(full);
                            if (!nm.empty()) c = nm;
                        }
                    }
                }
            } else if (m.rfind("ldr", 0) == 0 && l.ops.find("x16") != std::string::npos) {
                c = "GOT load";   // typical PLT/GOT sequence
            }
        } else {
            // x86-64
            if (m == "call" || m == "jmp") {
                size_t hx = l.ops.find("0x");
                if (hx != std::string::npos) {
                    u64 t = strtoull(l.ops.c_str() + hx + 2, nullptr, 16);
                    std::string nm = names.lookup(t);
                    if (!nm.empty()) c = nm;
                }
                if (l.ops.find("[rip") != std::string::npos) {
                    u64 t;
                    if (ripTarget(l, t)) {
                        std::string nm = names.lookup(t);
                        if (!nm.empty()) c = nm;
                    }
                }
            } else if (m == "lea" && l.ops.find("rip") != std::string::npos) {
                u64 t;
                if (ripTarget(l, t)) {
                    auto it = strs.find(t);
                    if (it != strs.end()) c = "\"" + it->second.substr(0, 64) + "\"";
                    else {
                        std::string nm = names.lookup(t);
                        if (!nm.empty()) c = "&" + nm;
                    }
                }
            } else if (m == "push" && l.ops.rfind("0x", 0) == 0) {
                u64 v = strtoull(l.ops.c_str() + 2, nullptr, 16);
                auto it = strs.find(v);
                if (it != strs.end()) c = "\"" + it->second.substr(0, 48) + "\"";
            }
        }

        // frame pointers
        if (m == "push" && l.ops == "rbp") c = "save frame pointer";
        if (m == "mov" && l.ops == "rbp, rsp") c = "set frame pointer";
        if (m == "pacibsp") c = "sign return addr (PAC)";

        if (!c.empty()) l.comment = c;
    }

    // dangerous import comments + call classification
    for (auto& l : lines) {
        std::string m = lower(l.mnem);
        bool isCall = (m == "call" || m == "bl");
        if (!isCall || l.comment.empty()) continue;
        const char* cls = classifyImport(l.comment);
        if (cls) {
            std::string extra;
            if (std::string(cls) == "dangerous")
                extra = "  // WARNING: no bounds check";
            else if (std::string(cls) == "exec")
                extra = "  // WARNING: process execution";
            else if (std::string(cls) == "dynload")
                extra = "  // dynamic loading";
            else if (std::string(cls) == "network")
                extra = "  // network";
            l.comment += extra;
        }
    }
}

} // namespace sako
