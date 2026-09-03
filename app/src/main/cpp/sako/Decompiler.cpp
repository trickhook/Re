// Heuristic ASM -> Pseudo-C translator.
// Produces readable "register pseudo-C" (not a real decompiler — see README).
#include "Analysis.h"
#include <cstdlib>
#include <sstream>
#include <set>

namespace sako {

namespace {

std::string lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return r;
}

// first 0x... token in string
bool firstHex(const std::string& s, u64& v) {
    size_t p = s.find("0x");
    if (p == std::string::npos) return false;
    char* end = nullptr;
    unsigned long long x = strtoull(s.c_str() + p + 2, &end, 16);
    if (end == s.c_str() + p + 2) return false;
    v = u64(x);
    return true;
}

std::string labelOf(u64 a) { return "L_" + hexAddr(a).substr(2); }
std::string fnameOf(u64 a, const std::map<u64, std::string>& labels) {
    auto it = labels.find(a);
    if (it != labels.end() && !it->second.empty()) return it->second;
    return "sub_" + hexAddr(a).substr(2);
}

// "x0, [x1, #0x8]" -> (reg="x0", base="x1", off=8, ok)
struct MemOp { std::string reg, base; i64 off = 0; bool ok = false; };

MemOp parseArm64Mem(const std::string& ops) {
    // format: Xt, [Xn, #imm]  or Xt, [Xn]
    MemOp m;
    size_t lb = ops.find('[');
    size_t rb = ops.find(']');
    if (lb == std::string::npos || rb == std::string::npos || rb < lb) return m;
    m.reg = ops.substr(0, ops.find(','));
    // trim
    while (!m.reg.empty() && m.reg.back() == ' ') m.reg.pop_back();
    std::string inner = ops.substr(lb + 1, rb - lb - 1);
    size_t comma = inner.find(',');
    m.base = (comma == std::string::npos) ? inner : inner.substr(0, comma);
    while (!m.base.empty() && m.base.front() == ' ') m.base.erase(0, 1);
    while (!m.base.empty() && m.base.back() == ' ') m.base.pop_back();
    if (comma != std::string::npos) {
        std::string offStr = inner.substr(comma + 1);
        u64 v = 0;
        if (firstHex(offStr, v)) m.off = i64(v);
        else m.off = 0;
    }
    m.ok = !m.reg.empty() && !m.base.empty();
    return m;
}

} // namespace

std::string genPseudo(const std::vector<AsmLine>& lines, const std::string& arch,
                      u64 funcStart, const std::string& funcName,
                      const std::map<u64, std::string>& labels) {
    std::ostringstream out;
    out << "void " << (funcName.empty() ? ("sub_" + hexAddr(funcStart).substr(2)) : funcName)
        << "() {  // pseudo-C heuristic (SakoRE)\n";

    // collect branch targets for labels
    std::set<u64> targets;
    for (auto& l : lines) {
        u64 t;
        bool isBr = (l.mnem == "b" || l.mnem == "bl" || l.mnem.rfind("b.", 0) == 0 ||
                     l.mnem == "cbz" || l.mnem == "cbnz" || l.mnem == "tbz" || l.mnem == "tbnz" ||
                     l.mnem == "jmp" || (lower(l.mnem).rfind("j", 0) == 0 && l.mnem != "jmp"));
        if (isBr && firstHex(l.ops, t)) targets.insert(t);
    }

    bool isArm = (arch == "ARM64" || arch == "ARM");

    for (auto& l : lines) {
        if (targets.count(l.addr)) out << labelOf(l.addr) << ":\n";
        std::string m = lower(l.mnem);
        std::string o = l.ops;
        std::string line;

        if (m == "nop" || m == "endbr64" || m == "pacibsp" || m == "cet_eb") continue;

        if (isArm) {
            if (m == "ret" || m == "retaa" || m == "retab") line = "return;";
            else if (m == "stp" && o.find("x29") != std::string::npos) continue;  // frame
            else if (m == "sub" && o.find("sp, sp") != std::string::npos) continue; // frame
            else if (m == "mov" || m == "movz" || m == "movn") {
                u64 v;
                if (firstHex(o, v)) {
                    std::string reg = o.substr(0, o.find(','));
                    line = reg + " = " + hexAddr(v) + ";";
                }
            } else if (m == "movk") { continue; }
            else if (m == "add" || m == "sub" || m == "mul") {
                // xD, xN, #imm | xD, xN, xM
                size_t c1 = o.find(','), c2 = o.find(',', c1 + 1);
                if (c1 != std::string::npos && c2 != std::string::npos) {
                    std::string d = o.substr(0, c1);
                    std::string n = o.substr(c1 + 2, c2 - c1 - 2);
                    std::string r = o.substr(c2 + 2);
                    if (!r.empty() && r[0] == '#') r.erase(0, 1);
                    line = d + " = " + n + (m == "add" ? " + " : m == "sub" ? " - " : " * ") +
                           (r.empty() ? "?" : r) + ";";
                }
            } else if (m == "ldr" || m == "ldrb" || m == "ldrh" || m == "ldrsw" ||
                       m == "str" || m == "strb" || m == "strh") {
                MemOp mo = parseArm64Mem(o);
                if (mo.ok) {
                    std::string cast = (m.find("b") == m.size() - 1) ? "u8" :
                                       (m.find("h") == m.size() - 1) ? "u16" :
                                       (mo.reg.size() && mo.reg[0] == 'w') ? "u32" : "u64";
                    std::string ptr = "*(" + cast + "*)(" + mo.base +
                                      (mo.off ? ((mo.off > 0 ? " + " : " - ") + hexAddr(u64(mo.off > 0 ? u64(mo.off) : u64(-mo.off)))) : "") + ")";
                    line = (m[0] == 'l') ? (mo.reg + " = " + ptr + ";") : (ptr + " = " + mo.reg + ";");
                }
            } else if (m == "bl") {
                u64 t;
                if (firstHex(o, t)) line = fnameOf(t, labels) + "();  // " + hexAddr(t);
            } else if (m == "blr") {
                line = o + "();";
            } else if (m == "b") {
                u64 t;
                if (firstHex(o, t)) line = "goto " + labelOf(t) + ";";
            } else if (m.rfind("b.", 0) == 0) {
                u64 t;
                if (firstHex(o, t)) line = "if (cond) goto " + labelOf(t) + ";  // " + m;
            } else if (m == "cbz" || m == "cbnz") {
                size_t c = o.rfind(',');
                u64 t;
                if (c != std::string::npos && firstHex(o, t)) {
                    std::string reg = o.substr(0, c);
                    line = "if (" + reg + (m == "cbz" ? " == 0" : " != 0") + ") goto " + labelOf(t) + ";";
                }
            } else if (m == "cmp") {
                line = "// cmp " + o;
            } else if (m == "adrp" || m == "adr") {
                size_t c = o.find(',');
                if (c != std::string::npos) line = o.substr(0, c) + " = &" + o.substr(c + 2) + ";";
            }
        } else {
            // x86
            if (m == "ret" || m == "retn" || m == "retq") line = "return;";
            else if (m == "push" && o == "rbp") continue;
            else if (m == "mov" && o == "rbp, rsp") continue;
            else if (m == "mov" || m == "movabs") {
                size_t c = o.find(", 0x");
                if (c != std::string::npos) {
                    line = o.substr(0, c) + " = " + o.substr(c + 2) + ";";
                } else {
                    size_t c2 = o.find(", [");
                    if (c2 != std::string::npos) {
                        std::string reg = o.substr(0, c2);
                        std::string mem = o.substr(c2 + 2);
                        line = reg + " = *(u64*)" + mem + ";";
                    }
                }
            } else if (m == "lea") {
                size_t c = o.find(", ");
                if (c != std::string::npos) line = o.substr(0, c) + " = &" + o.substr(c + 2) + ";";
            } else if (m == "call") {
                u64 t;
                if (firstHex(o, t)) line = fnameOf(t, labels) + "();  // " + hexAddr(t);
                else line = o + "();";
            } else if (m == "jmp") {
                u64 t;
                if (firstHex(o, t)) line = "goto " + labelOf(t) + ";";
                else line = "goto " + o + ";  // indirect";
            } else if (m.size() > 1 && m[0] == 'j') {
                u64 t;
                if (firstHex(o, t)) line = "if (cond) goto " + labelOf(t) + ";  // " + m;
            } else if (m == "cmp" || m == "test") {
                line = "// " + m + " " + o;
            } else if (m == "xor" && o == "eax, eax") {
                line = "eax = 0;";
            } else if (m == "add" || m == "sub" || m == "and" || m == "or" || m == "imul") {
                size_t c = o.find(", ");
                if (c != std::string::npos) {
                    std::string op = m == "add" ? "+" : m == "sub" ? "-" : m == "and" ? "&" : m == "or" ? "|" : "*";
                    line = o.substr(0, c) + " " + op + "= " + o.substr(c + 2) + ";";
                }
            }
        }

        if (!line.empty()) out << "    " << line << "\n";
        else if (!m.empty() && m[0] != '.') out << "    /* " << l.mnem << (o.empty() ? "" : " " + o) << " */\n";
    }
    if (targets.count(funcStart + 0)) out << labelOf(funcStart) << ":\n";
    out << "}\n";
    return out.str();
}

} // namespace sako
