// IR decompiler core: expression rendering, lifting, propagation, emission.
#include "Analysis.h"
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <vector>
#include <sstream>

namespace sako {

// ======================================================= IrExpr methods ==
std::shared_ptr<IrExpr> IrExpr::clone() const {
    auto e = std::make_shared<IrExpr>();
    e->kind = kind; e->imm = imm; e->reg = reg; e->name = name;
    e->binop = binop; e->size = size; e->isArg = isArg; e->isBool = isBool;
    e->cmpOp = cmpOp;
    if (a) e->a = a->clone();
    if (b) e->b = b->clone();
    for (auto& x : args) e->args.push_back(x->clone());
    return e;
}

int IrExpr::complexity() const {
    int n = 1;
    if (a) n += a->complexity();
    if (b) n += b->complexity();
    return n;
}

bool IrExpr::containsReg(const std::string& r) const {
    if (kind == REG && reg == r) return true;
    if (a && a->containsReg(r)) return true;
    if (b && b->containsReg(r)) return true;
    for (auto& x : args) if (x->containsReg(r)) return true;
    return false;
}

void IrExpr::collectRegs(std::set<std::string>& out) const {
    if (kind == REG) out.insert(reg);
    if (a) a->collectRegs(out);
    if (b) b->collectRegs(out);
    for (auto& x : args) x->collectRegs(out);
}

static std::string typeOfWidth(int bytes) {
    switch (bytes) {
        case 1: return "u8";
        case 2: return "u16";
        case 4: return "u32";
        default: return "u64";
    }
}

std::string IrExpr::render() const {
    switch (kind) {
        case IMM: {
            std::ostringstream os;
            if (imm >= 0x10000) os << "0x" << hexAddr(imm);
            else os << imm;
            return os.str();
        }
        case REG:  return reg;
        case STRREF: return "\"" + name + "\"";
        case MEM: {
            std::string base = a ? a->render() : "0";
            std::string off;
            if (imm) {
                i64 s = i64(imm);
                off = (s > 0 ? " + " : " - ") +
                      std::to_string(s > 0 ? s : -s);
            }
            return "*(" + typeOfWidth(size) + "*)(" + base + off + ")";
        }
        case BIN: {
            std::string l = a ? a->render() : "?";
            std::string r = b ? b->render() : "?";
            return "(" + l + " " + binop + " " + r + ")";
        }
        case UN: return "(" + binop + "(" + (a ? a->render() : "?") + "))";
        case CALL: {
            std::string s = name + "(";
            for (size_t i = 0; i < args.size(); ++i) {
                if (i) s += ", ";
                s += args[i]->render();
            }
            return s + ")";
        }
        case COND: {
            std::string l = a ? a->render() : "?";
            std::string r = b ? b->render() : "?";
            std::string op = cmpOp.empty() ? "!=" : cmpOp;
            return "(" + l + " " + op + " " + r + ")";
        }
    }
    return "?";
}

namespace {

// ======================================================== lifting utils ==
std::string lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return r;
}

bool parseHex(const std::string& s, u64& v) {
    size_t p = s.find("0x");
    if (p == std::string::npos) return false;
    char* end = nullptr;
    unsigned long long x = strtoull(s.c_str() + p + 2, &end, 16);
    if (end == s.c_str() + p + 2) return false;
    v = u64(x);
    return true;
}

std::vector<std::string> splitOps(const std::string& s) {
    std::vector<std::string> out;
    int depth = 0;
    std::string cur;
    for (char c : s) {
        if (c == '[' || c == '(') { ++depth; cur += c; }
        else if (c == ']' || c == ')') { --depth; cur += c; }
        else if (c == ',' && depth == 0) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    for (auto& t : out) {
        while (!t.empty() && t.front() == ' ') t.erase(0, 1);
        while (!t.empty() && t.back() == ' ') t.pop_back();
    }
    return out;
}

// "[x1, #0x8]" / "[x1]" -> (base, off, widthHint)
bool parseMemOperand(const std::string& opnd, std::string& base, i64& off) {
    size_t lb = opnd.find('['), rb = opnd.find(']');
    if (lb == std::string::npos || rb == std::string::npos || rb < lb) return false;
    std::string inner = opnd.substr(lb + 1, rb - lb - 1);
    size_t comma = inner.find(',');
    base = (comma == std::string::npos) ? inner : inner.substr(0, comma);
    while (!base.empty() && base.front() == ' ') base.erase(0, 1);
    while (!base.empty() && base.back() == ' ') base.pop_back();
    off = 0;
    if (comma != std::string::npos) {
        std::string rest = inner.substr(comma + 1);
        while (!rest.empty() && rest.front() == ' ') rest.erase(0, 1);
        size_t hx = rest.find("0x");
        if (hx != std::string::npos) off = i64(strtoll(rest.c_str() + hx + 2, nullptr, 16));
    }
    return !base.empty();
}

bool parseX86Mem(const std::string& opnd, std::string& base, i64& off) {
    size_t lb = opnd.find('['), rb = opnd.find(']');
    if (lb == std::string::npos || rb == std::string::npos || rb < lb) return false;
    std::string inner = opnd.substr(lb + 1, rb - lb - 1);
    if (inner.find('*') != std::string::npos) return false;
    size_t plus = inner.find('+'), minus = inner.find('-');
    base = inner; off = 0;
    if (plus != std::string::npos) {
        base = inner.substr(0, plus);
        size_t hx = inner.find("0x", plus);
        if (hx != std::string::npos) off = i64(strtoll(inner.c_str() + hx + 2, nullptr, 16));
    } else if (minus != std::string::npos && inner.find("0x", minus) != std::string::npos) {
        base = inner.substr(0, minus);
        size_t hx = inner.find("0x", minus);
        off = -i64(strtoll(inner.c_str() + hx + 2, nullptr, 16));
    }
    while (!base.empty() && base.front() == ' ') base.erase(0, 1);
    while (!base.empty() && base.back() == ' ') base.pop_back();
    return !base.empty() && base != "rip";
}

bool isVectorReg(const std::string& r) {
    return !r.empty() && (r[0] == 'v' || r[0] == 'q' || r[0] == 's' || r[0] == 'h' || r[0] == 'b') &&
           r.find_first_not_of("vdqshb0123456789") == std::string::npos;
}

bool isZeroReg(const std::string& r) { return r == "xzr" || r == "wzr"; }

std::string regVar(const std::string& r) {
    if (r == "x29") return "fp";
    if (r == "x30") return "lr";
    if (r == "xzr" || r == "wzr") return "0";
    return r;
}

int regBytes(const std::string& r) {
    if (r.empty()) return 8;
    if (r[0] == 'w') return 4;
    if (r[0] == 'x') return 8;
    if (r == "eax" || r == "ebx" || r == "ecx" || r == "edx" ||
        r == "esi" || r == "edi" || r == "ebp" || r == "esp") return 4;
    if (r == "ax" || r == "bx" || r == "cx" || r == "dx" ||
        r == "si" || r == "di" || r == "bp" || r == "sp") return 2;
    if (r == "al" || r == "bl" || r == "cl" || r == "dl") return 1;
    return 8;
}

} // namespace

// ===================================================== decompileIR itself ==
IrResult decompileIR(const std::vector<AsmLine>& lines, const std::string& arch,
                     u64 funcStart, const std::string& funcNameIn,
                     const AddrNames& names,
                     const std::vector<FoundString>& strings) {
    IrResult res;
    if (lines.empty()) return res;
    bool arm = (arch == "ARM64");

    auto blocks = buildCfg(lines, funcStart, funcStart + 65536, arch);
    if (blocks.empty()) return res;
    int nB = int(blocks.size());

    // ---------- dominators ----------
    std::map<int, std::set<int>> preds;
    for (auto& b : blocks) for (int s : b.succ) preds[s].insert(b.id);
    std::vector<std::set<int>> dom(nB);
    {
        for (int i = 0; i < nB; ++i) {
            if (i == 0) dom[i].insert(i);
            else for (int j = 0; j < nB; ++j) dom[i].insert(j);
        }
        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 64) {
            changed = false;
            for (int i = 0; i < nB; ++i) {
                if (i == 0) continue;
                std::set<int> nd;
                bool first = true;
                for (int p : preds[i]) {
                    if (p >= nB || dom[p].empty()) continue;
                    if (first) { nd = dom[p]; first = false; }
                    else {
                        std::set<int> isect;
                        for (int x : nd) if (dom[p].count(x)) isect.insert(x);
                        nd = isect;
                    }
                }
                if (first) continue;
                nd.insert(i);
                if (nd != dom[i]) { dom[i] = nd; changed = true; }
            }
        }
    }
    auto dominates = [&](int d, int x) -> bool {
        return d >= 0 && x >= 0 && d < nB && x < nB && dom[x].count(d) != 0;
    };

    // ---------- loops: back edges ----------
    struct Loop { int header = 0, src = 0; u64 headerAddr = 0; std::string cond; };
    std::vector<Loop> loops;
    std::map<int, int> headerToLoop, srcToLoop;
    for (auto& b : blocks) {
        for (int s : b.succ) {
            if (s < nB && dominates(s, b.id)) {
                if (headerToLoop.count(s)) continue;
                Loop L;
                L.header = s; L.src = b.id;
                L.headerAddr = blocks[s].start;
                headerToLoop[s] = int(loops.size());
                srcToLoop[b.id] = int(loops.size());
                loops.push_back(L);
                break;
            }
        }
    }

    // ---------- per-block lifting state ----------
    std::map<std::string, std::shared_ptr<IrExpr>> regs;
    std::shared_ptr<IrExpr> fl_a, fl_b;
    int maxArgSeen = -1;
    std::set<std::string> usedVars, writtenVars;

    auto initRegs = [&]() {
        regs.clear(); fl_a = nullptr; fl_b = nullptr;
        if (arm) {
            for (int i = 0; i <= 7; ++i)
                regs["x" + std::to_string(i)] =
                    IrExpr::makeReg("a" + std::to_string(i), 8, true);
        } else {
            const char* args[6] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
            for (int i = 0; i < 6; ++i)
                regs[args[i]] = IrExpr::makeReg("a" + std::to_string(i), 8, true);
        }
    };

    auto readReg = [&](const std::string& r) -> std::shared_ptr<IrExpr> {
        if (isZeroReg(r)) return IrExpr::makeImm(0);
        usedVars.insert(regVar(r));
        auto it = regs.find(r);
        if (it != regs.end() && it->second && it->second->complexity() <= 8)
            return it->second->clone();
        // ARM w0..w7 are the low halves of argument registers a0..a7
        if (arm && r.size() == 2 && r[0] == 'w' && isdigit((unsigned char)r[1])) {
            int n = r[1] - '0';
            if (n <= 7) {
                usedVars.insert("a" + std::to_string(n));
                return IrExpr::makeReg("a" + std::to_string(n), 4, true);
            }
        }
        return IrExpr::makeReg(regVar(r), regBytes(r));
    };

    auto immOrReg = [&](std::string s2) -> std::shared_ptr<IrExpr> {
        if (!s2.empty() && s2[0] == '#') s2.erase(0, 1);
        u64 v;
        if (parseHex(s2, v)) return IrExpr::makeImm(v);
        if (!s2.empty() && isdigit((unsigned char)s2[0]))
            return IrExpr::makeImm(u64(strtoull(s2.c_str(), nullptr, 10)));
        return readReg(s2);
    };

    auto clearFlags = [&]() { fl_a = nullptr; fl_b = nullptr; };

    auto condText = [&](const std::string& mnem) -> std::string {
        if (!fl_a) return "cond";
        std::string m = lower(mnem);
        std::string op;
        if (m == "b.eq" || m == "je") op = "==";
        else if (m == "b.ne" || m == "jne") op = "!=";
        else if (m == "b.lt" || m == "jl") op = "<";
        else if (m == "b.le" || m == "jle" || m == "jng") op = "<=";
        else if (m == "b.gt" || m == "jg" || m == "jnle") op = ">";
        else if (m == "b.ge" || m == "jge" || m == "jnl") op = ">=";
        else if (m == "b.lo" || m == "bcc" || m == "jb" || m == "jc") op = "<";
        else if (m == "b.ls" || m == "jbe" || m == "jna") op = "<=";
        else if (m == "b.hi" || m == "ja") op = ">";
        else if (m == "b.hs" || m == "jae" || m == "jnc") op = ">=";
        else if (m == "js") return "(" + fl_a->render() + " < 0)";
        else if (m == "jns") return "(" + fl_a->render() + " >= 0)";
        else return "cond";
        return "(" + fl_a->render() + " " + op + " " +
               (fl_b ? fl_b->render() : "0") + ")";
    };

    // lift one instruction; appends statements; returns control token
    std::function<std::string(const AsmLine&, std::vector<IrStmt>&)> lift;
    lift = [&](const AsmLine& l, std::vector<IrStmt>& out) -> std::string {
        std::string m = lower(l.mnem);
        std::string ops = l.ops;
        auto toks = splitOps(ops);

        if (m == "nop" || m == "endbr64" || m == "endbr" || m == "pacibsp" ||
            m == "paciasp" || m == "autibsp" || m == "cet_eb" || m == "hint" ||
            m == "dmb" || m == "dsb" || m == "isb" || m == "leave" || m == "cdq" ||
            m == "cdqe" || m == "cqo" || m == "movk" || m == "xchg") return "";
        if (arm) {
            if (m == "stp" && ops.find("x29") != std::string::npos) return "";
            if (m == "ldp" && ops.find("x29") != std::string::npos) return "";
            if (m == "sub" && toks.size() >= 2 && toks[0] == "sp" && toks[1] == "sp") return "";
            if (m == "add" && toks.size() >= 2 && toks[0] == "sp" && toks[1] == "sp") return "";
        } else {
            if (m == "push" && ops.find("[") == std::string::npos &&
                ops != "0x0") {
                // plain register push — stack traffic, skip
                return "";
            }
            if (m == "pop") return "";
            if (m == "mov" && (ops == "rbp, rsp" || ops == "ebp, esp")) return "";
        }
        if (!toks.empty() && isVectorReg(toks[0])) return "";

        if (arm) {
            if (m == "ret" || m == "retaa" || m == "retab") {
                IrStmt s; s.kind = IrStmt::RETURN; s.rhs = readReg("x0"); s.addr = l.addr;
                out.push_back(s);
                return "ret";
            }
            if (m == "mov" || m == "movz" || m == "movn") {
                if (toks.size() < 2) return "";
                std::string d = toks[0];
                auto v = immOrReg(toks[1]);
                if (isZeroReg(toks[1])) v = IrExpr::makeImm(0);
                regs[d] = v;
                return "";
            }
            if (m == "add" || m == "sub" || m == "mul" || m == "and" || m == "orr" ||
                m == "eor" || m == "lsl" || m == "lsr" || m == "asr" || m == "udiv" ||
                m == "sdiv" || m == "madd" || m == "msub" || m == "neg") {
                if (toks.size() < 2) return "";
                std::string d = toks[0];
                if (m == "neg") {
                    regs[d] = IrExpr::makeBin("-", IrExpr::makeImm(0), readReg(toks[1]));
                    return "";
                }
                if (toks.size() < 3) return "";
                std::string op;
                if (m == "add") op = "+"; else if (m == "sub") op = "-";
                else if (m == "mul" || m == "madd" || m == "msub") op = "*";
                else if (m == "and") op = "&"; else if (m == "orr") op = "|";
                else if (m == "eor") op = "^"; else if (m == "lsl") op = "<<";
                else if (m == "lsr" || m == "asr") op = ">>";
                else op = "/";
                auto v1 = readReg(toks[1]);
                auto v2 = immOrReg(toks[2]);
                auto e = IrExpr::makeBin(op, v1, v2);
                if ((m == "madd" || m == "msub") && toks.size() >= 4) {
                    auto v3 = readReg(toks[3]);
                    e = IrExpr::makeBin(m == "madd" ? "+" : "-", e, v3);
                }
                regs[d] = e;
                return "";
            }
            if (m == "cset") {
                if (toks.empty()) return "";
                std::string cc = toks.size() > 1 ? toks[1] : "ne";
                std::string base = cc.substr(0, cc.find('.'));
                std::string op = base == "eq" ? "==" : base == "lt" ? "<" :
                                 base == "le" ? "<=" : base == "gt" ? ">" :
                                 base == "ge" ? ">=" : "!=";
                if (fl_a)
                    regs[toks[0]] = IrExpr::makeCond(op, fl_a->clone(),
                                                     fl_b ? fl_b->clone() : IrExpr::makeImm(0));
                else regs[toks[0]] = IrExpr::makeImm(1);
                clearFlags();
                return "";
            }
            if (m == "cmp" || m == "cmn") {
                if (toks.size() < 2) { clearFlags(); return ""; }
                fl_a = readReg(toks[0]);
                fl_b = immOrReg(toks[1]);
                return "";
            }
            if (m == "adrp" || m == "adr") {
                if (toks.size() < 2) return "";
                u64 v;
                if (parseHex(toks[1], v)) {
                    std::string nm = names.lookup(v);
                    if (!nm.empty() && nm.find('+') == std::string::npos)
                        regs[toks[0]] = IrExpr::makeReg("&" + nm, 8);
                    else regs[toks[0]] = IrExpr::makeImm(v);
                }
                return "";
            }
            if (m == "ldr" || m == "ldrb" || m == "ldrh" || m == "ldrsw" || m == "ldur") {
                if (toks.size() < 2) return "";
                std::string d = toks[0];
                int sz = (m == "ldrb") ? 1 : (m == "ldrh") ? 2 :
                         (m == "ldrsw") ? 4 :
                         (!d.empty() && d[0] == 'w') ? 4 : 8;
                std::string base; i64 off;
                if (!parseMemOperand(ops, base, off)) return "";
                regs[d] = IrExpr::makeMem(readReg(base), off, sz);
                return "";
            }
            if (m == "str" || m == "strb" || m == "strh" || m == "stur") {
                if (toks.size() < 1) return "";
                std::string src = toks[0];
                int sz = (m == "strb") ? 1 : (m == "strh") ? 2 :
                         (!src.empty() && src[0] == 'w') ? 4 : 8;
                std::string base; i64 off;
                if (!parseMemOperand(ops, base, off)) return "";
                if (base == "sp") return "";
                auto val = toks.size() >= 1 ? readReg(src) : IrExpr::makeImm(0);
                auto memE = IrExpr::makeMem(readReg(base), off, sz);
                out.push_back(IrStmt::makeAssign(memE, val, l.addr));
                return "";
            }
            if (m == "stp" || m == "stlr") return "";
            if (m == "bl") {
                u64 t;
                std::string fname;
                if (parseHex(ops, t)) {
                    std::string nm = names.lookup(t);
                    fname = nm.empty() ? ("sub_" + hexAddr(t).substr(2)) : nm;
                } else fname = ops;
                auto callE = IrExpr::makeCall(fname);
                for (int i = 0; i <= 7; ++i) {
                    callE->args.push_back(readReg("x" + std::to_string(i)));
                    if (i > maxArgSeen && i <= 3) maxArgSeen = i;  // conservative: first 4
                }
                IrStmt s; s.kind = IrStmt::CALL; s.rhs = callE; s.addr = l.addr;
                out.push_back(s);
                regs["x0"] = callE;
                ++res.nCalls;
                return "";
            }
            if (m == "blr") {
                if (toks.empty()) return "";
                auto callE = IrExpr::makeCall(readReg(toks[0])->render());
                for (int i = 0; i <= 7; ++i)
                    callE->args.push_back(readReg("x" + std::to_string(i)));
                IrStmt s; s.kind = IrStmt::CALL; s.rhs = callE; s.addr = l.addr;
                out.push_back(s);
                regs["x0"] = callE;
                ++res.nCalls;
                return "";
            }
            if (m == "b") {
                u64 t;
                if (parseHex(ops, t)) return "jmp:" + std::to_string(t);
                return "ret";
            }
            if (m.rfind("b.", 0) == 0) {
                u64 t;
                if (parseHex(ops, t)) return "cjmp:" + std::to_string(t) + "|" + m;
                return "ret";
            }
            if (m == "cbz" || m == "cbnz") {
                if (toks.size() < 2) return "";
                u64 t;
                if (!parseHex(toks[1], t)) return "";
                fl_a = readReg(toks[0]);
                fl_b = IrExpr::makeImm(0);
                return "cjmp:" + std::to_string(t) + "|" + m;
            }
            if (m == "tbz" || m == "tbnz") {
                if (toks.size() < 3) return "";
                u64 t;
                if (!parseHex(toks[2], t)) return "";
                std::string bit = toks[1];
                if (!bit.empty() && bit[0] == '#') bit.erase(0, 1);
                u64 bitn = strtoull(bit.c_str(), nullptr, 10);
                fl_a = IrExpr::makeBin("&",
                        IrExpr::makeBin(">>", readReg(toks[0]), IrExpr::makeImm(bitn)),
                        IrExpr::makeImm(1));
                fl_b = IrExpr::makeImm(0);
                return "cjmp:" + std::to_string(t) + "|" + (m == "tbz" ? "b.eq" : "b.ne");
            }
            return "";
        }

        // ---------------- x86-64 ----------------
        if (m == "ret" || m == "retn" || m == "retq") {
            IrStmt s; s.kind = IrStmt::RETURN; s.rhs = readReg("rax"); s.addr = l.addr;
            out.push_back(s);
            return "ret";
        }
        if (m == "mov" || m == "movabs") {
            if (toks.size() < 2) return "";
            std::string d = toks[0], src = toks[1];
            std::shared_ptr<IrExpr> v;
            if (src.rfind("0x", 0) == 0)
                v = IrExpr::makeImm(u64(strtoull(src.c_str() + 2, nullptr, 16)), regBytes(d));
            else if (src.find('[') != std::string::npos) {
                if (src.find("rip") != std::string::npos) return "";
                std::string base; i64 off;
                if (!parseX86Mem(src, base, off)) return "";
                v = IrExpr::makeMem(readReg(base), off, regBytes(d));
            } else v = readReg(src);
            regs[d] = v;
            return "";
        }
        if (m == "lea") {
            if (toks.size() < 2) return "";
            std::string d = toks[0], src = toks[1];
            if (src.find("rip") != std::string::npos) {
                // resolve rip-relative data reference to a named/string value
                int len = 0;
                for (size_t bi = 0; bi + 1 < l.bytes.size(); bi += 3) ++len;
                size_t hx = src.find("0x");
                if (hx != std::string::npos) {
                    i64 disp = i64(strtoll(src.c_str() + hx + 2, nullptr, 16));
                    u64 tgt = l.addr + u64(len) + u64(disp);
                    std::string nm = names.lookup(tgt);
                    // string content?
                    std::string strVal;
                    for (auto& fs : strings)
                        if (fs.addr == tgt) { strVal = fs.value; break; }
                    if (!strVal.empty()) {
                        auto e = IrExpr::make(IrExpr::STRREF);
                        e->name = strVal.substr(0, 80);
                        e->size = 8;
                        regs[d] = e;
                    } else if (!nm.empty() && nm.find('+') == std::string::npos) {
                        regs[d] = IrExpr::makeReg("&" + nm, 8);
                    } else {
                        regs[d] = IrExpr::makeReg("&DATA_" + hexAddr(tgt).substr(2), 8);
                    }
                }
                return "";
            }
            std::string base; i64 off;
            if (!parseX86Mem(src, base, off)) return "";
            auto e = readReg(base);
            if (off) e = IrExpr::makeBin("+", e, IrExpr::makeImm(u64(off)));
            regs[d] = e;
            return "";
        }
        if (m == "movzx" || m == "movsx" || m == "movsxd") {
            if (toks.size() < 2) return "";
            std::string d = toks[0], src = toks[1];
            if (src.find('[') != std::string::npos) {
                std::string base; i64 off;
                if (!parseX86Mem(src, base, off)) return "";
                regs[d] = IrExpr::makeMem(readReg(base), off, 4);
            } else regs[d] = readReg(src);
            return "";
        }
        if (m == "add" || m == "sub" || m == "and" || m == "or" || m == "xor" ||
            m == "shl" || m == "sal" || m == "shr" || m == "sar" || m == "imul") {
            if (toks.size() < 2) return "";
            std::string d = toks[0];
            std::string op;
            if (m == "add") op = "+"; else if (m == "sub") op = "-";
            else if (m == "and") op = "&"; else if (m == "or") op = "|";
            else if (m == "xor") op = "^";
            else if (m == "shl" || m == "sal") op = "<<";
            else if (m == "shr" || m == "sar") op = ">>";
            else op = "*";
            auto v1 = readReg(d);
            std::shared_ptr<IrExpr> v2;
            std::string s2 = toks[1];
            if (s2.find('[') != std::string::npos) {
                std::string base; i64 off;
                if (!parseX86Mem(s2, base, off)) return "";
                v2 = IrExpr::makeMem(readReg(base), off, regBytes(d));
            } else if (s2.rfind("0x", 0) == 0)
                v2 = IrExpr::makeImm(u64(strtoull(s2.c_str() + 2, nullptr, 16)));
            else v2 = readReg(s2);
            regs[d] = IrExpr::makeBin(op, v1, v2);
            if (m == "add" || m == "sub") { fl_a = regs[d]; fl_b = nullptr; }
            return "";
        }
        if (m == "inc") { if (toks.empty()) return "";
            regs[toks[0]] = IrExpr::makeBin("+", readReg(toks[0]), IrExpr::makeImm(1)); return ""; }
        if (m == "dec") { if (toks.empty()) return "";
            regs[toks[0]] = IrExpr::makeBin("-", readReg(toks[0]), IrExpr::makeImm(1)); return ""; }
        if (m == "cmp" || m == "test") {
            if (toks.size() < 2) { clearFlags(); return ""; }
            std::string s1 = toks[0], s2 = toks[1];
            if (s1.find('[') != std::string::npos) {
                std::string base; i64 off;
                if (parseX86Mem(s1, base, off)) fl_a = IrExpr::makeMem(readReg(base), off, 8);
                else fl_a = IrExpr::makeReg("mem", 8);
            } else fl_a = readReg(s1);
            if (s2.rfind("0x", 0) == 0)
                fl_b = IrExpr::makeImm(u64(strtoull(s2.c_str() + 2, nullptr, 16)));
            else if (s2.find('[') != std::string::npos) fl_b = IrExpr::makeReg("mem", 8);
            else fl_b = readReg(s2);
            return "";
        }
        if (m == "call") {
            std::string fname;
            if (ops.rfind("0x", 0) == 0) {
                u64 t = strtoull(ops.c_str() + 2, nullptr, 16);
                std::string nm = names.lookup(t);
                fname = nm.empty() ? ("sub_" + hexAddr(t).substr(2)) : nm;
            } else if (ops.find("[rip") != std::string::npos) fname = "indirect_call";
            else fname = ops;
            auto callE = IrExpr::makeCall(fname);
            const char* argRegs[6] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
            for (int i = 0; i < 6; ++i) {
                callE->args.push_back(readReg(argRegs[i]));
                if (i > maxArgSeen && i <= 3) maxArgSeen = i;
            }
            IrStmt s; s.kind = IrStmt::CALL; s.rhs = callE; s.addr = l.addr;
            out.push_back(s);
            regs["rax"] = callE;
            ++res.nCalls;
            return "";
        }
        if (m == "jmp") {
            if (ops.rfind("0x", 0) == 0) {
                u64 t = strtoull(ops.c_str() + 2, nullptr, 16);
                return "jmp:" + std::to_string(t);
            }
            return "ret";
        }
        if (m.size() > 1 && m[0] == 'j') {
            if (ops.rfind("0x", 0) == 0) {
                u64 t = strtoull(ops.c_str() + 2, nullptr, 16);
                return "cjmp:" + std::to_string(t) + "|" + m;
            }
            return "ret";
        }
        if (m == "sete" || m == "setne" || m == "setl" || m == "setg" ||
            m == "seta" || m == "setb") {
            if (toks.empty()) return "";
            std::string op = m == "sete" ? "==" : m == "setne" ? "!=" :
                             (m == "setl" || m == "setb") ? "<" : ">";
            if (fl_a)
                regs[toks[0]] = IrExpr::makeCond(op, fl_a->clone(),
                                                 fl_b ? fl_b->clone() : IrExpr::makeImm(0));
            else regs[toks[0]] = IrExpr::makeImm(1);
            clearFlags();
            return "";
        }
        return "";
    };

    // ---------- per-block terminators ----------
    struct Term { int kind = 0; u64 target = 0; };
    auto termOf = [&](int bid) -> Term {
        Term t;
        if (bid < 0 || bid >= nB) return t;
        auto& b = blocks[bid];
        const AsmLine* last = nullptr;
        for (auto& l : lines)
            if (l.addr >= b.start && l.addr < b.end) last = &l;
        if (!last) return t;
        std::string m = lower(last->mnem);
        u64 tgt;
        bool has = parseHex(last->ops, tgt);
        if (m == "ret" || m == "retn" || m == "retq" || m == "retaa" || m == "retab") { t.kind = 1; return t; }
        if (m == "b" || m == "jmp") {
            if (has) { t.kind = 2; t.target = tgt; } else t.kind = 1;
            return t;
        }
        if (m.rfind("b.", 0) == 0 || m == "cbz" || m == "cbnz" || m == "tbz" ||
            m == "tbnz" || (m.size() > 1 && m[0] == 'j' && m != "jmp")) {
            t.kind = 3;
            if (has) t.target = tgt;
            return t;
        }
        return t;
    };

    // condition text at a cjmp block: re-lift the block's flag-setting instrs
    std::vector<IrStmt> dummy;
    auto condAtBlock = [&](int bid) -> std::string {
        if (bid < 0 || bid >= nB) return "cond";
        auto& b = blocks[bid];
        initRegs();
        std::string cond = "cond";
        for (auto& l : lines) {
            if (l.addr < b.start || l.addr >= b.end) continue;
            std::string m = lower(l.mnem);
            if (m.rfind("b.", 0) == 0 || (m.size() > 1 && m[0] == 'j' && m != "jmp")) {
                cond = condText(m);
                break;
            }
            if (m == "cbz") {
                auto t2 = splitOps(l.ops);
                if (!t2.empty()) cond = "(" + readReg(t2[0])->render() + " == 0)";
                break;
            }
            if (m == "cbnz") {
                auto t2 = splitOps(l.ops);
                if (!t2.empty()) cond = "(" + readReg(t2[0])->render() + " != 0)";
                break;
            }
            if (m == "tbz" || m == "tbnz") {
                auto t2 = splitOps(l.ops);
                if (t2.size() >= 2) {
                    std::string bit = t2[1];
                    if (!bit.empty() && bit[0] == '#') bit.erase(0, 1);
                    cond = std::string("(((") + readReg(t2[0])->render() + " >> " +
                           bit + ") & 1) " + (m == "tbz" ? "==" : "!=") + " 0)";
                }
                break;
            }
            lift(l, dummy);
        }
        return cond;
    };

    // fill loop conditions
    for (auto& L : loops) {
        Term st = termOf(L.src);
        if (st.kind == 3) L.cond = condAtBlock(L.src);
        else L.cond = "true";
    }

    // ---------- pass 1: lift blocks ----------
    std::map<int, std::vector<IrStmt>> blockStmts;
    for (auto& b : blocks) {
        std::vector<IrStmt> out;
        initRegs();
        bool done = false;
        for (auto& l : lines) {
            if (l.addr < b.start || l.addr >= b.end) continue;
            if (done) break;
            std::string ctl = lift(l, out);
            if (ctl == "ret" || ctl.rfind("jmp:", 0) == 0 || ctl.rfind("cjmp:", 0) == 0)
                done = true;
        }
        // dead-store elimination on register assignments
        for (size_t i = 0; i < out.size(); ++i) {
            IrStmt& s = out[i];
            if (s.kind != IrStmt::ASSIGN || !s.lhs || s.lhs->kind != IrExpr::REG) continue;
            std::string r = s.lhs->reg;
            if (r == "x0" || r == "rax") continue;   // return-value regs stay
            bool readLater = false;
            for (size_t k = i + 1; k < out.size() && !readLater; ++k) {
                IrStmt& t2 = out[k];
                if (t2.rhs && t2.rhs->containsReg(r)) readLater = true;
                if (t2.lhs && t2.lhs->kind == IrExpr::MEM && t2.lhs->containsReg(r)) readLater = true;
                if (t2.lhs && t2.lhs->kind == IrExpr::REG && t2.lhs->reg == r) break;
            }
            if (!readLater) {
                // mark for removal
                s.kind = IrStmt::COMMENT;
                s.text = "";
            }
        }
        auto& v = blockStmts[b.id];
        for (auto& s : out)
            if (!(s.kind == IrStmt::COMMENT && s.text.empty())) v.push_back(s);
    }

    // ---------- pass 2: structured emission ----------
    std::ostringstream body;
    std::string fname = funcNameIn.empty() ? ("sub_" + hexAddr(funcStart).substr(2)) : funcNameIn;

    std::map<int, int> predCount;
    for (auto& b : blocks) for (int s : b.succ) predCount[s]++;

    std::set<int> skipBlocks;
    std::set<u64> labelsUsed;
    std::map<u64, std::string> labelName;
    for (auto& b : blocks)
        for (int s : b.succ)
            if (labelName.find(blocks[s].start) == labelName.end())
                labelName[blocks[s].start] = "L_" + hexAddr(blocks[s].start).substr(2);

    auto emitStmts = [&](int bid, int indent) {
        std::string pad(indent, ' ');
        for (auto& s : blockStmts[bid]) {
            if (s.kind == IrStmt::ASSIGN) {
                if (s.lhs && s.rhs)
                    body << pad << s.lhs->render() << " = " << s.rhs->render() << ";\n";
            } else if (s.kind == IrStmt::CALL) {
                if (s.rhs) body << pad << s.rhs->render() << ";\n";
            } else if (s.kind == IrStmt::RETURN) {
                if (s.rhs && s.rhs->kind != IrExpr::REG)
                    body << pad << "return " << s.rhs->render() << ";\n";
                else body << pad << "return;\n";
            }
        }
    };

    for (auto& b : blocks) {
        if (skipBlocks.count(b.id)) continue;
        int bid = b.id;

        if (headerToLoop.count(bid)) {
            Loop& L = loops[headerToLoop[bid]];
            body << "    while (" << (L.cond.empty() ? "true" : L.cond) << ") {  // loop @ "
                 << hexAddr(L.headerAddr) << "\n";
            ++res.nWhile;
        }

        if (labelName.count(b.start))
            body << "  " << labelName[b.start] << ":\n";

        emitStmts(bid, 8);

        if (srcToLoop.count(bid)) {
            body << "    }\n";
            continue;
        }

        Term t = termOf(bid);
        if (t.kind != 3) continue;

        int fall = -1, tgt = -1;
        for (auto& b2 : blocks) {
            if (b2.start == b.end && fall < 0) fall = b2.id;
            if (b2.start == t.target && tgt < 0) tgt = b2.id;
        }
        std::string cond = condAtBlock(bid);

        bool diamond = false;
        if (fall >= 0 && tgt >= 0 && tgt != fall && predCount[tgt] == 1) {
            Term tt = termOf(tgt);
            Term tf = termOf(fall);
            u64 mergeT = 0, mergeF = 0;
            if (tt.kind == 2) mergeT = tt.target;
            else if (tt.kind == 0) mergeT = blocks[tgt].end;
            if (tf.kind == 2) mergeF = tf.target;
            else if (tf.kind == 0) mergeF = blocks[fall].end;
            diamond = (mergeT != 0 && mergeT == mergeF && tt.kind == 2);
        }

        if (diamond && tgt >= 0) {
            body << "        if " << cond << " {\n";
            emitStmts(tgt, 12);
            body << "        }\n";
            skipBlocks.insert(tgt);
            ++res.nIf;
        } else if (tgt >= 0 && labelName.count(t.target)) {
            body << "        if " << cond << " goto " << labelName[t.target] << ";\n";
            labelsUsed.insert(t.target);
            ++res.nIf; ++res.nGoto;
        } else if (t.target) {
            std::string lbl = "L_" + hexAddr(t.target).substr(2);
            body << "        if " << cond << " goto " << lbl << ";\n";
            labelName[t.target] = lbl;
            labelsUsed.insert(t.target);
            ++res.nIf; ++res.nGoto;
        }
    }

    // ---------- build final text ----------
    std::ostringstream head;
    // signature
    std::set<std::string> sigArgs;
    for (auto& v : usedVars)
        if (v.rfind("a", 0) == 0 && v.size() == 2 && isdigit((unsigned char)v[1]))
            sigArgs.insert(v);
    for (int i = 0; i <= maxArgSeen; ++i) sigArgs.insert("a" + std::to_string(i));

    bool hasRet = false;
    for (auto& kv : blockStmts)
        for (auto& s : kv.second)
            if (s.kind == IrStmt::RETURN && s.rhs && s.rhs->kind != IrExpr::REG)
                hasRet = true;

    head << (hasRet ? "u64" : "void") << " " << fname << "(";
    std::vector<std::string> argsSorted;
    for (auto& a : sigArgs) argsSorted.push_back(a);
    std::sort(argsSorted.begin(), argsSorted.end(), [](const std::string& x, const std::string& y) {
        int nx = x.size() >= 2 ? (isdigit((unsigned char)x[1]) ? x[1] - '0' : 0) : 0;
        int ny = y.size() >= 2 ? (isdigit((unsigned char)y[1]) ? y[1] - '0' : 0) : 0;
        return nx < ny;
    });
    for (size_t i = 0; i < argsSorted.size(); ++i) {
        if (i) head << ", ";
        head << "u64 " << argsSorted[i];
    }
    head << ") {  // SakoRE IR\n";

    // declarations: only registers actually written via statements
    std::set<std::string> writtenRegs;
    for (auto& kv : blockStmts)
        for (auto& s : kv.second)
            if (s.kind == IrStmt::ASSIGN && s.lhs && s.lhs->kind == IrExpr::REG)
                writtenRegs.insert(s.lhs->reg);
    for (auto& w : writtenRegs) {
        if (sigArgs.count(w)) continue;
        if (w == "0" || w == "mem") continue;
        head << "    u64 " << w << ";\n";
    }
    // memory cells assigned through pointers are anonymous — nothing to declare

    std::string bodyStr = body.str();
    // balance braces: unclosed loop headers get closers; stray closers removed
    {
        int net = 0;
        for (char c : bodyStr) { if (c == '{') ++net; else if (c == '}') --net; }
        if (net > 0) {
            for (int i = 0; i < net; ++i) bodyStr += "    }\n";
        } else if (net < 0) {
            int excess = -net;
            std::vector<std::string> lines;
            size_t pos = 0;
            while (pos <= bodyStr.size()) {
                size_t nl = bodyStr.find('\n', pos);
                if (nl == std::string::npos) { lines.push_back(bodyStr.substr(pos)); break; }
                lines.push_back(bodyStr.substr(pos, nl - pos));
                pos = nl + 1;
            }
            for (size_t k = lines.size(); k-- > 0 && excess > 0;) {
                std::string t = lines[k];
                while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();
                if (t == "}") { lines[k].clear(); --excess; }
            }
            std::ostringstream join;
            for (auto& l : lines) join << l << "\n";
            bodyStr = join.str();
        }
    }
    std::string text = head.str() + bodyStr + "}\n";

    // strip unreferenced labels
    {
        std::vector<std::string> allLines;
        size_t pos = 0;
        while (pos <= text.size()) {
            size_t nl = text.find('\n', pos);
            if (nl == std::string::npos) { allLines.push_back(text.substr(pos)); break; }
            allLines.push_back(text.substr(pos, nl - pos));
            pos = nl + 1;
        }
        std::ostringstream finalText;
        for (auto& ln : allLines) {
            std::string tr = ln;
            while (!tr.empty() && (tr.front() == ' ' || tr.front() == '\t')) tr.erase(0, 1);
            if (tr.rfind("L_", 0) == 0 && tr.find(':') != std::string::npos) {
                std::string lbl = tr.substr(0, tr.find(':'));
                if (text.find("goto " + lbl + ";") == std::string::npos) continue;
            }
            finalText << ln << "\n";
        }
        res.text = finalText.str();
    }
    res.ok = true;
    for (auto& kv : blockStmts) res.nStmts += int(kv.second.size());
    return res;
}

} // namespace sako
