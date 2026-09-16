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
    // args carries call arguments and the else-value of a lifted ternary; not
    // counting them let unbounded expressions through the propagation guard.
    for (auto& x : args) n += x->complexity();
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
            // hexAddr() already emits the "0x" prefix; prepending another one
            // produced literals like "0x0x169000".
            if (i64(imm) < 0 && i64(imm) > -0x10000)
                return "-" + std::to_string(-i64(imm));
            if (imm >= 0x10000) return hexAddr(imm);
            return std::to_string(imm);
        }
        case REG:  return reg;
        case STRREF: return "\"" + name + "\"";
        case MEM: {
            // *(u64*)(&sym) is just sym.
            if (imm == 0 && a && a->kind == REG && a->reg.size() > 1 && a->reg[0] == '&')
                return a->reg.substr(1);
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
            // csel and friends lift to a ternary: cond in `a`, the taken value
            // in `b`, the untaken value in args[0].
            if (binop == "?:")
                return "(" + l + " ? " + r + " : " +
                       (args.empty() ? "0" : args[0]->render()) + ")";
            return "(" + l + " " + binop + " " + r + ")";
        }
        case UN:
            if (binop == "~" && a && a->kind == IMM)
                return IrExpr::makeImm(~a->imm & (a->size >= 8 ? ~u64(0)
                                                              : ((u64(1) << (a->size * 8)) - 1)),
                                       a->size)->render();
            return "(" + binop + "(" + (a ? a->render() : "?") + "))";
        case CALL: {
            // isBool marks a call where no argument register was set up in the
            // reconstructed region: the arguments are unknown, not absent.
            if (args.empty() && isBool) return name + "(...)";
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
        while (!rest.empty() && (rest.back() == ' ' || rest.back() == '!')) rest.pop_back();
        // Only a leading '#' marks an immediate displacement. Without this
        // check "[x1, x2, lsl #3]" parsed the shift amount as an offset, and
        // the '-' of "#-0x24" was skipped entirely by searching for "0x".
        if (!rest.empty() && rest[0] == '#') {
            std::string num = rest.substr(1);
            bool neg = false;
            if (!num.empty() && (num[0] == '-' || num[0] == '+')) {
                neg = (num[0] == '-');
                num.erase(0, 1);
            }
            u64 v = 0;
            if (num.rfind("0x", 0) == 0 || num.rfind("0X", 0) == 0)
                v = strtoull(num.c_str() + 2, nullptr, 16);
            else v = strtoull(num.c_str(), nullptr, 10);
            off = neg ? -i64(v) : i64(v);
        }
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

// Truncate to a register width so 32-bit arithmetic does not leak high bits.
u64 truncTo(u64 v, int bytes) {
    if (bytes >= 8) return v;
    return v & ((u64(1) << (bytes * 8)) - 1);
}

i64 signExtend(u64 v, int bytes) {
    if (bytes >= 8) return i64(v);
    u64 m = u64(1) << (bytes * 8 - 1);
    v = truncTo(v, bytes);
    return i64((v ^ m) - m);
}

// Constant-fold a binary node. movz/movk pairs and adrp/add pairs both build
// their value across two instructions, so without folding every reconstructed
// address and immediate stayed split across an expression tree.
std::shared_ptr<IrExpr> foldBin(const std::string& op,
                                std::shared_ptr<IrExpr> l,
                                std::shared_ptr<IrExpr> r) {
    if (l && r && l->kind == IrExpr::IMM && r->kind == IrExpr::IMM) {
        int w = l->size > r->size ? l->size : r->size;
        u64 a = l->imm, b = r->imm, v = 0;
        bool ok = true;
        if      (op == "+")  v = a + b;
        else if (op == "-")  v = a - b;
        else if (op == "*")  v = a * b;
        else if (op == "&")  v = a & b;
        else if (op == "|")  v = a | b;
        else if (op == "^")  v = a ^ b;
        else if (op == "<<") v = (b < 64) ? (a << b) : 0;
        else if (op == ">>") v = (b < 64) ? (a >> b) : 0;
        else if (op == "/")  { if (b) v = a / b; else ok = false; }
        else ok = false;
        if (ok) return IrExpr::makeImm(truncTo(v, w), w);
    }
    // x + 0 / x - 0 / x * 1 add nothing but noise to the output.
    if (r && r->kind == IrExpr::IMM && r->imm == 0 && (op == "+" || op == "-" ||
        op == "|" || op == "^" || op == "<<" || op == ">>")) return l;
    if (r && r->kind == IrExpr::IMM && r->imm == 1 && (op == "*" || op == "/")) return l;
    return IrExpr::makeBin(op, l, r);
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
            for (int i = 0; i <= 7; ++i) {
                std::string n = "a" + std::to_string(i);
                regs["x" + std::to_string(i)] = IrExpr::makeReg(n, 8, true);
                regs["w" + std::to_string(i)] = IrExpr::makeReg(n, 4, true);
            }
        } else {
            const char* args[6] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
            for (int i = 0; i < 6; ++i)
                regs[args[i]] = IrExpr::makeReg("a" + std::to_string(i), 8, true);
        }
    };

    auto readReg = [&](const std::string& r) -> std::shared_ptr<IrExpr> {
        if (isZeroReg(r)) return IrExpr::makeImm(0);
        auto it = regs.find(r);
        if (it != regs.end() && it->second && it->second->complexity() <= 8) {
            auto e = it->second->clone();
            // A propagated value may itself still be the incoming a<n> seed;
            // recording the names it mentions is what makes the reconstructed
            // signature list the parameters the body actually reads.
            e->collectRegs(usedVars);
            return e;
        }
        // ARM w0..w7 are the low halves of argument registers a0..a7
        if (arm && r.size() == 2 && r[0] == 'w' && isdigit((unsigned char)r[1])) {
            int n = r[1] - '0';
            if (n <= 7) {
                usedVars.insert("a" + std::to_string(n));
                return IrExpr::makeReg("a" + std::to_string(n), 4, true);
            }
        }
        usedVars.insert(regVar(r));
        return IrExpr::makeReg(regVar(r), regBytes(r));
    };

    // A reconstructed absolute address is far more useful as the string or
    // symbol it points at. adrp+add pairs are the usual way ARM64 materialises
    // one, and previously they surfaced as raw arithmetic on a page address.
    std::map<u64, const FoundString*> strAt;
    for (auto& fs : strings) strAt.emplace(fs.addr, &fs);

    auto resolveAddr = [&](u64 v) -> std::shared_ptr<IrExpr> {
        auto si = strAt.find(v);
        if (si != strAt.end()) {
            auto e = IrExpr::make(IrExpr::STRREF);
            std::string t = si->second->value;
            if (t.size() > 72) t = t.substr(0, 72) + "...";
            std::string esc;
            for (char c : t) {
                if (c == '"' || c == '\\') { esc += '\\'; esc += c; }
                else if (c == '\n') esc += "\\n";
                else if (c == '\t') esc += "\\t";
                else esc += c;
            }
            e->name = esc;
            e->size = 8;
            return e;
        }
        std::string nm = names.lookup(v);
        if (!nm.empty() && nm.find('+') == std::string::npos)
            return IrExpr::makeReg("&" + nm, 8);
        return IrExpr::makeImm(v);
    };

    // Build a load/store operand, folding a constant base plus displacement
    // into one absolute address so it can be named.
    auto memAt = [&](std::shared_ptr<IrExpr> base, i64 off, int sz) -> std::shared_ptr<IrExpr> {
        if (base && base->kind == IrExpr::IMM) {
            u64 abs = base->imm + u64(off);
            auto r = resolveAddr(abs);
            if (r->kind == IrExpr::REG) return IrExpr::makeMem(r, 0, sz);
            return IrExpr::makeMem(IrExpr::makeImm(abs), 0, sz);
        }
        return IrExpr::makeMem(base, off, sz);
    };

    auto immOrReg = [&](std::string s2) -> std::shared_ptr<IrExpr> {
        if (!s2.empty() && s2[0] == '#') s2.erase(0, 1);
        u64 v;
        if (parseHex(s2, v)) return IrExpr::makeImm(v);
        if (!s2.empty() && isdigit((unsigned char)s2[0]))
            return IrExpr::makeImm(u64(strtoull(s2.c_str(), nullptr, 10)));
        return readReg(s2);
    };

    // ARM64 defines a write to Wn as zero-extending into Xn. Tracking only the
    // name the instruction happened to use meant "mov w3, wzr" was invisible to
    // anything that later read x3.
    auto setReg = [&](const std::string& d, std::shared_ptr<IrExpr> v) {
        regs[d] = v;
        if (!arm || !v || d.size() < 2 || (d[0] != 'w' && d[0] != 'x')) return;
        if (d.find_first_not_of("0123456789", 1) != std::string::npos) return;
        std::string other = (d[0] == 'w' ? "x" : "w") + d.substr(1);
        if (v->kind == IrExpr::IMM)
            regs[other] = IrExpr::makeImm(truncTo(v->imm, 4), d[0] == 'w' ? 8 : 4);
        else
            regs[other] = v;
    };

    auto clearFlags = [&]() { fl_a = nullptr; fl_b = nullptr; };

    // How many argument registers were set up before this call. A register
    // still holding its pristine a<n> seed was never written here, so claiming
    // it as an argument is a guess the listing should not make.
    auto argsSetUp = [&](const char* const* names_, int maxN) -> int {
        int last = -1;
        for (int i = 0; i < maxN; ++i) {
            auto it = regs.find(names_[i]);
            if (it == regs.end() || !it->second) continue;
            auto& e = it->second;
            bool pristine = (e->kind == IrExpr::REG && e->isArg &&
                             e->reg == "a" + std::to_string(i));
            if (!pristine) last = i;
        }
        return last + 1;
    };
    static const char* kArmArgs[8] = {"x0","x1","x2","x3","x4","x5","x6","x7"};
    static const char* kX86Args[6] = {"rdi","rsi","rdx","rcx","r8","r9"};
    // Call results bind to a temporary. Propagating the call expression itself
    // made a value used three times print the whole call three times, which
    // also reads as three separate calls.
    int tmpSeq = 0;

    // Width of the operands the last compare set the flags from. Needed to
    // fold a constant comparison with the right signedness and truncation.
    int flWidth = 8;

    // Returns "" when the condition could not be recovered, "true"/"false"
    // when it folds to a constant, and a C expression otherwise.
    auto condText = [&](const std::string& mnem) -> std::string {
        if (!fl_a) return "";
        std::string m = lower(mnem);
        std::string op;
        bool uns = false;
        if (m == "b.eq" || m == "je" || m == "jz" || m == "cbz") op = "==";
        else if (m == "b.ne" || m == "jne" || m == "jnz" || m == "cbnz") op = "!=";
        else if (m == "b.lt" || m == "b.mi" || m == "jl" || m == "js") op = "<";
        else if (m == "b.le" || m == "jle" || m == "jng") op = "<=";
        else if (m == "b.gt" || m == "jg" || m == "jnle") op = ">";
        else if (m == "b.ge" || m == "b.pl" || m == "jge" || m == "jnl") op = ">=";
        else if (m == "b.lo" || m == "b.cc" || m == "bcc" || m == "jb" || m == "jc") { op = "<"; uns = true; }
        else if (m == "b.ls" || m == "jbe" || m == "jna") { op = "<="; uns = true; }
        else if (m == "b.hi" || m == "ja") { op = ">"; uns = true; }
        else if (m == "b.hs" || m == "b.cs" || m == "jae" || m == "jnc") { op = ">="; uns = true; }
        else if (m == "b.al") return "true";
        else if (m == "b.nv") return "false";
        else return "";

        auto rhs = fl_b ? fl_b : IrExpr::makeImm(0);
        std::string ls = fl_a->render(), rs = rhs->render();

        // Both sides constant: decide it here rather than emitting a branch on
        // a comparison of two literals. Obfuscators lean on exactly this.
        if (fl_a->kind == IrExpr::IMM && rhs->kind == IrExpr::IMM) {
            bool r;
            if (uns) {
                u64 x = truncTo(fl_a->imm, flWidth), y = truncTo(rhs->imm, flWidth);
                r = op == "==" ? x == y : op == "!=" ? x != y : op == "<" ? x < y :
                    op == "<=" ? x <= y : op == ">" ? x > y : x >= y;
            } else {
                i64 x = signExtend(fl_a->imm, flWidth), y = signExtend(rhs->imm, flWidth);
                r = op == "==" ? x == y : op == "!=" ? x != y : op == "<" ? x < y :
                    op == "<=" ? x <= y : op == ">" ? x > y : x >= y;
            }
            return r ? "true" : "false";
        }
        // A register compared against itself ("cmp w24, w24") is a constant
        // regardless of its value — another control-flow flattening idiom.
        if (ls == rs && fl_a->kind == IrExpr::REG && rhs->kind == IrExpr::REG)
            return (op == "==" || op == "<=" || op == ">=") ? "true" : "false";

        return "(" + ls + " " + op + " " + rs + ")";
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
            m == "cdqe" || m == "cqo" || m == "xchg") return "";
        if (arm) {
            if (m == "stp" && ops.find("x29") != std::string::npos) return "";
            if (m == "ldp" && ops.find("x29") != std::string::npos) return "";
            if (m == "sub" && toks.size() >= 2 && toks[0] == "sp" && toks[1] == "sp") return "";
            if (m == "add" && toks.size() >= 2 && toks[0] == "sp" && toks[1] == "sp") return "";
            // Frame-pointer setup. Propagating sp into x29 made the same slot
            // print as "sp + N" before this point and "fp + N" after it.
            if ((m == "mov" || m == "add") && toks.size() >= 2 &&
                toks[0] == "x29" && toks[1] == "sp") return "";
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
            // movz/movk/movn carry an optional "lsl #N" third operand, and a
            // 64-bit constant is normally assembled as movz + up to three movk.
            auto shiftOf = [&](const std::vector<std::string>& t) -> int {
                if (t.size() < 3) return 0;
                size_t h = t[2].find('#');
                return h == std::string::npos ? 0 : atoi(t[2].c_str() + h + 1);
            };
            auto immOf = [&](std::string t, u64& v) -> bool {
                if (!t.empty() && t[0] == '#') t.erase(0, 1);
                if (parseHex(t, v)) return true;
                if (!t.empty() && (isdigit((unsigned char)t[0]) || t[0] == '-')) {
                    v = u64(strtoll(t.c_str(), nullptr, 10));
                    return true;
                }
                return false;
            };

            if (m == "mov" || m == "movz" || m == "movn") {
                if (toks.size() < 2) return "";
                std::string d = toks[0];
                int w = regBytes(d);
                u64 iv;
                if ((m == "movz" || m == "movn") && immOf(toks[1], iv)) {
                    u64 val = (shiftOf(toks) < 64) ? (iv << shiftOf(toks)) : 0;
                    if (m == "movn") val = ~val;
                    setReg(d, IrExpr::makeImm(truncTo(val, w), w));
                    return "";
                }
                auto v = immOrReg(toks[1]);
                if (isZeroReg(toks[1])) v = IrExpr::makeImm(0);
                setReg(d, v);
                return "";
            }
            if (m == "movk") {
                if (toks.size() < 2) return "";
                std::string d = toks[0];
                int w = regBytes(d);
                u64 iv = 0;
                if (!immOf(toks[1], iv)) return "";
                int sh = shiftOf(toks);
                u64 mask = (sh < 64) ? ~(u64(0xFFFF) << sh) : ~u64(0);
                u64 ins = (sh < 64) ? (iv << sh) : 0;
                auto it = regs.find(d);
                if (it != regs.end() && it->second && it->second->kind == IrExpr::IMM) {
                    setReg(d, IrExpr::makeImm(truncTo((it->second->imm & mask) | ins, w), w));
                } else {
                    setReg(d, foldBin("|",
                        foldBin("&", readReg(d), IrExpr::makeImm(mask, w)),
                        IrExpr::makeImm(ins, w)));
                }
                return "";
            }
            if (m == "add" || m == "sub" || m == "mul" || m == "and" || m == "orr" ||
                m == "eor" || m == "lsl" || m == "lsr" || m == "asr" || m == "udiv" ||
                m == "sdiv" || m == "madd" || m == "msub" || m == "neg") {
                if (toks.size() < 2) return "";
                std::string d = toks[0];
                if (m == "neg") {
                    setReg(d, IrExpr::makeBin("-", IrExpr::makeImm(0), readReg(toks[1])));
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
                auto e = foldBin(op, v1, v2);
                if ((m == "madd" || m == "msub") && toks.size() >= 4) {
                    auto v3 = readReg(toks[3]);
                    e = foldBin(m == "madd" ? "+" : "-", e, v3);
                }
                // "adrp xN, page" + "add xN, xN, #off" is how ARM64 forms the
                // address of a string or global; once folded it can be named.
                if (m == "add" && e->kind == IrExpr::IMM && e->imm >= 0x1000)
                    e = resolveAddr(e->imm);
                setReg(d, e);
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
                    setReg(toks[0], IrExpr::makeCond(op, fl_a->clone(),
                                                     fl_b ? fl_b->clone() : IrExpr::makeImm(0)));
                else setReg(toks[0], IrExpr::makeImm(1));
                clearFlags();
                return "";
            }
            if (m == "cmp" || m == "cmn" || m == "tst" || m == "subs" || m == "adds") {
                if (toks.size() < 2) { clearFlags(); return ""; }
                size_t li = (m == "subs" || m == "adds") ? 1 : 0;
                if (toks.size() <= li + 1) { clearFlags(); return ""; }
                flWidth = regBytes(toks[li]);
                fl_a = readReg(toks[li]);
                fl_b = immOrReg(toks[li + 1]);
                if (m == "tst") {
                    fl_a = foldBin("&", fl_a, fl_b);
                    fl_b = IrExpr::makeImm(0);
                }
                if (m == "subs" || m == "adds")
                    setReg(toks[0], foldBin(m == "subs" ? "-" : "+", fl_a->clone(), fl_b->clone()));
                return "";
            }
            if (m == "adrp" || m == "adr") {
                if (toks.size() < 2) return "";
                u64 v;
                if (parseHex(toks[1], v)) {
                    // adrp yields a page base that the next add completes, so it
                    // stays a bare immediate; adr is already the final address.
                    if (m == "adr") setReg(toks[0], resolveAddr(v));
                    else setReg(toks[0], IrExpr::makeImm(v));
                }
                return "";
            }
            // ldr xN, =literal / ldr xN, #pc-relative resolves through the
            // literal pool; Capstone renders the target address directly.
            if (m == "csel" || m == "csinc" || m == "csinv" || m == "csneg" ||
                m == "cinc" || m == "cinv" || m == "cneg" || m == "csetm") {
                if (toks.empty()) return "";
                std::string d = toks[0];
                auto ccOf = [&](const std::string& cc) -> std::string {
                    std::string b = cc.substr(0, cc.find('.'));
                    if (b == "eq") return "=="; if (b == "ne") return "!=";
                    if (b == "lt" || b == "lo" || b == "cc") return "<";
                    if (b == "le" || b == "ls") return "<=";
                    if (b == "gt" || b == "hi") return ">";
                    if (b == "ge" || b == "hs" || b == "cs") return ">=";
                    return "";
                };
                if (m == "csetm") {
                    setReg(d, fl_a ? IrExpr::makeCond(ccOf(toks.size() > 1 ? toks[1] : "ne"),
                                                      fl_a->clone(),
                                                      fl_b ? fl_b->clone() : IrExpr::makeImm(0))
                                   : IrExpr::makeImm(0));
                    clearFlags();
                    return "";
                }
                if (toks.size() < 3) return "";
                bool three = (m == "csel" || m == "csinc" || m == "csinv" || m == "csneg");
                std::string ccTok = three ? (toks.size() > 3 ? toks[3] : "ne") : toks[2];
                std::string op = ccOf(ccTok);
                auto tv = readReg(toks[1]);
                auto fv = three ? readReg(toks[2]) : readReg(toks[1]);
                if (m == "csinc" || m == "cinc") fv = foldBin("+", fv, IrExpr::makeImm(1));
                else if (m == "csinv" || m == "cinv") {
                    auto n = IrExpr::make(IrExpr::UN); n->binop = "~"; n->a = fv; fv = n;
                }
                else if (m == "csneg" || m == "cneg") fv = foldBin("-", IrExpr::makeImm(0), fv);
                if (!op.empty() && fl_a) {
                    auto c = IrExpr::makeCond(op, fl_a->clone(),
                                              fl_b ? fl_b->clone() : IrExpr::makeImm(0));
                    auto sel = IrExpr::make(IrExpr::BIN);
                    sel->binop = "?:"; sel->a = c; sel->b = tv;
                    sel->args.push_back(fv);
                    sel->size = regBytes(d);
                    if (sel->complexity() > 4) {
                        auto tmp = IrExpr::makeReg("v" + std::to_string(++tmpSeq), sel->size);
                        out.push_back(IrStmt::makeAssign(tmp->clone(), sel, l.addr));
                        setReg(d, tmp);
                    } else setReg(d, sel);
                } else setReg(d, tv);
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
                setReg(d, memAt(readReg(base), off, sz));
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
                auto memE = memAt(readReg(base), off, sz);
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
                int na = argsSetUp(kArmArgs, 8);
                for (int i = 0; i < na; ++i)
                    callE->args.push_back(readReg(kArmArgs[i]));
                if (na == 0) callE->name += "";   // rendered as f(...) below
                callE->isBool = (na == 0);
                IrStmt s; s.kind = IrStmt::CALL; s.rhs = callE; s.addr = l.addr;
                s.lhs = IrExpr::makeReg("v" + std::to_string(++tmpSeq), 8);
                out.push_back(s);
                setReg("x0", s.lhs->clone());
                ++res.nCalls;
                return "";
            }
            if (m == "blr") {
                if (toks.empty()) return "";
                auto callE = IrExpr::makeCall(readReg(toks[0])->render());
                int na = argsSetUp(kArmArgs, 8);
                for (int i = 0; i < na; ++i)
                    callE->args.push_back(readReg(kArmArgs[i]));
                callE->isBool = (na == 0);
                IrStmt s; s.kind = IrStmt::CALL; s.rhs = callE; s.addr = l.addr;
                s.lhs = IrExpr::makeReg("v" + std::to_string(++tmpSeq), 8);
                out.push_back(s);
                setReg("x0", s.lhs->clone());
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
            flWidth = regBytes(s1);
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
            int na = argsSetUp(kX86Args, 6);
            for (int i = 0; i < na; ++i)
                callE->args.push_back(readReg(kX86Args[i]));
            callE->isBool = (na == 0);
            IrStmt s; s.kind = IrStmt::CALL; s.rhs = callE; s.addr = l.addr;
            s.lhs = IrExpr::makeReg("v" + std::to_string(++tmpSeq), 8);
            out.push_back(s);
            regs["rax"] = s.lhs->clone();
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

    // ---------- pass 1: lift blocks ----------
    // A block with a single predecessor starts from that predecessor's exit
    // state. ARM64 puts the cmp and the b.cc in separate blocks whenever a
    // compare feeds more than one branch, so lifting each block from scratch
    // left the flags empty and the branch condition unrecoverable.
    std::map<int, std::vector<IrStmt>> blockStmts;
    std::map<int, std::string> blockCond;
    struct ExitState {
        std::map<std::string, std::shared_ptr<IrExpr>> regs;
        std::shared_ptr<IrExpr> fa, fb;
        int fw = 8;
        bool valid = false;
    };
    std::vector<ExitState> exitState;
    exitState.resize(size_t(nB));

    for (auto& b : blocks) {
        std::vector<IrStmt> out;
        int soleP = -1;
        {
            auto pit = preds.find(b.id);
            if (pit != preds.end() && pit->second.size() == 1) soleP = *pit->second.begin();
        }
        if (soleP >= 0 && soleP < nB && exitState[size_t(soleP)].valid) {
            auto& e = exitState[size_t(soleP)];
            regs = e.regs; fl_a = e.fa; fl_b = e.fb; flWidth = e.fw;
        } else {
            initRegs();
            flWidth = 8;
        }
        bool done = false;
        for (auto& l : lines) {
            if (l.addr < b.start || l.addr >= b.end) continue;
            if (done) break;
            std::string ctl = lift(l, out);
            if (ctl.rfind("cjmp:", 0) == 0) {
                size_t bar = ctl.find('|');
                blockCond[b.id] = condText(bar == std::string::npos ? std::string()
                                                                   : ctl.substr(bar + 1));
                done = true;
            } else if (ctl == "ret" || ctl.rfind("jmp:", 0) == 0) done = true;
        }
        {
            auto& e = exitState[size_t(b.id)];
            e.regs = regs; e.fa = fl_a; e.fb = fl_b; e.fw = flWidth; e.valid = true;
        }
        // dead-store elimination on register assignments
        for (size_t i = 0; i < out.size(); ++i) {
            IrStmt& s = out[i];
            if (s.kind != IrStmt::ASSIGN || !s.lhs || s.lhs->kind != IrExpr::REG) continue;
            std::string r = s.lhs->reg;
            if (r == "x0" || r == "rax") continue;   // return-value regs stay
            // Temporaries are block-local names but can be read from a block
            // that inherits this one's state; usedTemps decides their fate.
            if (!r.empty() && r[0] == 'v') continue;
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

    // ---------- loop validation ----------
    // A back edge alone does not make a region that can be printed as a while
    // loop. Unless the header dominates every block up to the back-edge source
    // and nothing jumps into the middle from outside, emitting `while` puts a
    // closing brace in the wrong place and swallows the branches after it.
    // Obfuscated dispatch loops hit exactly that case, so they stay as labels.
    {
        std::vector<Loop> keep;
        std::map<int, int> h2, s2;
        for (auto& L : loops) {
            if (L.src < L.header) continue;
            bool good = true;
            for (int i = L.header; i <= L.src && good; ++i) {
                if (!dominates(L.header, i)) good = false;
                if (i == L.header) continue;
                auto pit = preds.find(i);
                if (pit == preds.end()) continue;
                for (int pp : pit->second)
                    if (pp < L.header || pp > L.src) { good = false; break; }
            }
            if (!good) continue;
            // The back edge must be the block's own terminator, and the loop
            // must be left by falling out of the source block.
            Term st = termOf(L.src);
            if (st.kind != 3 || st.target != blocks[L.header].start) continue;
            std::string c = blockCond.count(L.src) ? blockCond[L.src] : std::string();
            if (c.empty() || c == "false") continue;
            L.cond = c;
            h2[L.header] = int(keep.size());
            s2[L.src] = int(keep.size());
            keep.push_back(L);
        }
        loops.swap(keep);
        headerToLoop.swap(h2);
        srcToLoop.swap(s2);
    }

    // A call temporary is only worth naming when something reads it; otherwise
    // the call stands on its own as a statement.
    std::set<std::string> usedTemps;
    for (auto& kv : blockStmts)
        for (auto& st : kv.second) {
            std::set<std::string> r;
            if (st.rhs) st.rhs->collectRegs(r);
            if (st.lhs && st.lhs->kind != IrExpr::REG) st.lhs->collectRegs(r);
            for (auto& n : r)
                if (n.size() > 1 && n[0] == 'v' &&
                    n.find_first_not_of("0123456789", 1) == std::string::npos)
                    usedTemps.insert(n);
        }
    for (auto& kv : blockCond) {
        const std::string& c = kv.second;
        for (size_t i = 0; i + 1 < c.size(); ++i) {
            if (c[i] != 'v' || (i && (isalnum((unsigned char)c[i - 1]) || c[i - 1] == '_'))) continue;
            size_t j = i + 1;
            while (j < c.size() && isdigit((unsigned char)c[j])) ++j;
            if (j > i + 1 && (j >= c.size() || !(isalnum((unsigned char)c[j]) || c[j] == '_')))
                usedTemps.insert(c.substr(i, j - i));
        }
    }

    // ---------- pass 2: structured emission ----------
    std::ostringstream body;
    std::string fname = funcNameIn.empty() ? ("sub_" + hexAddr(funcStart).substr(2)) : funcNameIn;

    std::map<int, int> predCount;
    for (auto& b : blocks) for (int s : b.succ) predCount[s]++;

    std::set<int> skipBlocks;
    std::set<u64> labelsUsed;
    std::set<std::string> unrecoveredCC;
    std::map<u64, std::string> labelName;
    for (auto& b : blocks)
        for (int s : b.succ)
            if (labelName.find(blocks[s].start) == labelName.end())
                labelName[blocks[s].start] = "L_" + hexAddr(blocks[s].start).substr(2);

    auto emitStmts = [&](int bid, int indent) {
        std::string pad(indent, ' ');
        for (auto& s : blockStmts[bid]) {
            if (s.kind == IrStmt::ASSIGN) {
                if (s.lhs && s.lhs->kind == IrExpr::REG && !s.lhs->reg.empty() &&
                    s.lhs->reg[0] == 'v' && !usedTemps.count(s.lhs->reg)) continue;
                if (s.lhs && s.rhs)
                    body << pad << s.lhs->render() << " = " << s.rhs->render() << ";\n";
            } else if (s.kind == IrStmt::CALL) {
                if (!s.rhs) continue;
                if (s.lhs && usedTemps.count(s.lhs->reg))
                    body << pad << s.lhs->render() << " = " << s.rhs->render() << ";\n";
                else
                    body << pad << s.rhs->render() << ";\n";
            } else if (s.kind == IrStmt::RETURN) {
                // Returning the entry value of a0 means nothing was computed;
                // anything else is a real return value.
                if (s.rhs && !(s.rhs->kind == IrExpr::REG && s.rhs->isArg))
                    body << pad << "return " << s.rhs->render() << ";\n";
                else body << pad << "return;\n";
            }
        }
    };

    // Addresses still reached by a surviving branch. A block that is only
    // reachable by falling through an unconditional transfer is dead once a
    // constant branch above it has been folded away.
    std::set<u64> branchTargets;
    for (auto& b2 : blocks) {
        Term t2 = termOf(b2.id);
        std::string c2 = blockCond.count(b2.id) ? blockCond[b2.id] : std::string();
        if (t2.kind == 2 && t2.target) branchTargets.insert(t2.target);
        else if (t2.kind == 3 && t2.target && c2 != "false") branchTargets.insert(t2.target);
    }
    for (auto& L : loops) branchTargets.insert(blocks[L.header].start);

    bool reachable = true;
    for (auto& b : blocks) {
        if (skipBlocks.count(b.id)) continue;
        int bid = b.id;
        if (branchTargets.count(b.start)) reachable = true;
        if (!reachable) continue;

        if (headerToLoop.count(bid)) {
            Loop& L = loops[headerToLoop[bid]];
            body << "    do {  // loop @ " << hexAddr(L.headerAddr) << "\n";
            ++res.nWhile;
        }

        if (labelName.count(b.start))
            body << "  " << labelName[b.start] << ":\n";

        emitStmts(bid, 8);

        if (srcToLoop.count(bid)) {
            Loop& L = loops[srcToLoop[bid]];
            body << "    } while (" << (L.cond.empty() ? "true" : L.cond) << ");\n";
            continue;
        }

        Term t = termOf(bid);

        // Does some block start at this address? A branch out of the function
        // (a tail call) has no label to jump to and must not become a goto.
        auto blockAt = [&](u64 a) -> int {
            if (!a) return -1;
            for (auto& b2 : blocks) if (b2.start == a) return b2.id;
            return -1;
        };
        auto gotoTarget = [&](u64 a, int indent) -> bool {
            std::string pad(indent, ' ');
            if (blockAt(a) < 0) {
                body << pad << "/* branch to " << hexAddr(a) << " — outside this function */\n";
                return false;
            }
            std::string lbl = labelName.count(a) ? labelName[a] : ("L_" + hexAddr(a).substr(2));
            labelName[a] = lbl;
            body << pad << "goto " << lbl << ";\n";
            labelsUsed.insert(a);
            ++res.nGoto;
            return true;
        };

        if (t.kind == 2) {
            if (t.target && t.target != b.end) gotoTarget(t.target, 8);
            reachable = false;
            continue;
        }
        if (t.kind == 1) { reachable = false; continue; }
        if (t.kind != 3) continue;

        int fall = -1, tgt = -1;
        for (auto& b2 : blocks) {
            if (b2.start == b.end && fall < 0) fall = b2.id;
            if (b2.start == t.target && tgt < 0) tgt = b2.id;
        }
        std::string cond = blockCond.count(bid) ? blockCond[bid] : std::string();

        // A condition that folded to a constant is not worth printing as a
        // branch: the taken edge becomes a plain goto, the untaken one vanishes.
        if (cond == "false") continue;
        if (cond == "true") {
            if (t.target) gotoTarget(t.target, 8);
            reachable = false;
            continue;
        }
        if (cond.empty()) {
            // The flag-setting instruction is outside the reconstructed region.
            // Say so with a named token rather than inventing a condition.
            std::string cc = "CC";
            for (auto& l : lines)
                if (l.addr >= b.start && l.addr < b.end) {
                    std::string mm = lower(l.mnem);
                    if (mm.rfind("b.", 0) == 0) cc = "CC_" + mm.substr(2);
                    else if (mm.size() > 1 && mm[0] == 'j' && mm != "jmp")
                        cc = "CC_" + mm.substr(1);
                }
            for (auto& c : cc) if (c >= 'a' && c <= 'z') c = char(c - 'a' + 'A');
            cond = "(" + cc + ")";
            unrecoveredCC.insert(cc);
        }

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
        } else if (t.target && blockAt(t.target) >= 0) {
            std::string lbl = labelName.count(t.target) ? labelName[t.target]
                                                        : ("L_" + hexAddr(t.target).substr(2));
            labelName[t.target] = lbl;
            body << "        if " << cond << " goto " << lbl << ";\n";
            labelsUsed.insert(t.target);
            ++res.nIf; ++res.nGoto;
        } else if (t.target) {
            body << "        if " << cond
                 << " { /* branch to " << hexAddr(t.target) << " — outside this function */ }\n";
            ++res.nIf;
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
            if (s.kind == IrStmt::RETURN && s.rhs &&
                !(s.rhs->kind == IrExpr::REG && s.rhs->isArg))
                hasRet = true;

    head << (hasRet ? "u64" : "void") << " " << fname << "(";
    std::vector<std::string> argsSorted;
    for (auto& a : sigArgs) argsSorted.push_back(a);
    std::sort(argsSorted.begin(), argsSorted.end(), [](const std::string& x, const std::string& y) {
        int nx = x.size() >= 2 ? (isdigit((unsigned char)x[1]) ? x[1] - '0' : 0) : 0;
        int ny = y.size() >= 2 ? (isdigit((unsigned char)y[1]) ? y[1] - '0' : 0) : 0;
        return nx < ny;
    });
    if (argsSorted.empty()) head << "void";
    for (size_t i = 0; i < argsSorted.size(); ++i) {
        if (i) head << ", ";
        head << "u64 " << argsSorted[i];
    }
    head << ") {  // Nocturne IR\n";

    std::string bodyStr = body.str();
    // balance braces: unclosed loop headers get closers; stray closers removed
    {
        int net = 0;
        for (char c : bodyStr) { if (c == '{') ++net; else if (c == '}') --net; }
        if (net > 0) {
            for (int i = 0; i < net; ++i) bodyStr += "    } while (0);\n";
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
    // Clean the body before deriving anything from it: single-use temporaries,
    // gotos that land on the next line and labels nothing jumps to all
    // disappear, and the declaration list must reflect what survives.
    std::vector<std::string> allLines;
    {
        size_t pos = 0;
        while (pos <= bodyStr.size()) {
            size_t nl = bodyStr.find('\n', pos);
            if (nl == std::string::npos) { allLines.push_back(bodyStr.substr(pos)); break; }
            allLines.push_back(bodyStr.substr(pos, nl - pos));
            pos = nl + 1;
        }
    }

    auto scanIdents = [](const std::string& ln, const std::function<void(const std::string&)>& fn) {
        std::string tok;
        bool inStr = false;
        for (size_t i = 0; i <= ln.size(); ++i) {
            char c = i < ln.size() ? ln[i] : '\n';
            if (inStr) {                    // identifiers inside a recovered
                if (c == '\\') ++i;         // string literal are text, not code
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { tok.clear(); inStr = true; continue; }
            if (isalnum((unsigned char)c) || c == '_') { tok += c; continue; }
            if (!tok.empty()) { fn(tok); tok.clear(); }
        }
    };
    auto isTemp = [](const std::string& t) {
        return t.size() > 1 && t[0] == 'v' &&
               t.find_first_not_of("0123456789", 1) == std::string::npos;
    };

    // A temporary that appears only in its own binding was never read.
    {
        std::map<std::string, int> uses;
        for (auto& ln : allLines)
            scanIdents(ln, [&](const std::string& t) { if (isTemp(t)) ++uses[t]; });
        for (auto& ln : allLines) {
            size_t eq = ln.find(" = ");
            if (eq == std::string::npos) continue;
            std::string lhs = ln.substr(0, eq);
            size_t st = lhs.find_first_not_of(" \t");
            if (st == std::string::npos) continue;
            std::string pad = lhs.substr(0, st);
            lhs = lhs.substr(st);
            if (!isTemp(lhs)) continue;
            if (uses[lhs] == 1) ln = pad + ln.substr(eq + 3);
        }
    }

    // A goto whose target is the next line is a fall-through. These show up
    // once a folded constant branch makes the blocks in between unreachable.
    for (size_t i = 0; i + 1 < allLines.size(); ++i) {
        std::string g = allLines[i];
        while (!g.empty() && (g.front() == ' ' || g.front() == '\t')) g.erase(0, 1);
        if (g.rfind("goto ", 0) != 0 || g.empty() || g.back() != ';') continue;
        std::string lbl = g.substr(5, g.size() - 6);
        size_t j = i + 1;
        while (j < allLines.size() && allLines[j].find_first_not_of(" \t") == std::string::npos) ++j;
        if (j >= allLines.size()) continue;
        std::string nxt = allLines[j];
        while (!nxt.empty() && (nxt.front() == ' ' || nxt.front() == '\t')) nxt.erase(0, 1);
        if (nxt == lbl + ":") allLines[i].clear();
    }

    // Two returns in a row with no label between them: the second is dead.
    {
        bool prevRet = false;
        for (auto& ln : allLines) {
            std::string t = ln;
            while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.erase(0, 1);
            if (t.empty()) continue;
            if (prevRet && t.rfind("return", 0) == 0) { ln.clear(); continue; }
            prevRet = (t.rfind("return", 0) == 0);
        }
    }

    // Drop labels nothing jumps to, then blank runs left behind.
    {
        std::set<std::string> targets;
        for (auto& ln : allLines) {
            std::string t = ln;
            while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.erase(0, 1);
            size_t g = t.find("goto ");
            if (g != std::string::npos) {
                std::string lbl = t.substr(g + 5);
                size_t e = lbl.find(';');
                if (e != std::string::npos) targets.insert(lbl.substr(0, e));
            }
        }
        std::vector<std::string> kept;
        bool prevBlank = false;
        for (auto& ln : allLines) {
            std::string t = ln;
            while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.erase(0, 1);
            if (t.rfind("L_", 0) == 0 && t.size() > 2 && t.back() == ':' &&
                !targets.count(t.substr(0, t.size() - 1)))
                continue;
            // Nothing in the body is deliberately blank; the gaps are where
            // folded branches and stripped labels used to be.
            if (t.empty()) continue;
            (void)prevBlank;
            kept.push_back(ln);
        }
        allLines.swap(kept);
    }

    // Declarations come from the surviving body: a register can reach the
    // listing through a propagated expression or a branch condition without
    // ever being the target of an emitted assignment, and those names used to
    // appear undeclared.
    auto regWidth = [](const std::string& t) -> int {
        if (t == "fp" || t == "lr" || t == "sp") return 8;
        if (t.size() >= 2 && (t[0] == 'x' || t[0] == 'w') &&
            t.find_first_not_of("0123456789", 1) == std::string::npos) {
            int n = atoi(t.c_str() + 1);
            if (n >= 0 && n <= 30) return t[0] == 'w' ? 4 : 8;
        }
        static const char* r64[] = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                                    "r8","r9","r10","r11","r12","r13","r14","r15"};
        for (auto n : r64) if (t == n) return 8;
        static const char* r32[] = {"eax","ebx","ecx","edx","esi","edi","ebp","esp"};
        for (auto n : r32) if (t == n) return 4;
        return 0;
    };
    std::map<std::string, int> declRegs;
    std::set<std::string> usedCC;
    // numeric order, so v2 does not sort between v15 and v16
    auto byIndex = [](const std::string& a, const std::string& b) {
        int x = atoi(a.c_str() + 1), y = atoi(b.c_str() + 1);
        return x != y ? x < y : a < b;
    };
    std::set<std::string, decltype(byIndex)> declTemps(byIndex);
    for (auto& ln : allLines)
        scanIdents(ln, [&](const std::string& t) {
            int w = regWidth(t);
            if (w && !sigArgs.count(t)) declRegs[t] = w;
            else if (isTemp(t)) declTemps.insert(t);
            else if (t.rfind("CC_", 0) == 0 && unrecoveredCC.count(t)) usedCC.insert(t);
        });

    std::ostringstream decls;
    for (auto& t : declTemps) decls << "    u64 " << t << ";\n";
    if (!declRegs.empty()) {
        decls << "    // machine registers with no reconstructed definition in this function\n";
        for (auto& kv : declRegs)
            decls << "    " << typeOfWidth(kv.second) << " " << kv.first << ";\n";
    }
    if (!usedCC.empty()) {
        decls << "    // condition-code tests whose flag-setting instruction was not traced\n";
        for (auto& c : usedCC) decls << "    int " << c << ";\n";
    }
    if (decls.tellp() > 0) decls << "\n";

    std::ostringstream finalText;
    finalText << head.str() << decls.str();
    for (auto& ln : allLines) finalText << ln << "\n";
    finalText << "}\n";
    res.text = finalText.str();

    res.ok = true;
    for (auto& kv : blockStmts) res.nStmts += int(kv.second.size());
    return res;
}

} // namespace sako
