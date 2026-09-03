// IR decompiler — expression trees lifted from assembly, with intra-block
// expression propagation, dead-store elimination, loop reconstruction
// (while from back-edges), if/else diamonds and typed declarations.
//
// Pipeline:  ASM lines -> [lift] -> IR statements -> [propagate/cleanup]
//            -> structured Pseudo-C text
#pragma once
#include "Types.h"
#include "Loaders.h"
#include "DeepAnalysis.h"
#include <memory>
#include <set>
#include <functional>

namespace sako {

// ---------------- Disassembler (Capstone primary, Mini fallback) ----------------
class Disasm {
public:
    Disasm() = default;
    ~Disasm() { close(); }
    Disasm(const Disasm&) = delete;
    Disasm& operator=(const Disasm&) = delete;

    // arch: "ARM64" | "ARM" | "X86_64" | "X86"
    bool open(const std::string& arch);
    void close();
    bool ready() const { return !backend_.empty(); }
    const std::string& backend() const { return backend_; }

    Disasm(Disasm&& o) noexcept { moveFrom(o); }
    Disasm& operator=(Disasm&& o) noexcept {
        if (this != &o) { close(); moveFrom(o); }
        return *this;
    }

    std::vector<AsmLine> disassemble(const u8* code, size_t size, u64 vaddr, size_t maxInstr = 4096);

private:
    void moveFrom(Disasm& o) {
        capstone_ = o.capstone_; o.capstone_ = false;
        csh_ = o.csh_; o.csh_ = 0;
        arch_ = std::move(o.arch_);
        backend_ = std::move(o.backend_);
    }

    bool capstone_ = false;
    size_t csh_ = 0;              // csh handle
    std::string arch_, backend_;
};

struct IrExpr {
    enum Kind { IMM, REG, MEM, BIN, UN, CALL, COND, STRREF } kind;
    u64 imm = 0;
    std::string reg;        // REG: register name as variable
    std::string name;       // CALL target / STRREF string value
    std::string binop;      // BIN operator
    int size = 8;           // width in bytes (REG/MEM loads)
    bool isArg = false;     // REG that is a function parameter (a0..a7)
    bool isBool = false;    // COND used as int
    std::string cmpOp;      // COND operator: == != < <= > >=
    std::shared_ptr<IrExpr> a, b;
    std::vector<std::shared_ptr<IrExpr>> args;

    static std::shared_ptr<IrExpr> make(IrExpr::Kind k) {
        auto e = std::make_shared<IrExpr>();
        e->kind = k;
        return e;
    }
    static std::shared_ptr<IrExpr> makeImm(u64 v, int sz = 8) {
        auto e = make(IMM); e->imm = v; e->size = sz; return e;
    }
    static std::shared_ptr<IrExpr> makeReg(const std::string& r, int sz = 8, bool arg = false) {
        auto e = make(REG); e->reg = r; e->size = sz; e->isArg = arg; return e;
    }
    static std::shared_ptr<IrExpr> makeMem(std::shared_ptr<IrExpr> base, i64 off, int sz) {
        auto e = make(MEM); e->a = std::move(base); e->imm = u64(off); e->size = sz; return e;
    }
    static std::shared_ptr<IrExpr> makeBin(const std::string& op,
                                           std::shared_ptr<IrExpr> l,
                                           std::shared_ptr<IrExpr> r) {
        auto e = make(BIN); e->binop = op; e->a = std::move(l); e->b = std::move(r); return e;
    }
    static std::shared_ptr<IrExpr> makeCond(const std::string& op,
                                            std::shared_ptr<IrExpr> l,
                                            std::shared_ptr<IrExpr> r) {
        auto e = make(COND); e->cmpOp = op; e->a = std::move(l); e->b = std::move(r);
        e->size = 4; return e;
    }
    static std::shared_ptr<IrExpr> makeCall(const std::string& fn) {
        auto e = make(CALL); e->name = fn; e->size = 8; return e;
    }

    std::shared_ptr<IrExpr> clone() const;
    std::string render() const;          // C syntax
    int complexity() const;              // node count
    bool containsReg(const std::string& r) const;
    void collectRegs(std::set<std::string>& out) const;
};

struct IrStmt {
    enum Kind { ASSIGN, CALL, IF, WHILE, LABEL, GOTO, RETURN, COMMENT, DECL } kind;
    std::shared_ptr<IrExpr> lhs;    // ASSIGN
    std::shared_ptr<IrExpr> rhs;    // ASSIGN
    std::string cond;               // IF/WHILE condition (C text)
    std::string label;              // LABEL/GOTO target
    std::string text;               // COMMENT / DECL
    std::vector<IrStmt> body;       // IF/WHILE then-body
    std::vector<IrStmt> body2;      // IF else-body
    u64 addr = 0;                   // originating instruction address

    static IrStmt makeAssign(std::shared_ptr<IrExpr> l, std::shared_ptr<IrExpr> r, u64 at) {
        IrStmt s; s.kind = ASSIGN; s.lhs = std::move(l); s.rhs = std::move(r); s.addr = at; return s;
    }
};

struct IrResult {
    bool ok = false;
    std::string text;               // final pseudo-C
    int nStmts = 0, nWhile = 0, nIf = 0, nGoto = 0, nCalls = 0;
};

// Build CFG-independent IR from one function's linear disassembly.
IrResult decompileIR(const std::vector<AsmLine>& lines, const std::string& arch,
                     u64 funcStart, const std::string& funcName,
                     const AddrNames& names,
                     const std::vector<FoundString>& strings = {});

// ---------------- CFG + legacy heuristic pseudo (fallback) ----------------
std::vector<CfgBlock> buildCfg(const std::vector<AsmLine>& lines, u64 funcStart, u64 funcEnd,
                               const std::string& arch);

// Heuristic ASM -> pseudo-C (register-flavored C with gotos) — fallback path.
std::string genPseudo(const std::vector<AsmLine>& lines, const std::string& arch,
                      u64 funcStart, const std::string& funcName,
                      const std::map<u64, std::string>& labels);

namespace mini {
bool supports(const std::string& arch);
std::vector<AsmLine> disassemble(const std::string& arch, const u8* code, size_t size, u64 vaddr, size_t maxInstr);
}

// ---------------- Functions & XREFs ----------------
std::vector<FuncInfo> discoverFunctionsElf(const Binary& b, const ElfInfo& e);
std::vector<FuncInfo> discoverFunctionsPe(const Binary& b, const PeInfo& e);

std::map<u64, std::vector<Xref>> buildXrefs(const std::string& arch, const u8* code, size_t size,
                                            u64 va, size_t cap = 200000);

} // namespace sako
