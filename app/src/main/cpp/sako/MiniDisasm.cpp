// MiniDisasm — lightweight built-in fallback disassembler.
// Covers a practical subset of ARM64 and x86-64 (common instructions).
// Not a replacement for Capstone — used only when Capstone is unavailable.
#include "Analysis.h"
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

namespace sako {
namespace mini {

bool supports(const std::string& arch) {
    return arch == "ARM64" || arch == "X86_64";
}

// ------------------------------------------------------------------ ARM64 ---
namespace arm64 {

static const char* X(int r) {
    static const char* t[32] = {"x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11",
        "x12","x13","x14","x15","x16","x17","x18","x19","x20","x21","x22","x23","x24","x25",
        "x26","x27","x28","x29","x30","sp"};
    return t[r & 31];
}
static const char* W(int r) {
    static const char* t[32] = {"w0","w1","w2","w3","w4","w5","w6","w7","w8","w9","w10","w11",
        "w12","w13","w14","w15","w16","w17","w18","w19","w20","w21","w22","w23","w24","w25",
        "w26","w27","w28","w29","w30","wsp"};
    return t[r & 31];
}
static const char* COND(int c) {
    static const char* t[16] = {"eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"};
    return t[c & 15];
}
static std::string hx(u64 v) { char b[24]; snprintf(b, sizeof b, "#0x%llX", (unsigned long long)v); return b; }

static bool decode(u32 w, u64 pc, AsmLine& l) {
    auto set = [&](const char* m, const std::string& o) { l.mnem = m; l.ops = o; return true; };

    if (w == 0xD503201F) return set("nop", "");
    if (w == 0xD503237F) return set("pacibsp", "");
    if (w == 0xD65F03C0) return set("ret", "");
    if (w == 0xD4000001) return set("svc", "#0");

    // B / BL
    if ((w & 0x7C000000) == 0x14000000) {
        i64 imm = sext(i64(w & 0x03FFFFFF), 26) * 4;
        return set((w & 0x04000000) ? "bl" : "b", hx(pc + imm));
    }
    // B.cond
    if ((w & 0xFF000010) == 0x54000000) {
        i64 imm = sext(i64((w >> 5) & 0x7FFFF), 19) * 4;
        char m[16]; snprintf(m, sizeof m, "b.%s", COND(int(w & 0xF)));
        return set(m, hx(pc + imm));
    }
    // CBZ / CBNZ
    if ((w & 0x7E000000) == 0x34000000) {
        bool sf = (w >> 31) & 1;
        bool nz = (w >> 24) & 1;
        int rt = int(w & 0x1F);
        i64 imm = sext(i64((w >> 5) & 0x7FFFF), 19) * 4;
        return set(nz ? "cbnz" : "cbz", std::string(sf ? X(rt) : W(rt)) + ", " + hx(pc + imm));
    }
    // TBZ / TBNZ
    if ((w & 0x7E000000) == 0x36000000) {
        bool nz = (w >> 24) & 1;
        int bit = int((((w >> 31) & 1) << 5) | ((w >> 19) & 0x1F));
        int rt = int(w & 0x1F);
        i64 imm = sext(i64((w >> 5) & 0x3FFF), 14) * 4;
        char b[8]; snprintf(b, sizeof b, "#%d", bit);
        return set(nz ? "tbnz" : "tbz", std::string(X(rt)) + ", " + b + ", " + hx(pc + imm));
    }
    // MOVZ / MOVN / MOVK  (sf opc 100101 hw imm16 Rd)
    {
        u32 pat = w & 0xFFE00000;
        if (pat == 0x52800000 || pat == 0xD2800000 ||   // movz
            pat == 0x12800000 || pat == 0x92800000 ||   // movn
            pat == 0x72800000 || pat == 0xF2800000) {   // movk
            bool sf = (w >> 31) & 1;
            u32 p2 = w & 0xFFE00000;
            const char* m = (p2 == 0x52800000 || p2 == 0xD2800000) ? "movz"
                          : (p2 == 0x12800000 || p2 == 0x92800000) ? "movn" : "movk";
            int hw = int((w >> 21) & 3);
            int imm16 = int((w >> 5) & 0xFFFF);
            int rd = int(w & 0x1F);
            std::string o = std::string(sf ? X(rd) : W(rd)) + ", " + hx(u64(imm16));
            if (hw) { char b[16]; snprintf(b, sizeof b, ", lsl #%d", hw * 16); o += b; }
            return set(m, o);
        }
    }
    // ADD/SUB (immediate)
    if ((w & 0x1F000000) == 0x11000000) {
        bool sf = (w >> 31) & 1;
        bool sub = (w >> 30) & 1;
        bool S = (w >> 29) & 1;
        u32 imm = (w >> 10) & 0xFFF;
        int rn = int((w >> 5) & 0x1F), rd = int(w & 0x1F);
        if (S && rd == 31) return set(sub ? "cmp" : "cmn", std::string(sf ? X(rn) : W(rn)) + ", " + hx(imm));
        const char* m = sub ? (S ? "subs" : "sub") : (S ? "adds" : "add");
        auto R = [&](int r) -> const char* { return sf ? X(r) : W(r); };
        return set(m, std::string(R(rd)) + ", " + R(rn) + ", " + hx(imm));
    }
    // ADD/SUB shifted register
    if ((w & 0x1F200000) == 0x0B000000) {
        bool sf = (w >> 31) & 1;
        bool sub = (w >> 30) & 1;
        bool S = (w >> 29) & 1;
        int rm = int((w >> 16) & 0x1F), rn = int((w >> 5) & 0x1F), rd = int(w & 0x1F);
        if (S && rd == 31) return set(sub ? "cmp" : "cmn", std::string(sf ? X(rm) : W(rm)));
        const char* m = sub ? (S ? "subs" : "sub") : (S ? "adds" : "add");
        auto R = [&](int r) -> const char* { return sf ? X(r) : W(r); };
        return set(m, std::string(R(rd)) + ", " + R(rn) + ", " + R(rm));
    }
    // MOV (register alias: ORR shifted register, Rn = xzr)
    if ((w & 0x7FE0FFE0) == 0x2A0003E0) {
        bool sf = (w >> 31) & 1;
        int rm = int((w >> 16) & 0x1F), rd = int(w & 0x1F);
        return set("mov", std::string(sf ? X(rd) : W(rd)) + ", " + (sf ? X(rm) : W(rm)));
    }
    // LDR/STR unsigned imm
    if ((w & 0x3B000000) == 0x39000000) {
        int size = int((w >> 30) & 3);
        bool load = (w >> 22) & 1;
        u32 imm = (w >> 10) & 0xFFF;
        int rn = int((w >> 5) & 0x1F), rt = int(w & 0x1F);
        const char* op0;
        if (size == 3) op0 = load ? "ldr" : "str";
        else if (size == 2) op0 = load ? "ldr" : "str";
        else if (size == 1) op0 = load ? "ldrh" : "strh";
        else op0 = load ? "ldrb" : "strb";
        char b[48];
        snprintf(b, sizeof b, "[%s, %s]", rn == 31 ? "sp" : X(rn),
                 hx(u64(imm) << size).c_str());
        std::string reg = size == 3 ? X(rt) : W(rt);
        return set(op0, reg + ", " + b);
    }
    // LDP/STP
    if ((w & 0x7C000000) == 0x28000000) {
        bool load = (w >> 22) & 1;
        bool sf = (w >> 31) & 1;
        i64 imm = sext(i64((w >> 15) & 0x7F), 7) * (sf ? 8 : 4);
        int rt = int(w & 0x1F), rn = int((w >> 5) & 0x1F), rt2 = int((w >> 10) & 0x1F);
        char b[72];
        snprintf(b, sizeof b, "%s, %s, [%s, %s]", sf ? X(rt) : W(rt), sf ? X(rt2) : W(rt2),
                 rn == 31 ? "sp" : X(rn), hx(u64(imm >= 0 ? u64(imm) : u64(-imm))).c_str());
        return set(load ? "ldp" : "stp", b);
    }
    // ADRP
    if ((w & 0x9F000000) == 0x90000000) {
        int rd = int(w & 0x1F);
        i64 immhi = i64((w >> 5) & 0x7FFFF);
        i64 immlo = i64((w >> 29) & 3);
        i64 imm = sext((immhi << 2) | immlo, 21) << 12;
        return set("adrp", std::string(X(rd)) + ", " + hx((pc & ~u64(0xFFF)) + u64(imm)));
    }
    // ADR
    if ((w & 0x9F000000) == 0x10000000) {
        int rd = int(w & 0x1F);
        i64 immhi = i64((w >> 5) & 0x7FFFF);
        i64 immlo = i64((w >> 29) & 3);
        i64 imm = sext((immhi << 2) | immlo, 21);
        return set("adr", std::string(X(rd)) + ", " + hx(pc + u64(imm)));
    }
    // BLR / BR / RET reg
    if ((w & 0xFFFFFC1F) == 0xD63F0000) return set("blr", X(int((w >> 5) & 0x1F)));
    if ((w & 0xFFFFFC1F) == 0xD61F0000) return set("br",  X(int((w >> 5) & 0x1F)));
    if ((w & 0xFFFFFC1F) == 0xD65F0000) return set("ret", X(int((w >> 5) & 0x1F)));
    // MUL
    if ((w & 0x7FE0FC00) == 0x1B007C00) {
        int rd = int(w & 0x1F), rn = int((w >> 5) & 0x1F), rm = int((w >> 16) & 0x1F);
        return set("mul", std::string(X(rd)) + ", " + X(rn) + ", " + X(rm));
    }
    // SVC
    if ((w & 0xFFE0001F) == 0xD4000001) return set("svc", hx((w >> 5) & 0xFFFF));

    char b[48];
    snprintf(b, sizeof b, "0x%08X", w);
    return set(".word", b);
}

} // namespace arm64

// ----------------------------------------------------------------- x86-64 ---
namespace x86 {

static const char* R64(int r) {
    static const char* t[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
    return t[r & 15];
}
static const char* R32(int r) {
    static const char* t[8] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
    return t[r & 7];
}
static const char* R8(int r) {
    static const char* t[8] = {"al","cl","dl","bl","spl","bpl","sil","dil"};
    return t[r & 7];
}
static const char* CC(int c) {
    static const char* t[16] = {"o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"};
    return t[c & 15];
}
static std::string hx(u64 v) { char b[24]; snprintf(b, sizeof b, "0x%llX", (unsigned long long)v); return b; }

struct Modrm {
    int mod = 0, reg = 0, rm = 0;
    bool mem = false, rip = false;
    std::string text;
};

// decode modrm at p; rexByte = 0 if none; returns bytes consumed (0 = fail)
static int modrm(const u8* p, size_t n, int rexByte, int opsz, Modrm& m) {
    if (!n) return 0;
    int b = p[0];
    m.mod = (b >> 6) & 3;
    m.reg = (b >> 3) & 7;
    m.rm  = b & 7;
    bool rxr = (rexByte & 4) != 0;  // REX.R
    bool rxb = (rexByte & 1) != 0;  // REX.B

    if (m.mod == 3) {
        m.mem = false;
        int r = m.rm + (rxb ? 8 : 0);
        m.text = opsz == 8 ? R64(r) : opsz == 1 ? R8(m.rm) : R32(m.rm);
        return 1;
    }
    m.mem = true;
    std::string base, idx;
    int scale = 0;
    int dispBytes = m.mod == 1 ? 1 : (m.mod == 2 ? 4 : 0);
    size_t extra = 0;
    i64 disp = 0;

    if (m.mod == 0 && m.rm == 5) {
        m.rip = true;
        dispBytes = 4;
    } else if (m.rm == 4) { // SIB byte follows
        if (n < 2) return 0;
        int sib = p[1]; extra = 1;
        int sBase = sib & 7, sIdx = (sib >> 3) & 7;
        scale = 1 << ((sib >> 6) & 3);
        bool sbb = (rexByte & 1) != 0;
        if (sBase == 5 && m.mod == 0) dispBytes = 4;
        else base = R64(sBase + (sbb ? 8 : 0));
        bool sbx = (rexByte & 2) != 0;
        if (sIdx != 4) idx = R64(sIdx + (sbx ? 8 : 0));
    } else {
        base = R64(m.rm + (rxb ? 8 : 0));
    }

    if (dispBytes) {
        if (extra + size_t(dispBytes) + 1 > n) return 0;
        if (dispBytes == 1) disp = i64(int8_t(p[extra]));
        else disp = i64(int32_t(rd32(p + extra)));
    }

    std::string s = "[";
    if (m.rip) s = "[rip";
    else if (!base.empty()) s += base;
    if (!idx.empty()) {
        if (!m.rip && !base.empty()) s += "+";
        s += idx;
        if (scale > 1) { char b[8]; snprintf(b, sizeof b, "*%d", scale); s += b; }
    }
    if (dispBytes) {
        if (m.rip) { s += (disp < 0 ? "-" : "+"); if (disp < 0) disp = -disp; s += hx(u64(disp)); }
        else if (disp < 0) { s += "-"; s += hx(u64(-disp)); }
        else if (!base.empty() || !idx.empty()) { s += "+"; s += hx(u64(disp)); }
        else s += hx(u64(disp));
    }
    s += "]";
    m.text = s;
    return int(1 + extra + size_t(dispBytes));
}

// returns bytes consumed (0 = unknown)
static size_t decodeOne(const u8* p, size_t n, u64 pc, AsmLine& l) {
    size_t pos = 0;
    auto set = [&](const char* m, const std::string& o, size_t len) { l.mnem = m; l.ops = o; return len; };

    // prefixes
    bool opsz16 = false;
    int rexByte = 0;
    while (pos < n) {
        u8 c = p[pos];
        if (c == 0x66) { opsz16 = true; ++pos; }
        else if (c == 0xF3 || c == 0xF2 || c == 0xF0) ++pos;
        else if (c == 0x2E || c == 0x3E || c == 0x26 || c == 0x36 || c == 0x64 || c == 0x65) ++pos;
        else if (c >= 0x40 && c <= 0x4F) { rexByte = c; ++pos; }
        else break;
    }
    if (pos >= n) return 0;
    u8 op = p[pos++];
    bool rexW = (rexByte & 8) != 0;
    int osz = rexW ? 8 : (opsz16 ? 2 : 4);

    // endbr64
    if (op == 0x0F && pos + 1 < n && p[pos] == 0x1E && p[pos + 1] == 0xFA)
        return set("endbr64", "", pos + 2);

    // two-byte opcodes (subset)
    if (op == 0x0F) {
        if (pos >= n) return 0;
        u8 op2 = p[pos++];
        if (op2 >= 0x80 && op2 <= 0x8F) { // jcc rel32
            if (pos + 4 > n) return 0;
            i32 rel = i32(rd32(p + pos));
            char m[8]; snprintf(m, sizeof m, "j%s", CC(op2 & 15));
            return set(m, hx(pc + pos + 4 + rel), pos + 4);
        }
        if (op2 == 0x05) return set("syscall", "", pos);
        if (op2 == 0x0B) return set("ud2", "", pos);
        if (op2 == 0x1E) return set("endbr64?", "", pos);
        if ((op2 & 0xFE) == 0xBE || (op2 & 0xFE) == 0xB6) { // movsx/movzx
            Modrm m2; int c = modrm(p + pos, n - pos, rexByte, osz == 8 ? 4 : osz, m2);
            if (!c) return 0;
            std::string dst = osz == 8 ? R64(m2.reg + ((rexByte & 4) ? 8 : 0)) : R32(m2.reg);
            return set((op2 & 1) ? "movsx" : "movzx", dst + ", " + m2.text, pos + size_t(c));
        }
        if (op2 == 0x10 || op2 == 0x11) { // SSE movups etc.
            Modrm m2; int c = modrm(p + pos, n - pos, rexByte, 4, m2);
            if (!c) return 0;
            return set("movups", (op2 == 0x11 ? m2.text + ", xmm" : "xmm, " + m2.text), pos + size_t(c));
        }
        return 0;
    }

    // one-byte simple
    if (op == 0x55) return set("push", "rbp", pos);
    if (op == 0x5D) return set("pop", "rbp", pos);
    if (op >= 0x50 && op <= 0x57) return set("push", R64(op - 0x50), pos);
    if (op >= 0x58 && op <= 0x5F) return set("pop", R64(op - 0x58), pos);
    if (op == 0xC3) return set("ret", "", pos);
    if (op == 0xC9) return set("leave", "", pos);
    if (op == 0x90) return set("nop", "", pos);
    if (op == 0xCC) return set("int3", "", pos);
    if (op == 0xFC) return set("cld", "", pos);
    if (op == 0x6A) { if (pos >= n) return 0; return set("push", hx(u64(int8_t(p[pos]))), pos + 1); }
    if (op == 0x68) { if (pos + 4 > n) return 0; return set("push", hx(rd32(p + pos)), pos + 4); }
    if (op == 0xE8 || op == 0xE9) {
        if (pos + 4 > n) return 0;
        i32 rel = i32(rd32(p + pos));
        return set(op == 0xE8 ? "call" : "jmp", hx(pc + pos + 4 + rel), pos + 4);
    }
    if (op == 0xEB) {
        if (pos >= n) return 0;
        i32 rel = i32(int8_t(p[pos]));
        return set("jmp", hx(pc + pos + 1 + rel), pos + 1);
    }
    if (op >= 0x70 && op <= 0x7F) {
        if (pos >= n) return 0;
        i32 rel = i32(int8_t(p[pos]));
        char m[8]; snprintf(m, sizeof m, "j%s", CC(op & 15));
        return set(m, hx(pc + pos + 1 + rel), pos + 1);
    }

    // mov reg, imm
    if ((op & 0xF8) == 0xB8) {
        int r = op & 7;
        if (rexW) { if (pos + 8 > n) return 0; return set("mov", std::string(R64(r + ((rexByte & 1) ? 8 : 0))) + ", " + hx(rd64(p + pos)), pos + 8); }
        if (pos + 4 > n) return 0;
        return set("mov", std::string(R32(r)) + ", " + hx(rd32(p + pos)), pos + 4);
    }

    // imm8 accumulator ops
    if ((op & 0xFE) == 0x04) {
        static const char* al[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
        if (pos >= n) return 0;
        return set(al[(op >> 3) & 7], std::string("al, ") + hx(p[pos]), pos + 1);
    }

    static const char* arith[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
    int ar = (op >> 3) & 7;
    int lo = op & 7;

    // 00..3F arithmetic r/m,r and r,r/m
    if (ar < 8 && (lo == 0 || lo == 1 || lo == 2 || lo == 3)) {
        bool is64 = (lo == 1 || lo == 3) && rexW;
        int sz = (lo == 0 || lo == 2) ? 1 : (rexW ? 8 : 4);
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, sz, m2);
        if (!c) return 0;
        int ridx = m2.reg + ((rexByte & 4) ? 8 : 0);
        std::string rr = sz == 1 ? R8(m2.reg) : (is64 ? R64(ridx) : R32(m2.reg));
        if (lo == 0 || lo == 1) // op r/m, r
            return set(arith[ar], m2.text + ", " + rr, pos + size_t(c));
        return set(arith[ar], rr + ", " + m2.text, pos + size_t(c)); // op r, r/m
    }

    if (ar < 8 && lo == 4) { // eax, imm32
        if (pos + 4 > n) return 0;
        return set(arith[ar], std::string("eax, ") + hx(rd32(p + pos)), pos + 4);
    }
    if (ar < 8 && lo == 5 && rexW) {
        if (pos + 4 > n) return 0;
        return set(arith[ar], std::string("rax, ") + hx(u64(i64(i32(rd32(p + pos))))), pos + 4);
    }

    // mov r/m,r and r,r/m
    if (op == 0x89 || op == 0x8B) {
        int sz = rexW ? 8 : (opsz16 ? 2 : 4);
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, sz, m2);
        if (!c) return 0;
        int ridx = m2.reg + ((rexByte & 4) ? 8 : 0);
        std::string rr = sz == 8 ? R64(ridx) : R32(m2.reg);
        if (op == 0x89) return set("mov", m2.text + ", " + rr, pos + size_t(c));
        return set("mov", rr + ", " + m2.text, pos + size_t(c));
    }
    if (op == 0x88) {
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, 1, m2);
        if (!c) return 0;
        return set("mov", m2.text + ", " + R8(m2.reg), pos + size_t(c));
    }
    if (op == 0x8A) {
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, 1, m2);
        if (!c) return 0;
        return set("mov", std::string(R8(m2.reg)) + ", " + m2.text, pos + size_t(c));
    }

    // lea
    if (op == 0x8D) {
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, rexW ? 8 : 4, m2);
        if (!c) return 0;
        std::string dst = rexW ? R64(m2.reg + ((rexByte & 4) ? 8 : 0)) : R32(m2.reg);
        return set("lea", dst + ", " + m2.text, pos + size_t(c));
    }

    // test r/m, r
    if (op == 0x85) {
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, rexW ? 8 : 4, m2);
        if (!c) return 0;
        int ridx = m2.reg + ((rexByte & 4) ? 8 : 0);
        std::string rr = rexW ? R64(ridx) : R32(m2.reg);
        return set("test", m2.mem ? (m2.text + ", " + rr) : (m2.text + ", " + rr), pos + size_t(c));
    }

    // xchg
    if (op == 0x87) {
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, rexW ? 8 : 4, m2);
        if (!c) return 0;
        int ridx = m2.reg + ((rexByte & 4) ? 8 : 0);
        std::string rr = rexW ? R64(ridx) : R32(m2.reg);
        return set("xchg", m2.text + ", " + rr, pos + size_t(c));
    }

    // 0x81 / 0x83 group imm
    if (op == 0x81 || op == 0x83) {
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, rexW ? 8 : 4, m2);
        if (!c) return 0;
        size_t immLen = op == 0x81 ? 4 : 1;
        if (pos + size_t(c) - 1 + immLen > n) return 0;
        const u8* ip = p + pos + size_t(c) - 1;
        std::string immv = (op == 0x81) ? hx(rexW ? u64(i64(i32(rd32(ip)))) : rd32(ip))
                                        : hx(u64(i64(int8_t(ip[0]))));
        std::string dst = m2.mem ? m2.text : (rexW ? R64(m2.rm + ((rexByte & 1) ? 8 : 0)) : R32(m2.rm));
        return set(arith[m2.reg & 7], dst + ", " + immv, pos + size_t(c) - 1 + immLen);
    }

    // mov r/m, imm32 (C7)
    if (op == 0xC7) {
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, rexW ? 8 : 4, m2);
        if (!c || m2.reg != 0) return c ? 0 : 0;
        if (pos + size_t(c) - 1 + 4 > n) return 0;
        const u8* ip = p + pos + size_t(c) - 1;
        std::string dst = m2.mem ? m2.text : (rexW ? R64(m2.rm + ((rexByte & 1) ? 8 : 0)) : R32(m2.rm));
        return set("mov", dst + ", " + hx(rexW ? u64(i64(i32(rd32(ip)))) : rd32(ip)),
                   pos + size_t(c) - 1 + 4);
    }

    // movsxd
    if (op == 0x63 && rexW) {
        Modrm m2; int c = modrm(p + pos, n - pos, rexByte, 4, m2);
        if (!c) return 0;
        return set("movsxd", std::string(R64(m2.reg + ((rexByte & 4) ? 8 : 0))) + ", " + m2.text,
                   pos + size_t(c));
    }

    return 0;
}

static std::vector<AsmLine> run(const u8* code, size_t size, u64 vaddr, size_t maxInstr) {
    std::vector<AsmLine> out;
    size_t pos = 0;
    int badRun = 0;
    while (pos < size && out.size() < maxInstr) {
        AsmLine l;
        l.addr = vaddr + pos;
        size_t len = decodeOne(code + pos, size - pos, vaddr + pos, l);
        if (len == 0) {
            char b[40];
            snprintf(b, sizeof b, "%02X", code[pos]);
            l.bytes = b;
            l.mnem = ".byte";
            l.ops = b;
            len = 1;
            if (++badRun >= 16) break;
        } else {
            badRun = 0;
            char bbuf[40];
            size_t nb = std::min<size_t>(len, size_t(8));
            int o = 0;
            for (size_t k = 0; k < nb; ++k)
                o += snprintf(bbuf + o, sizeof(bbuf) - size_t(o), "%02X", code[pos + k]);
            l.bytes.assign(bbuf, size_t(o));
        }
        out.push_back(l);
        pos += len;
    }
    return out;
}

} // namespace x86

std::vector<AsmLine> disassemble(const std::string& arch, const u8* code, size_t size, u64 vaddr, size_t maxInstr) {
    if (arch == "ARM64") {
        std::vector<AsmLine> out;
        size_t count = std::min(maxInstr, size / 4);
        out.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            AsmLine l;
            l.addr = vaddr + i * 4;
            u32 w = rd32(code + i * 4);
            char bb[16];
            snprintf(bb, sizeof bb, "%02X%02X%02X%02X", code[i*4+3], code[i*4+2], code[i*4+1], code[i*4]);
            l.bytes = bb;
            arm64::decode(w, l.addr, l);
            out.push_back(l);
        }
        return out;
    }
    if (arch == "X86_64") return x86::run(code, size, vaddr, maxInstr);
    return {};
}

} // namespace mini
} // namespace sako
