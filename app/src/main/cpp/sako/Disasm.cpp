#include "Analysis.h"
#include <cstring>
#include <algorithm>

#ifdef SAKO_HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

namespace sako {

#ifdef SAKO_HAVE_CAPSTONE
namespace {

struct ArchSpec {
    cs_arch arch;
    unsigned mode;
    size_t   step;      // resync stride: the instruction alignment of the ISA
};

// Every decoder Capstone 4.0.2 ships, keyed by the arch ids the loaders emit.
// `step` is how far to advance after an undecodable byte so the stream
// re-synchronises on a real instruction boundary instead of drifting.
bool specFor(const std::string& a, ArchSpec& out) {
    const unsigned LE = CS_MODE_LITTLE_ENDIAN, BE = CS_MODE_BIG_ENDIAN;
    if (a == "ARM64")      { out = {CS_ARCH_ARM64, LE, 4}; return true; }
    if (a == "ARM64BE")    { out = {CS_ARCH_ARM64, BE, 4}; return true; }
    if (a == "ARM")        { out = {CS_ARCH_ARM,   CS_MODE_ARM   | LE, 4}; return true; }
    if (a == "ARMBE")      { out = {CS_ARCH_ARM,   CS_MODE_ARM   | BE, 4}; return true; }
    if (a == "THUMB")      { out = {CS_ARCH_ARM,   CS_MODE_THUMB | LE, 2}; return true; }
    if (a == "THUMBBE")    { out = {CS_ARCH_ARM,   CS_MODE_THUMB | BE, 2}; return true; }
    if (a == "X86_64")     { out = {CS_ARCH_X86,   CS_MODE_64 | LE, 1}; return true; }
    if (a == "X86")        { out = {CS_ARCH_X86,   CS_MODE_32 | LE, 1}; return true; }
    if (a == "X86_16")     { out = {CS_ARCH_X86,   CS_MODE_16 | LE, 1}; return true; }
    if (a == "MIPS32")     { out = {CS_ARCH_MIPS,  CS_MODE_MIPS32 | LE, 4}; return true; }
    if (a == "MIPS32BE")   { out = {CS_ARCH_MIPS,  CS_MODE_MIPS32 | BE, 4}; return true; }
    if (a == "MIPS64")     { out = {CS_ARCH_MIPS,  CS_MODE_MIPS64 | LE, 4}; return true; }
    if (a == "MIPS64BE")   { out = {CS_ARCH_MIPS,  CS_MODE_MIPS64 | BE, 4}; return true; }
    if (a == "PPC32")      { out = {CS_ARCH_PPC,   CS_MODE_32 | LE, 4}; return true; }
    if (a == "PPC32BE")    { out = {CS_ARCH_PPC,   CS_MODE_32 | BE, 4}; return true; }
    if (a == "PPC64")      { out = {CS_ARCH_PPC,   CS_MODE_64 | LE, 4}; return true; }
    if (a == "PPC64BE")    { out = {CS_ARCH_PPC,   CS_MODE_64 | BE, 4}; return true; }
    // SPARC, SystemZ, m68k, XCore and TI C6000 are big-endian architectures.
    if (a == "SPARC")      { out = {CS_ARCH_SPARC, BE, 4}; return true; }
    if (a == "SPARCV9")    { out = {CS_ARCH_SPARC, unsigned(BE | CS_MODE_V9), 4}; return true; }
    if (a == "SYSZ")       { out = {CS_ARCH_SYSZ,  BE, 2}; return true; }
    if (a == "M68K")       { out = {CS_ARCH_M68K,  BE, 2}; return true; }
    if (a == "XCORE")      { out = {CS_ARCH_XCORE, BE, 2}; return true; }
    if (a == "TMS320C64X") { out = {CS_ARCH_TMS320C64X, BE, 4}; return true; }
    if (a == "M680X")      { out = {CS_ARCH_M680X, CS_MODE_M680X_6809, 1}; return true; }
    if (a == "EVM")        { out = {CS_ARCH_EVM,   0, 1}; return true; }
    return false;
}

} // namespace
#endif

bool Disasm::open(const std::string& arch) {
    close();
    arch_ = arch;

#ifdef SAKO_HAVE_CAPSTONE
    ArchSpec spec{};
    if (specFor(arch, spec)) {
        csh h = 0;
        if (cs_open(spec.arch, cs_mode(spec.mode), &h) == CS_ERR_OK) {
            csh_ = size_t(h);
            step_ = spec.step;
            capstone_ = true;

            // ARM32 interworks between ARM and Thumb inside a single object, so
            // hold a second handle and switch per region rather than guessing
            // one mode for the whole binary.
            if (arch == "ARM" || arch == "ARMBE") {
                ArchSpec t{};
                if (specFor(arch == "ARM" ? "THUMB" : "THUMBBE", t)) {
                    csh th = 0;
                    if (cs_open(t.arch, cs_mode(t.mode), &th) == CS_ERR_OK)
                        cshAlt_ = size_t(th);
                }
            }

            int maj = 0, mino = 0;
            cs_version(&maj, &mino);
            char buf[64];
            snprintf(buf, sizeof buf, "Capstone %u.%u (%s%s)", maj, mino, arch.c_str(),
                     cshAlt_ ? ", ARM/Thumb" : "");
            backend_ = buf;
            return true;
        }
    }
#endif
    if (mini::supports(arch)) {
        backend_ = "Mini (built-in)";
        step_ = (arch == "ARM64") ? 4 : 1;
        return true;
    }
    backend_.clear();
    return false;
}

void Disasm::close() {
#ifdef SAKO_HAVE_CAPSTONE
    if (capstone_) {
        if (csh_)    { csh h = csh(csh_);    cs_close(&h); }
        if (cshAlt_) { csh h = csh(cshAlt_); cs_close(&h); }
    }
#endif
    capstone_ = false;
    csh_ = 0;
    cshAlt_ = 0;
    step_ = 1;
    defaultThumb_ = false;
    armMap_.clear();
    backend_.clear();
}

char Disasm::modeAt(u64 va) const {
    if (armMap_.empty()) return defaultThumb_ ? 't' : 'a';
    auto it = std::upper_bound(armMap_.begin(), armMap_.end(), va,
                               [](u64 v, const std::pair<u64, char>& e) { return v < e.first; });
    if (it == armMap_.begin()) return defaultThumb_ ? 't' : 'a';
    return (--it)->second;
}

u64 Disasm::nextBoundary(u64 va) const {
    auto it = std::upper_bound(armMap_.begin(), armMap_.end(), va,
                               [](u64 v, const std::pair<u64, char>& e) { return v < e.first; });
    return it == armMap_.end() ? ~u64(0) : it->first;
}

#ifdef SAKO_HAVE_CAPSTONE
namespace {

void pushInsn(std::vector<AsmLine>& out, const cs_insn& in) {
    AsmLine l;
    l.addr = in.address;
    char bbuf[64];
    size_t nb = std::min<size_t>(size_t(in.size), size_t(8));
    int o = 0;
    for (size_t k = 0; k < nb; ++k)
        o += snprintf(bbuf + o, sizeof(bbuf) - size_t(o), "%02X ", in.bytes[k]);
    if (in.size > 8 && o + 3 < int(sizeof(bbuf)))
        o += snprintf(bbuf + o, sizeof(bbuf) - size_t(o), "…");
    while (o > 0 && bbuf[o - 1] == ' ') --o;
    l.bytes.assign(bbuf, size_t(o));
    l.mnem = in.mnemonic;
    l.ops = in.op_str;
    out.push_back(l);
}

void pushRaw(std::vector<AsmLine>& out, const u8* code, size_t pos, u64 va, size_t width) {
    AsmLine l;
    l.addr = va;
    char bbuf[32], obuf[32];
    if (width == 4) {
        snprintf(bbuf, sizeof bbuf, "%02X %02X %02X %02X",
                 code[pos], code[pos + 1], code[pos + 2], code[pos + 3]);
        snprintf(obuf, sizeof obuf, "0x%08X",
                 unsigned(code[pos] | (code[pos + 1] << 8) | (code[pos + 2] << 16) |
                          (u32(code[pos + 3]) << 24)));
        l.mnem = ".word";
    } else {
        snprintf(bbuf, sizeof bbuf, "%02X", code[pos]);
        snprintf(obuf, sizeof obuf, "0x%02X", code[pos]);
        l.mnem = ".byte";
    }
    l.bytes = bbuf;
    l.ops = obuf;
    out.push_back(l);
}

// Decode [pos, end) with one handle, appending to out. Returns the new pos.
size_t runRange(csh h, std::vector<AsmLine>& out, const u8* code, size_t pos, size_t end,
                u64 vaddr, size_t maxInstr, size_t step) {
    int badRun = 0;
    while (pos < end && out.size() < maxInstr) {
        cs_insn* insn = nullptr;
        size_t cnt = cs_disasm(h, code + pos, end - pos, vaddr + pos, 64, &insn);
        if (cnt == 0) {
            pushRaw(out, code, pos, vaddr + pos, 1);
            pos += step;
            if (++badRun >= 16) break;
            continue;
        }
        badRun = 0;
        for (size_t i = 0; i < cnt && out.size() < maxInstr; ++i) {
            pushInsn(out, insn[i]);
            pos += size_t(insn[i].size);
        }
        cs_free(insn, cnt);
    }
    return pos;
}

} // namespace
#endif

std::vector<AsmLine> Disasm::disassemble(const u8* code, size_t size, u64 vaddr, size_t maxInstr,
                                         bool* gaveUp) {
    std::vector<AsmLine> out;
    if (gaveUp) *gaveUp = false;
    if (!ready() || !code || !size) return out;

#ifdef SAKO_HAVE_CAPSTONE
    if (capstone_) {
        out.reserve(std::min(maxInstr, size_t(1024)));

        // ARM32 with a Thumb handle: walk the mapping-symbol regions, decoding
        // each in its own mode and emitting literal pools as data.
        if (cshAlt_) {
            size_t pos = 0;
            while (pos < size && out.size() < maxInstr) {
                u64 va = vaddr + pos;
                char m = modeAt(va);
                u64 bound = nextBoundary(va);
                size_t end = size;
                if (bound != ~u64(0) && bound > va) {
                    u64 span = bound - va;
                    if (span < u64(size - pos)) end = pos + size_t(span);
                }
                if (end <= pos) break;

                if (m == 'd') {
                    // Literal pool — 4-byte words, or trailing bytes.
                    while (pos < end && out.size() < maxInstr) {
                        size_t width = (end - pos >= 4) ? 4 : 1;
                        pushRaw(out, code, pos, vaddr + pos, width);
                        pos += width;
                    }
                    continue;
                }
                csh h = csh(m == 't' ? cshAlt_ : csh_);
                size_t adv = runRange(h, out, code, pos, end, vaddr, maxInstr,
                                      m == 't' ? 2 : 4);
                if (adv <= pos) break;   // no progress: stop rather than spin
                pos = adv;
            }
            // Short of the end with budget to spare means a run gave up, or a
            // region made no progress at all.
            if (gaveUp && pos < size && out.size() < maxInstr) *gaveUp = true;
            return out;
        }

        size_t got = runRange(csh(csh_), out, code, 0, size, vaddr, maxInstr, step_);
        if (gaveUp && got < size && out.size() < maxInstr) *gaveUp = true;
        return out;
    }
#endif
    auto lines = mini::disassemble(arch_, code, size, vaddr, maxInstr);
    // The fallback decoder walks a fixed stride and never bails mid-range, so
    // the only way it comes up short is an architecture it does not cover --
    // and an empty listing for a non-empty range is exactly the thing this flag
    // exists to say out loud.
    if (gaveUp && lines.empty()) *gaveUp = true;
    return lines;
}

} // namespace sako
