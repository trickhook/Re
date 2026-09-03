#include "Analysis.h"
#include <cstring>

#ifdef SAKO_HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

namespace sako {

bool Disasm::open(const std::string& arch) {
    close();
    arch_ = arch;

#ifdef SAKO_HAVE_CAPSTONE
    cs_arch a;
    cs_mode m;
    bool ok = false;
    if (arch == "ARM64")      { a = CS_ARCH_ARM64; m = CS_MODE_LITTLE_ENDIAN; ok = true; }
    else if (arch == "ARM")   { a = CS_ARCH_ARM;   m = cs_mode(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN); ok = true; }
    else if (arch == "X86_64"){ a = CS_ARCH_X86;   m = cs_mode(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN); ok = true; }
    else if (arch == "X86")   { a = CS_ARCH_X86;   m = cs_mode(CS_MODE_32 | CS_MODE_LITTLE_ENDIAN); ok = true; }
    csh h = 0;
    if (ok && cs_open(a, m, &h) == CS_ERR_OK) {
        csh_ = size_t(h);
        capstone_ = true;
        int maj = 0, mino = 0;
        cs_version(&maj, &mino);
        char buf[32];
        snprintf(buf, sizeof buf, "Capstone %u.%u", maj, mino);
        backend_ = buf;
        return true;
    }
#endif
    if (mini::supports(arch)) {
        backend_ = "Mini (built-in)";
        return true;
    }
    backend_.clear();
    return false;
}

void Disasm::close() {
#ifdef SAKO_HAVE_CAPSTONE
    if (capstone_ && csh_) {
        csh h = csh(csh_);
        cs_close(&h);
    }
#endif
    capstone_ = false;
    csh_ = 0;
    backend_.clear();
}

std::vector<AsmLine> Disasm::disassemble(const u8* code, size_t size, u64 vaddr, size_t maxInstr) {
    std::vector<AsmLine> out;
    if (!ready() || !code || !size) return out;

#ifdef SAKO_HAVE_CAPSTONE
    if (capstone_) {
        csh h = csh(csh_);
        size_t step = (arch_ == "ARM64" || arch_ == "ARM") ? 4 : 1;
        size_t pos = 0;
        int badRun = 0;
        out.reserve(std::min(maxInstr, size_t(1024)));
        while (pos < size && out.size() < maxInstr) {
            cs_insn* insn = nullptr;
            size_t cnt = cs_disasm(h, code + pos, size - pos, vaddr + pos, 64, &insn);
            if (cnt == 0) {
                // invalid byte: emit .byte and step over
                AsmLine l;
                l.addr = vaddr + pos;
                char bbuf[16];
                snprintf(bbuf, sizeof bbuf, "%02X", code[pos]);
                l.bytes = bbuf;
                l.mnem = ".byte";
                l.ops = bbuf;
                out.push_back(l);
                pos += step;
                if (++badRun >= 16) break;
                continue;
            }
            badRun = 0;
            for (size_t i = 0; i < cnt && out.size() < maxInstr; ++i) {
                AsmLine l;
                l.addr = insn[i].address;
                char bbuf[64];
                size_t nb = std::min<size_t>(size_t(insn[i].size), size_t(8));
                int o = 0;
                for (size_t k = 0; k < nb; ++k)
                    o += snprintf(bbuf + o, sizeof(bbuf) - size_t(o), "%02X ", insn[i].bytes[k]);
                if (insn[i].size > 8 && o + 3 < int(sizeof(bbuf)))
                    o += snprintf(bbuf + o, sizeof(bbuf) - size_t(o), "…");
                while (o > 0 && bbuf[o - 1] == ' ') --o; // trim trailing space
                l.bytes.assign(bbuf, size_t(o));
                l.mnem = insn[i].mnemonic;
                l.ops = insn[i].op_str;
                out.push_back(l);
                pos += size_t(insn[i].size);
            }
            cs_free(insn, cnt);
        }
        return out;
    }
#endif
    return mini::disassemble(arch_, code, size, vaddr, maxInstr);
}

} // namespace sako
