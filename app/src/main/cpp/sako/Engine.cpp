#include "Engine.h"
#include "Binary.h"
#include "DebugSession.h"
#include "Script.h"
#include "Demangle.h"
#include <chrono>
#include <cstring>
#include <sstream>

namespace sako {

Engine& Engine::instance() {
    static Engine e;
    return e;
}

// ---------------------------------------------------------------- helpers --
static std::string q(const std::string& s) { return "\"" + jsonEscape(s) + "\""; }
static std::string hq(u64 v) { return q(hexAddr(v)); }
static std::string num(u64 v) {
    std::ostringstream os; os << v; return os.str();
}

u64 Engine::vaToOff(const Ctx& c, u64 va) {
    switch (c.fmt) {
        case Fmt::ELF: return elfVaToOff(c.elf, va);
        case Fmt::PE:  return peVaToOff(c.pe, va);
        default:       return va < c.bin.data.size() ? va : ~u64(0);
    }
}

// ---------------------------------------------------------------- context --
bool Engine::ensureCtx(const std::string& path) {
    if (ctxPath_ == path && !ctx_.bin.data.empty()) return true;

    Ctx c;
    auto t0 = std::chrono::steady_clock::now();
    c.bin = loadBinaryFile(path);
    auto t1 = std::chrono::steady_clock::now();
    if (c.bin.data.empty()) {
        // keep note; report via analyze()
        ctx_ = Ctx{};
        ctx_.bin.path = path;
        ctx_.notes.push_back("Could not read file (missing or empty)");
        ctxPath_.clear();
        return false;
    }
    c.loadMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    const u8* p = c.bin.data.data();
    size_t n = c.bin.data.size();
    c.fmt = detectFormat(p, n);

    switch (c.fmt) {
        case Fmt::ELF: {
            c.elf = parseElf(c.bin);
            c.arch = c.elf.archEnum;
            if (c.elf.bits == 32 && c.arch == "X86_64") c.arch = "X86";
            c.funcs = discoverFunctionsElf(c.bin, c.elf);
            u64 va = 0, size = 0;
            if (elfExecRange(c.elf, va, size)) {
                u64 off = elfVaToOff(c.elf, va);
                if (off != ~u64(0) && off + size <= n) {
                    c.xrefs = buildXrefs(c.arch, p + off, size, va);
                }
            }
            c.names = buildAddrNamesElf(c.bin, c.elf);
            c.cg = buildCallGraph(c.xrefs, c.funcs, c.names);
            if (!c.cg.edges.empty())
                c.notes.push_back("Call graph: " + std::to_string(c.cg.edges.size()) + " call edges");
            // strings from alloc non-exec sections (or whole file fallback)
            {
                std::vector<FoundString> all;
                bool any = false;
                for (auto& s : c.elf.sections) {
                    if (s.flags.find('A') == std::string::npos) continue;
                    if (s.flags.find('X') != std::string::npos) continue;
                    if (s.type != "PROGBITS" || s.offset == 0 || s.size == 0) continue;
                    if (s.offset + s.size > n) continue;
                    auto v = extractPrintableStrings(p + s.offset, s.size, s.addr, 3000, 4);
                    if (!v.empty()) any = true;
                    for (auto& fs : v) { if (all.size() < 3000) all.push_back(fs); else break; }
                    if (all.size() >= 3000) break;
                }
                if (!any) all = extractPrintableStrings(p, n, c.elf.base, 3000, 5);
                c.strings = std::move(all);
            }
            if (c.funcs.empty()) c.notes.push_back("No function symbols — used linear scan");
            break;
        }
        case Fmt::PE: {
            c.pe = parsePe(c.bin);
            c.arch = c.pe.archEnum;
            c.funcs = discoverFunctionsPe(c.bin, c.pe);
            u64 va = 0, size = 0;
            if (peExecRange(c.pe, va, size)) {
                u64 off = peVaToOff(c.pe, va);
                if (off != ~u64(0) && off + size <= n) {
                    c.xrefs = buildXrefs(c.arch, p + off, size, va);
                }
            }
            c.names = buildAddrNamesPe(c.bin, c.pe);
            c.cg = buildCallGraph(c.xrefs, c.funcs, c.names);
            c.strings = extractPrintableStrings(p, n, c.pe.imageBase, 3000, 5);
            break;
        }
        case Fmt::DEX: {
            c.dex = parseDex(c.bin);
            c.arch.clear();
            for (size_t i = 0; i < c.dex.strings.size() && c.strings.size() < 3000; ++i) {
                if (c.dex.strings[i].size() >= 4)
                    c.strings.push_back(FoundString{u64(i), c.dex.strings[i]});
            }
            buildDexFuncsAndCalls(c.bin.data, c.dex, c.funcs, c.cg);
            if (c.funcs.empty()) c.notes.push_back("No compiled methods found in DEX");
            break;
        }
        default: {
            c.arch.clear();
            c.strings = extractPrintableStrings(p, n, 0, 3000, 5);
            c.notes.push_back("Unknown format — raw mode (hex + strings only)");
            break;
        }
    }

    if (!c.arch.empty() && c.dis.open(c.arch)) {
        c.backend = c.dis.backend();
        if (c.fmt == Fmt::ELF && c.dis.armDualMode()) {
            c.dis.setArmMapping(c.elf.armMapping);
            // Stripped .so files keep .dynsym but lose the $a/$t mapping symbols
            // in .symtab. The Thumb bit on dynsym FUNC entries survives, so fall
            // back to whichever mode the majority of known functions use.
            size_t thumbFns = 0;
            for (auto& f : c.funcs) if (f.thumb) ++thumbFns;
            c.dis.setDefaultThumb(thumbFns * 2 > c.funcs.size());
            if (!c.elf.armMapping.empty())
                c.notes.push_back("ARM mapping symbols: " +
                                  std::to_string(c.elf.armMapping.size()) +
                                  " ARM/Thumb/data regions");
            else if (thumbFns)
                c.notes.push_back("ARM: no mapping symbols, " +
                                  std::to_string(thumbFns) + " Thumb functions from dynsym");
        }
    } else {
        c.backend.clear();
        if (c.fmt == Fmt::ELF || c.fmt == Fmt::PE)
            c.notes.push_back("Disassembler unavailable for arch " + c.arch);
    }

    ctx_ = std::move(c);
    ctxPath_ = path;
    return true;
}

// ---------------------------------------------------------------- analyze --
std::string Engine::analyze(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream out;

    bool loaded = ensureCtx(path);
    const Ctx& c = ctx_;

    out << "{\"ok\":";
    if (!loaded) {
        out << "false,\"error\":\"" << jsonEscape(c.notes.empty() ? "Load failed" : c.notes[0]) << "\"}";
        return out.str();
    }

    out << "true"
        << ",\"format\":" << q(fmtName(c.fmt))
        << ",\"name\":" << q(c.bin.name)
        << ",\"arch\":" << q(c.arch.empty() ? "-" : c.arch)
        << ",\"entry\":" << hq(c.fmt == Fmt::PE ? c.pe.entry : c.fmt == Fmt::ELF ? c.elf.entry : 0)
        << ",\"base\":" << hq(c.fmt == Fmt::ELF ? c.elf.base : c.fmt == Fmt::PE ? c.pe.imageBase : 0)
        << ",\"sizeBytes\":" << num(c.bin.fullSize)
        << ",\"truncated\":" << (c.bin.truncated ? "true" : "false")
        << ",\"loadMs\":" << (int)c.loadMs
        << ",\"backend\":" << q(c.backend.empty() ? "-" : c.backend)
        << ",\"disassemblable\":" << (c.backend.empty() ? "false" : "true");

    // sections
    out << ",\"sections\":[";
    {
        const std::vector<Section>* v = nullptr;
        if (c.fmt == Fmt::ELF) v = &c.elf.sections;
        else if (c.fmt == Fmt::PE) v = &c.pe.sections;
        if (v) {
            for (size_t i = 0; i < v->size(); ++i) {
                if (i) out << ",";
                auto& s = (*v)[i];
                out << "{\"name\":" << q(s.name) << ",\"type\":" << q(s.type)
                    << ",\"flags\":" << q(s.flags)
                    << ",\"addr\":" << hq(s.addr) << ",\"offset\":" << num(s.offset)
                    << ",\"size\":" << num(s.size) << "}";
            }
        }
    }
    out << "]";

    // segments / memory map
    out << ",\"segments\":[";
    if (c.fmt == Fmt::ELF) {
        for (size_t i = 0; i < c.elf.segments.size(); ++i) {
            if (i) out << ",";
            auto& s = c.elf.segments[i];
            out << "{\"type\":" << q(s.type) << ",\"flags\":" << q(s.flags)
                << ",\"vaddr\":" << hq(s.vaddr) << ",\"offset\":" << num(s.offset)
                << ",\"filesz\":" << num(s.filesz) << ",\"memsz\":" << num(s.memsz) << "}";
        }
    } else if (c.fmt == Fmt::DEX) {
        const u8* hp = c.bin.data.data();
        struct Row { const char* n; u32 o, s; };
        Row rows[] = {
            {"header", 0, 112},
            {"string_ids", rd32(hp + 60), rd32(hp + 56) * 4},
            {"type_ids", rd32(hp + 68), rd32(hp + 64) * 4},
            {"proto_ids", rd32(hp + 76), rd32(hp + 72) * 12},
            {"method_ids", rd32(hp + 92), rd32(hp + 88) * 8},
            {"class_defs", rd32(hp + 100), rd32(hp + 96) * 32},
        };
        for (size_t i = 0; i < 6; ++i) {
            if (i) out << ",";
            out << "{\"type\":" << q(rows[i].n) << ",\"flags\":" << q("R")
                << ",\"vaddr\":" << hq(rows[i].o) << ",\"offset\":" << num(rows[i].o)
                << ",\"filesz\":" << num(rows[i].s) << ",\"memsz\":" << num(rows[i].s) << "}";
        }
    }
    out << "]";

    // functions
    out << ",\"functions\":[";
    for (size_t i = 0; i < c.funcs.size(); ++i) {
        if (i) out << ",";
        auto& f = c.funcs[i];
        out << "{\"addr\":" << hq(f.addr) << ",\"size\":" << num(f.size)
            << ",\"name\":" << q(f.name) << ",\"from\":" << q(f.from);
        if (looksMangled(f.name)) {
            std::string d = demangle(f.name);
            if (d != f.name) out << ",\"demangled\":" << q(d);
        }
        // call edge counts
        auto ce = c.cg.callees.find(f.addr);
        auto cr = c.cg.callers.find(f.addr);
        out << ",\"nCallees\":" << (ce == c.cg.callees.end() ? 0 : int(ce->second.size()))
            << ",\"nCallers\":" << (cr == c.cg.callers.end() ? 0 : int(cr->second.size()))
            << "}";
    }
    out << "]";

    // call graph (capped)
    out << ",\"callEdges\":[";
    {
        size_t cap = std::min<size_t>(c.cg.edges.size(), 4000);
        for (size_t i = 0; i < cap; ++i) {
            if (i) out << ",";
            auto& e = c.cg.edges[i];
            out << "{\"from\":" << hq(e.from) << ",\"to\":" << hq(e.to)
                << ",\"fromName\":" << q(e.fromName) << ",\"toName\":" << q(e.toName)
                << ",\"kind\":" << q(e.kind) << "}";
        }
    }
    out << "]";

    // strings
    out << ",\"strings\":[";
    for (size_t i = 0; i < c.strings.size(); ++i) {
        if (i) out << ",";
        out << "{\"addr\":" << hq(c.strings[i].addr)
            << ",\"value\":" << q(c.strings[i].value.substr(0, 256)) << "}";
    }
    out << "]";

    // imports / exports
    out << ",\"imports\":[";
    if (c.fmt == Fmt::ELF || c.fmt == Fmt::PE) {
        auto& v = c.fmt == Fmt::ELF ? c.elf.imports : c.pe.imports;
        for (size_t i = 0; i < v.size(); ++i) {
            if (i) out << ",";
            out << "{\"name\":" << q(v[i].name) << ",\"addr\":" << hq(v[i].addr) << "}";
        }
    }
    out << "],\"exports\":[";
    if (c.fmt == Fmt::ELF || c.fmt == Fmt::PE) {
        auto& v = c.fmt == Fmt::ELF ? c.elf.exports : c.pe.exports;
        for (size_t i = 0; i < v.size(); ++i) {
            if (i) out << ",";
            out << "{\"name\":" << q(v[i].name) << ",\"addr\":" << hq(v[i].addr) << "}";
        }
    }
    out << "]";

    // elf extras
    out << ",\"needed\":[";
    if (c.fmt == Fmt::ELF) {
        for (size_t i = 0; i < c.elf.needed.size(); ++i) {
            if (i) out << ",";
            out << q(c.elf.needed[i]);
        }
    }
    out << "],\"soName\":" << q(c.fmt == Fmt::ELF ? c.elf.soName : "");

    // dex extras
    out << ",\"dexClasses\":[";
    if (c.fmt == Fmt::DEX) {
        for (size_t i = 0; i < c.dex.classes.size(); ++i) {
            if (i) out << ",";
            out << "{\"name\":" << q(c.dex.classes[i].name)
                << ",\"super\":" << q(c.dex.classes[i].super) << "}";
        }
    }
    out << "],\"dexMethods\":[";
    if (c.fmt == Fmt::DEX) {
        for (size_t i = 0; i < c.dex.methods.size(); ++i) {
            if (i) out << ",";
            auto& m = c.dex.methods[i];
            out << "{\"clazz\":" << q(m.clazz) << ",\"name\":" << q(m.name)
                << ",\"proto\":" << q(m.proto) << ",\"codeOff\":" << num(m.codeOff) << "}";
        }
    }
    out << "]";

    // notes
    out << ",\"notes\":[";
    for (size_t i = 0; i < c.notes.size(); ++i) {
        if (i) out << ",";
        out << q(c.notes[i]);
    }
    out << "]}";
    return out.str();
}

// --------------------------------------------------------- functionDetail --
std::string Engine::functionDetail(const std::string& path, u64 addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureCtx(path);
    Ctx& c = ctx_;
    std::ostringstream out;

    if (c.fmt == Fmt::DEX) {
        bool found = false;
        for (auto& m : c.dex.methods) {
            if (m.codeOff != addr) continue;
            found = true;
            u32 sz = 0;
            if (addr + 16 <= c.bin.data.size()) sz = 16 + rd32(c.bin.data.data() + addr + 12) * 2;
            std::string nm = dexShortClass(m.clazz) + "." + m.name;
            auto ce = c.cg.callees.find(addr);
            auto cr = c.cg.callers.find(addr);
            out << "{\"ok\":true,\"addr\":\"" << hq(addr) << "\",\"size\":" << num(sz)
                << ",\"name\":" << q(nm) << ",\"displayName\":" << q(nm)
                << ",\"from\":\"dex\",\"backend\":\"dalvik\",\"arch\":\"DEX\""
                << ",\"pseudoMode\":\"dex\""
                << ",\"asm\":[]"
                << ",\"pseudo\":" << q(std::string("// Dalvik bytecode — DEX disassembler backend on the roadmap\n")
                    + "// class: " + m.clazz + "\n// proto: " + m.proto
                    + "\n// code: " + std::to_string(sz) + " bytes\n"
                    + "// callees: " + std::to_string(ce == c.cg.callees.end() ? 0 : (int)ce->second.size())
                    + " · callers: " + std::to_string(cr == c.cg.callers.end() ? 0 : (int)cr->second.size()) + "\n")
                << ",\"blocks\":[],\"xrefsIn\":[],\"xrefsOut\":[]}";
            break;
        }
        if (!found) out << "{\"ok\":false,\"error\":\"No method at this code offset\"}";
        return out.str();
    }

    if (!c.backend.empty() && (c.fmt != Fmt::ELF && c.fmt != Fmt::PE)) {
        out << "{\"ok\":false,\"error\":\"Disassembly not available for this format\"}";
        return out.str();
    }
    if (c.backend.empty()) {
        out << "{\"ok\":false,\"error\":\"No disassembler for this architecture\"}";
        return out.str();
    }

    // find function
    const FuncInfo* fn = nullptr;
    for (auto& f : c.funcs) {
        if (f.addr == addr) { fn = &f; break; }
    }
    if (!fn) {
        for (auto& f : c.funcs) {
            if (addr >= f.addr && addr < f.addr + f.size) { fn = &f; addr = f.addr; break; }
        }
    }
    if (!fn) {
        FuncInfo tmp;
        tmp.addr = addr; tmp.size = 512; tmp.name = "SUB_" + hexAddr(addr).substr(2); tmp.from = "manual";
        c.funcs.push_back(tmp);
        fn = &c.funcs.back();
    }

    u64 off = vaToOff(c, fn->addr);
    if (off == ~u64(0) || off >= c.bin.data.size()) {
        out << "{\"ok\":false,\"error\":\"Address not mapped in file\"}";
        return out.str();
    }
    u64 size = std::min<u64>(fn->size ? fn->size : 512, 65536);
    size = std::min<u64>(size, u64(c.bin.data.size()) - off);

    // For ARM32 the enclosing function's Thumb bit decides the mode wherever the
    // mapping table has nothing to say.
    if (c.dis.armDualMode()) c.dis.setDefaultThumb(fn->thumb);

    auto lines = c.dis.disassemble(c.bin.data.data() + off, size_t(size), fn->addr, 4096);

    // trim trailing zero-padding runs (e.g. 00 00 after _fini)
    {
        int runStart = -1, run = 0;
        for (size_t i = 0; i < lines.size(); ++i) {
            bool allZero = !lines[i].bytes.empty();
            for (char ch : lines[i].bytes)
                if (ch != '0' && ch != ' ') { allZero = false; break; }
            if (allZero) {
                if (run == 0) runStart = int(i);
                if (++run >= 4) { lines.resize(size_t(runStart)); break; }
            } else run = 0;
        }
    }

    // labels for calls
    std::map<u64, std::string> labels;
    for (auto& f : c.funcs) labels[f.addr] = f.name;

    auto blocks = buildCfg(lines, fn->addr, fn->addr + size, c.arch);

    // v2: auto comments
    autoComment(c.arch, lines, c.names, c.strings, fn->addr, fn->addr + size);

    // v2: IR decompiler with heuristic fallback
    IrResult ir = decompileIR(lines, c.arch, fn->addr, fn->name, c.names, c.strings);
    std::string pseudo = ir.ok ? ir.text
                               : genPseudo(lines, c.arch, fn->addr, fn->name, labels);
    std::string pseudoMode = ir.ok ? "IR" : "heuristic";

    // v2: demangled display name
    std::string displayName = fn->name;
    if (looksMangled(fn->name)) {
        std::string d = demangle(fn->name);
        if (d != fn->name) displayName = d;
    }

    out << "{\"ok\":true,\"addr\":" << hq(fn->addr) << ",\"name\":" << q(fn->name)
        << ",\"displayName\":" << q(displayName)
        << ",\"size\":" << num(fn->size) << ",\"from\":" << q(fn->from)
        << ",\"backend\":" << q(c.backend) << ",\"arch\":" << q(c.arch)
        << ",\"pseudoMode\":" << q(pseudoMode)
        << ",\"irStats\":{\"stmts\":" << ir.nStmts << ",\"whiles\":" << ir.nWhile
        << ",\"ifs\":" << ir.nIf << ",\"gotocs\":" << ir.nGoto
        << ",\"calls\":" << ir.nCalls << "}"
        << ",\"asm\":[";
    for (size_t i = 0; i < lines.size(); ++i) {
        if (i) out << ",";
        out << "{\"a\":" << hq(lines[i].addr) << ",\"b\":" << q(lines[i].bytes)
            << ",\"m\":" << q(lines[i].mnem) << ",\"o\":" << q(lines[i].ops)
            << ",\"c\":" << q(lines[i].comment) << "}";
    }
    out << "]";

    // pseudo with escaped newlines
    out << ",\"pseudo\":" << q(pseudo);

    // blocks
    out << ",\"blocks\":[";
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (i) out << ",";
        auto& b = blocks[i];
        out << "{\"id\":" << b.id << ",\"start\":" << hq(b.start)
            << ",\"end\":" << hq(b.end) << ",\"nInstr\":" << b.nInstr << ",\"succ\":[";
        for (size_t k = 0; k < b.succ.size(); ++k) {
            if (k) out << ",";
            out << b.succ[k];
        }
        out << "]}";
    }
    out << "]";

    // xrefs in/out
    out << ",\"xrefsIn\":[";
    {
        std::vector<Xref> in;
        for (auto& kv : c.xrefs)
            for (auto& x : kv.second)
                if (x.to >= fn->addr && x.to < fn->addr + std::max<u64>(fn->size, 4))
                    { in.push_back(x); if (in.size() >= 64) break; }
        for (size_t i = 0; i < in.size(); ++i) {
            if (i) out << ",";
            out << "{\"from\":" << hq(in[i].from) << ",\"to\":" << hq(in[i].to)
                << ",\"type\":" << q(in[i].type) << "}";
        }
    }
    out << "],\"xrefsOut\":[";
    {
        std::vector<Xref> outs;
        for (auto& l : lines) {
            if ((c.arch == "ARM64" && l.mnem == "bl") || (c.arch.find("X86") == 0 && l.mnem == "call")) {
                size_t p2 = l.ops.find("0x");
                if (p2 != std::string::npos) {
                    u64 t = strtoull(l.ops.c_str() + p2 + 2, nullptr, 16);
                    if (t) {
                        outs.push_back(Xref{l.addr, t, "call"});
                        if (outs.size() >= 64) break;
                    }
                }
            }
        }
        for (size_t i = 0; i < outs.size(); ++i) {
            if (i) out << ",";
            out << "{\"from\":" << hq(outs[i].from) << ",\"to\":" << hq(outs[i].to)
                << ",\"type\":" << q(outs[i].type) << "}";
        }
    }
    out << "]}";
    return out.str();
}

// ------------------------------------------------------------------ debug --
std::string Engine::debugRun(const std::vector<std::string>& argv, int maxEvents) {
    std::lock_guard<std::mutex> lock(mutex_);
    dbgStop_ = false;
    auto res = debugRunSyscalls(argv, maxEvents, dbgStop_);

    std::ostringstream out;
    out << "{\"ok\":" << (res.ok ? "true" : "false")
        << ",\"error\":" << q(res.error) << ",\"events\":[";
    for (size_t i = 0; i < res.eventJson.size(); ++i) {
        if (i) out << ",";
        out << res.eventJson[i];
    }
    out << "]}";
    return out.str();
}

void Engine::debugStop() {
    dbgStop_ = true;
    debugStopChild();
}

// ------------------------------------------------------------- callgraph --
std::string Engine::callGraph(const std::string& path, u64 focus) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureCtx(path);
    Ctx& c = ctx_;
    std::ostringstream out;

    if (c.cg.edges.empty()) {
        out << "{\"ok\":false,\"error\":\"no call edges (not disassemblable or no calls)\"}";
        return out.str();
    }

    out << "{\"ok\":true,\"focus\":\"" << hexAddr(focus) << "\",\"edges\":[";
    size_t shown = 0;
    for (auto& e : c.cg.edges) {
        if (focus) {
            // edges touching the focus function's range
            bool fromIn = false, toIn = false;
            for (auto& f : c.funcs) {
                if (e.from >= f.addr && e.from < f.addr + std::max<u64>(f.size, 4)) fromIn = true;
                if (e.to == f.addr) toIn = true;
            }
            if (!fromIn && !toIn) continue;
        }
        if (shown++) out << ",";
        if (shown >= 2000) break;
        out << "{\"from\":" << hq(e.from) << ",\"to\":" << hq(e.to)
            << ",\"fromName\":" << q(e.fromName) << ",\"toName\":" << q(e.toName)
            << ",\"kind\":" << q(e.kind) << "}";
    }
    out << "],\"funcs\":[";
    for (size_t i = 0; i < c.funcs.size() && i < 4000; ++i) {
        if (i) out << ",";
        auto& f = c.funcs[i];
        out << "{\"addr\":" << hq(f.addr) << ",\"name\":" << q(f.name) << "}";
    }
    out << "]}";
    return out.str();
}

// ---------------------------------------------------------------- debug2 --
std::string Engine::dbgCmd(const std::string& json) {
    return DebugSession::instance().cmd(json);
}

// ---------------------------------------------------------------- script --
std::string Engine::scriptRun(const std::string& source, const std::string& path) {
    std::lock_guard<std::mutex> slock(scriptMutex_);
    ensureCtx(path);
    Ctx& c = ctx_;

    std::ostringstream logBuf;
    std::vector<std::string> effects;

    SakoScript script;

    script.setBuiltin("log", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        std::string msg;
        for (size_t i = 0; i < a.size(); ++i) {
            if (i) msg += " ";
            msg += a[i].render();
        }
        logBuf << "[plugin] " << msg << "\n";
        return ScriptValue::nil();
    });

    script.setBuiltin("count_functions", [&](const std::vector<ScriptValue>&) -> ScriptValue {
        return ScriptValue::ofNum(double(c.funcs.size()));
    });
    script.setBuiltin("func_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        size_t i = size_t(a.empty() ? 0 : a[0].num);
        if (i >= c.funcs.size()) return ScriptValue::nil();
        auto o = std::make_shared<ScriptObj>();
        (*o)["addr"] = ScriptValue::ofNum(double(c.funcs[i].addr));
        (*o)["size"] = ScriptValue::ofNum(double(c.funcs[i].size));
        (*o)["name"] = ScriptValue::ofStr(c.funcs[i].name);
        (*o)["from"] = ScriptValue::ofStr(c.funcs[i].from);
        return ScriptValue::ofObj(o);
    });
    script.setBuiltin("func_by_name", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        std::string n = a.empty() ? "" : a[0].str;
        for (auto& f : c.funcs) {
            if (f.name == n || demangle(f.name) == n) {
                auto o = std::make_shared<ScriptObj>();
                (*o)["addr"] = ScriptValue::ofNum(double(f.addr));
                (*o)["size"] = ScriptValue::ofNum(double(f.size));
                (*o)["name"] = ScriptValue::ofStr(f.name);
                return ScriptValue::ofObj(o);
            }
        }
        return ScriptValue::nil();
    });
    script.setBuiltin("count_strings", [&](const std::vector<ScriptValue>&) -> ScriptValue {
        return ScriptValue::ofNum(double(c.strings.size()));
    });
    script.setBuiltin("string_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        size_t i = size_t(a.empty() ? 0 : a[0].num);
        if (i >= c.strings.size()) return ScriptValue::nil();
        auto o = std::make_shared<ScriptObj>();
        (*o)["addr"] = ScriptValue::ofNum(double(c.strings[i].addr));
        (*o)["value"] = ScriptValue::ofStr(c.strings[i].value);
        return ScriptValue::ofObj(o);
    });
    script.setBuiltin("count_imports", [&](const std::vector<ScriptValue>&) -> ScriptValue {
        if (c.fmt == Fmt::ELF) return ScriptValue::ofNum(double(c.elf.imports.size()));
        if (c.fmt == Fmt::PE) return ScriptValue::ofNum(double(c.pe.imports.size()));
        return ScriptValue::ofNum(0);
    });
    script.setBuiltin("import_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        size_t i = size_t(a.empty() ? 0 : a[0].num);
        const std::vector<Symbol>* v = nullptr;
        if (c.fmt == Fmt::ELF) v = &c.elf.imports;
        else if (c.fmt == Fmt::PE) v = &c.pe.imports;
        if (!v || i >= v->size()) return ScriptValue::nil();
        auto o = std::make_shared<ScriptObj>();
        (*o)["name"] = ScriptValue::ofStr((*v)[i].name);
        (*o)["addr"] = ScriptValue::ofNum(double((*v)[i].addr));
        return ScriptValue::ofObj(o);
    });
    script.setBuiltin("demangle", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        return ScriptValue::ofStr(a.empty() ? "" : demangle(a[0].str));
    });
    script.setBuiltin("classify", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        const char* r = a.empty() ? nullptr : classifyImport(a[0].str);
        return r ? ScriptValue::ofStr(r) : ScriptValue::nil();
    });
    script.setBuiltin("count_xrefs_to", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.empty()) return ScriptValue::ofNum(0);
        u64 addr = u64(a[0].num);
        auto it = c.xrefs.find(addr);
        return ScriptValue::ofNum(it == c.xrefs.end() ? 0 : double(it->second.size()));
    });
    script.setBuiltin("xref_to_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::nil();
        u64 addr = u64(a[0].num);
        size_t i = size_t(a[1].num);
        auto it = c.xrefs.find(addr);
        if (it == c.xrefs.end() || i >= it->second.size()) return ScriptValue::nil();
        auto o = std::make_shared<ScriptObj>();
        (*o)["from"] = ScriptValue::ofNum(double(it->second[i].from));
        (*o)["type"] = ScriptValue::ofStr(it->second[i].type);
        return ScriptValue::ofObj(o);
    });
    // effects for the app to persist
    script.setBuiltin("rename", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::ofBool(false);
        std::ostringstream fx;
        fx << "{\"op\":\"rename\",\"addr\":\"" << hexAddr(u64(a[0].num))
           << "\",\"name\":" << q(a[1].str) << "}";
        effects.push_back(fx.str());
        return ScriptValue::ofBool(true);
    });
    script.setBuiltin("comment", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::ofBool(false);
        std::ostringstream fx;
        fx << "{\"op\":\"comment\",\"addr\":\"" << hexAddr(u64(a[0].num))
           << "\",\"text\":" << q(a[1].str) << "}";
        effects.push_back(fx.str());
        return ScriptValue::ofBool(true);
    });
    script.setBuiltin("bookmark", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::ofBool(false);
        std::ostringstream fx;
        fx << "{\"op\":\"bookmark\",\"addr\":\"" << hexAddr(u64(a[0].num))
           << "\",\"label\":" << q(a[1].str) << "}";
        effects.push_back(fx.str());
        return ScriptValue::ofBool(true);
    });
    script.setBuiltin("hex", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.empty()) return ScriptValue::ofStr("0x0");
        return ScriptValue::ofStr("0x" + hexAddr(u64(a[0].num)));
    });
    script.setBuiltin("strlen", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        return ScriptValue::ofNum(a.empty() ? 0 : double(a[0].str.size()));
    });
    script.setBuiltin("charat", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::ofNum(0);
        long long i = (long long)a[1].num;
        if (i < 0 || i >= (long long)a[0].str.size()) return ScriptValue::ofNum(0);
        return ScriptValue::ofNum(double((unsigned char)a[0].str[(size_t)i]));
    });
    script.setBuiltin("str", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        return ScriptValue::ofStr(a.empty() ? "" : a[0].render());
    });

    ScriptError err = script.run(source);

    std::ostringstream out;
    out << "{\"ok\":" << (err.ok ? "true" : "false");
    if (!err.ok) out << ",\"error\":" << q(err.message) << ",\"line\":" << err.line;
    out << ",\"log\":" << q(logBuf.str()) << ",\"effects\":[";
    for (size_t i = 0; i < effects.size(); ++i) {
        if (i) out << ",";
        out << effects[i];
    }
    out << "]}";
    return out.str();
}

} // namespace sako
