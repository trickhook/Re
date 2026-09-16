#include "Engine.h"
#include "GhidraArch.h"
#include "GhidraEmu.h"
#include "JniTypes.h"
#include <fstream>
#include "Binary.h"
#include "DebugSession.h"
#include "Script.h"
#include "Demangle.h"
#include <chrono>
#include <cmath>
#include <cstring>
#include <sstream>

namespace sako {

// Address->string table size. Large enough to cover a real .rodata; the UI
// list is trimmed separately at serialisation time.
static const size_t kStringCap = 20000;
// How many of those to put in the analysis JSON the UI reads.
static const size_t kStringsInJson = 3000;
// Call edges in the analysis JSON. Measured on a host build (x86-64, warm JVM
// modelling org.json + parseMeta; a phone is several times slower, though the
// parse runs on Dispatchers.IO, not the UI thread):
//
//   edges   payload     parse   heap after
//    5203    890 KB     20 ms      ~9 MB   libanort.so (1.7 MB) — complete
//   12000   2.0 MB      35 ms     ~24 MB   cap
//   40000   5.8 MB      86 ms     ~47 MB
//   66059   9.3 MB     135 ms     ~80 MB   libpython3.12.so (9 MB) — complete
//
// 12000 covers the binaries this tool is pointed at with room to spare (2.3x
// the workhorse sample) and keeps the worst case at ~2 MB. Past that the array
// stops being something a UI can draw or a phone should hold, so it is capped
// — but never in silence: callEdgesTotal is always emitted next to the array,
// and a note says how much was left out. Edges are sorted by (caller, target),
// so what a cap removes is a documented suffix, not an invisible slice.
static const size_t kCallEdgesInJson = 12000;
// Edges and nodes in one callGraph() answer. This one is drawn as a graph, so
// the limit is what a canvas can show, not what the parser can take; the JSON
// carries edgesTotal / funcsTotal so the panel can say how much is off-screen.
static const size_t kCallGraphEdgesInJson = 4000;
static const size_t kCallGraphFuncsInJson = 4000;
// Call-site rows in one function's xrefsIn/xrefsOut. A bottom sheet is not a
// place for 300 rows, so this one stays small — but xrefsInTotal /
// xrefsOutTotal always carry the real count next to the truncated array.
static const size_t kXrefRowsInJson = 64;


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

// ------------------------------------------------------------ data xrefs --
// buildXrefs() records branch targets and nothing else, so on AArch64 the
// answer to "what references this string" was zero for every string in every
// binary. That is not a small gap: the shipped string-hunter plugin gates its
// whole body on `count_xrefs_to(s.addr) > 0` and has therefore never annotated
// a single string on the architecture this tool is built for, and the xrefs
// panel was empty for every piece of data.
//
// A data reference on AArch64 is two instructions — ADRP puts a 4 KiB page in
// a register, then ADD or LDR adds the offset — so it takes a register table
// to see one at all. The table is cleared at every RET, which keeps a page
// from leaking across a function boundary into a wrong answer.
//
// Type "data", never "call": buildCallGraph filters on "call", so the call
// graph is unchanged by this and stays a graph of calls.
static void addDataXrefs(const std::string& arch, const u8* code, size_t size, u64 va,
                         u64 mapLo, u64 mapHi,
                         std::map<u64, std::vector<Xref>>& out, size_t cap = 200000) {
    size_t total = 0;
    for (auto& kv : out) total += kv.second.size();
    auto push = [&](u64 from, u64 to) {
        if (to < mapLo || to >= mapHi || total >= cap) return;
        out[to].push_back(Xref{from, to, "data"});
        ++total;
    };

    if (arch == "ARM64") {
        u64 page[32];
        bool have[32];
        for (int i = 0; i < 32; ++i) { page[i] = 0; have[i] = false; }
        for (size_t i = 0; i + 4 <= size; i += 4) {
            u32 w = rd32(code + i);
            u64 pc = va + i;
            if (w == 0xD65F03C0) {                         // RET
                for (int k = 0; k < 32; ++k) have[k] = false;
                continue;
            }
            if ((w & 0x9F000000) == 0x90000000) {          // ADRP Rd, page
                u32 rd = w & 0x1F;
                i64 imm = i64(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3));
                page[rd] = u64(i64(pc & ~u64(0xFFF)) + (sext(imm, 21) << 12));
                have[rd] = true;
                continue;
            }
            if ((w & 0x9F000000) == 0x10000000) {          // ADR Rd, label
                u32 rd = w & 0x1F;
                i64 imm = i64(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3));
                page[rd] = u64(i64(pc) + sext(imm, 21));
                have[rd] = true;
                push(pc, page[rd]);
                continue;
            }
            if ((w & 0xFF800000) == 0x91000000) {          // ADD Xd, Xn, #imm12
                u32 rd = w & 0x1F, rn = (w >> 5) & 0x1F, imm12 = (w >> 10) & 0xFFF;
                if (have[rn]) {
                    u64 t = page[rn] + imm12;
                    push(pc, t);
                    page[rd] = t; have[rd] = true;
                } else if (rd != rn) have[rd] = false;
                continue;
            }
            if ((w & 0xFFC00000) == 0xF9400000) {          // LDR Xt, [Xn, #imm12*8]
                u32 rt = w & 0x1F, rn = (w >> 5) & 0x1F, imm12 = (w >> 10) & 0xFFF;
                if (have[rn]) push(pc, page[rn] + u64(imm12) * 8);
                have[rt] = false;
                continue;
            }
            if ((w & 0xFFC00000) == 0xB9400000) {          // LDR Wt, [Xn, #imm12*4]
                u32 rt = w & 0x1F, rn = (w >> 5) & 0x1F, imm12 = (w >> 10) & 0xFFF;
                if (have[rn]) push(pc, page[rn] + u64(imm12) * 4);
                have[rt] = false;
                continue;
            }
            // Anything else that writes Rd invalidates whatever page it held.
            // Only the common register-destination shapes are decoded here;
            // being conservative costs a missed reference, never a wrong one.
            // logical / add-sub shifted register, and MOVZ/MOVN/MOVK — the
            // 0x12800000 opcode field covers both widths of the move, so
            // there is no separate 32-bit case to test.
            if ((w & 0x1F000000) == 0x0A000000 || (w & 0x1F000000) == 0x0B000000 ||
                (w & 0x1F800000) == 0x12800000)
                have[w & 0x1F] = false;
        }
    } else if (arch == "X86_64") {
        // lea r64, [rip + disp32] — 48 8D /r with ModRM mod=00 rm=101.
        for (size_t i = 0; i + 7 <= size; ++i) {
            if ((code[i] & 0xF8) != 0x48 || code[i + 1] != 0x8D) continue;
            u8 modrm = code[i + 2];
            if ((modrm & 0xC7) != 0x05) continue;
            i64 d = i64(i32(rd32(code + i + 3)));
            push(va + i, u64(i64(va + i + 7) + d));
            i += 6;
        }
    }
}

// ------------------------------------------------ decompiler selection --
void Engine::setSleighDir(const std::string& dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    sleighDir_ = dir;
    if (!dir.empty()) GhidraDecomp::instance().setSpecDir(dir);
}

void Engine::setDecompiler(const std::string& which) {
    std::lock_guard<std::mutex> lock(mutex_);
    decompiler_ = (which == "ir") ? "ir" : "ghidra";
}

// Binds the Ghidra backend to the loaded image. Failure here is never fatal:
// the caller decompiles with the IR lifter instead and the reason is reported
// through decompilerStatus().
bool Engine::ghidraReady(Ctx& c, const std::string& path) {
    ghidraNote_.clear();
    if (decompiler_ != "ghidra") { ghidraNote_ = "built-in IR lifter selected"; return false; }
    if (!GhidraDecomp::compiledIn()) { ghidraNote_ = "engine built without it"; return false; }
    if (sleighDir_.empty()) { ghidraNote_ = "no SLEIGH specifications installed"; return false; }
    if (GhidraDecomp::languageFor(c.arch).empty()) {
        ghidraNote_ = "no SLEIGH specification for " + (c.arch.empty() ? "this target" : c.arch);
        return false;
    }
    if (c.bin.data.empty()) { ghidraNote_ = "no image loaded"; return false; }

    // The decompiler reads through virtual addresses, so it needs the mapping
    // the loader already worked out.
    std::vector<GhidraSeg> segs;
    if (c.fmt == Fmt::ELF) {
        for (auto& sg : c.elf.segments)
            if (sg.type == "LOAD" && sg.filesz)
                segs.push_back({sg.vaddr, sg.offset, sg.filesz,
                                sg.memsz ? sg.memsz : sg.filesz,
                                sg.flags.find('W') != std::string::npos});
    } else if (c.fmt == Fmt::PE) {
        for (auto& sc : c.pe.sections)
            if (sc.size)
                segs.push_back({sc.addr, sc.offset, sc.size, sc.size,
                                sc.flags.find('W') != std::string::npos});
    }
    if (segs.empty())
        segs.push_back({0, 0, u64(c.bin.data.size()), u64(c.bin.data.size()), true});

    // Read-only ranges come from the section table, because a linker happily
    // puts .rodata inside a writable PT_LOAD. Where a section itself says it
    // is writable we take it at its word: a writable .rodata usually means the
    // library rewrites its own constants, and folding through it would print
    // strings the running program never sees.
    std::vector<std::pair<u64, u64>> readOnly;
    if (c.fmt == Fmt::ELF) {
        for (auto& sc : c.elf.sections) {
            if (!sc.addr || !sc.size) continue;
            if (sc.flags.find('A') == std::string::npos) continue;
            if (sc.flags.find('W') != std::string::npos) continue;
            readOnly.push_back({sc.addr, sc.addr + sc.size});
        }
    } else if (c.fmt == Fmt::PE) {
        for (auto& sc : c.pe.sections) {
            if (!sc.addr || !sc.size) continue;
            if (sc.flags.find('W') != std::string::npos) continue;
            readOnly.push_back({sc.addr, sc.addr + sc.size});
        }
    }

    // Publishing every known entry point is what makes a call render as a
    // name. PLT stubs carry the imported name, which is the useful one.
    std::vector<std::pair<u64, std::string>> funcs;
    funcs.reserve(c.funcs.size() + c.elf.pltNames.size());
    for (auto& f : c.funcs)
        if (f.addr && !f.name.empty()) funcs.push_back({f.addr, f.name});
    for (auto& kv : c.elf.pltNames)
        if (kv.first && !kv.second.empty()) funcs.push_back({kv.first, kv.second});

    // Building a decompiler Architecture rebinds the one SLEIGH translator
    // the process keeps for this language, so the emulator has to know when
    // it happened: it shares that translator and would otherwise read the
    // next run's bytes through the decompiler's loader. Only a change of
    // image actually rebuilds, which is exactly when it matters.
    const bool rebuilt = (ghidraKey_ != path);

    std::string err;
    if (!GhidraDecomp::instance().open(path, c.arch, c.bin.data.data(), c.bin.data.size(),
                                       segs, readOnly, funcs, c.strings,
                                       c.elf.armMapping, err)) {
        ghidraNote_ = err.empty() ? "could not build the architecture" : err;
        ghidraKey_.clear();
        return false;
    }
    if (rebuilt) {
        ghidraKey_ = path;
        GhidraEmu::instance().translatorRebound();
    }
    return true;
}

// Does this function take a JNIEnv* as its first argument? Nothing in a
// stripped library says so, but the code does: an Android native helper loads
// the interface table out of its first argument and calls through it. That one
// fact is what turns
//     (**(code **)(*param_1 + 0x720))(param_1)
// into (*env)->ExceptionCheck(env), and this library does it 526 times.
// "x0, [x1, #8]" -> {"x0", "[x1, #8]"}
static std::vector<std::string> splitOperands(const std::string& ops) {
    std::vector<std::string> out;
    int depth = 0;
    std::string cur;
    for (char c : ops) {
        if (c == '[') { ++depth; cur += c; }
        else if (c == ']') { --depth; cur += c; }
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

// What one argument is used for, followed through the registers it is copied
// into. A single forward walk answers both questions we have about it: are the
// interface slots it is called through real JNI functions, and which calls is
// it handed on to.
//
// Deliberately a straight-line walk with no joins. A value that survives to a
// use along the fall-through path is the case worth catching, and treating
// anything else as unknown keeps a wrong claim out: the cost of being
// conservative is a helper left untyped, the cost of being wrong is printing a
// call the code never makes.
struct JniTrace {
    std::vector<u64> slots;                    // interface offsets called through it
    std::vector<std::pair<u64, int>> calls;    // (callee, argument index) it reaches
};

static void traceJniEnv(const std::vector<AsmLine>& lines, int envArg, JniTrace& out) {
    if (envArg < 0 || envArg > 7) return;
    bool isEnv[31] = {false};                  // holds the JNIEnv itself
    bool isTable[31] = {false};                // holds *JNIEnv, the function table
    std::map<i64, bool> slotIsEnv;             // frame offset -> spilled env

    auto regNum = [](const std::string& r) -> int {
        if (r.size() < 2 || (r[0] != 'x' && r[0] != 'w')) return -1;
        if (r.find_first_not_of("0123456789", 1) != std::string::npos) return -1;
        int n = atoi(r.c_str() + 1);
        return (n >= 0 && n <= 30) ? n : -1;
    };
    // "[sp, #16]" / "[x29, #-8]" -> the frame offset, if that is what it is
    auto frameOff = [](const std::string& ops, i64& off) -> bool {
        size_t lb = ops.find('[');
        if (lb == std::string::npos) return false;
        std::string inner = ops.substr(lb + 1);
        if (inner.rfind("sp", 0) != 0 && inner.rfind("x29", 0) != 0) return false;
        size_t h = inner.find('#');
        size_t rb = inner.find(']');
        if (h == std::string::npos || rb == std::string::npos || h > rb) { off = 0; return true; }
        bool neg = inner[h + 1] == '-';
        size_t ds = h + (neg ? 2 : 1);
        u64 v = strtoull(inner.c_str() + ds, nullptr,
                         inner.compare(ds, 2, "0x") == 0 ? 16 : 10);
        off = neg ? -i64(v) : i64(v);
        return true;
    };
    // "[x19, #0x720]" -> base register and displacement
    auto memBase = [&](const std::string& ops, int& base, u64& disp) -> bool {
        size_t lb = ops.find('[');
        if (lb == std::string::npos) return false;
        size_t rb = ops.find(']', lb);
        if (rb == std::string::npos) return false;
        std::string inner = ops.substr(lb + 1, rb - lb - 1);
        size_t comma = inner.find(',');
        std::string reg = (comma == std::string::npos) ? inner : inner.substr(0, comma);
        while (!reg.empty() && reg.back() == ' ') reg.pop_back();
        base = regNum(reg);
        disp = 0;
        if (base < 0) return false;
        if (comma != std::string::npos) {
            size_t h = inner.find('#', comma);
            if (h == std::string::npos) return false;   // register offset: not a slot
            disp = strtoull(inner.c_str() + h + 1, nullptr,
                            inner.compare(h + 1, 2, "0x") == 0 ? 16 : 10);
        }
        return true;
    };

    isEnv[envArg] = true;

    for (const AsmLine& l : lines) {
        const std::string& m = l.mnem;

        if (m == "bl" || m == "blr") {
            if (m == "bl") {
                size_t p = l.ops.find("0x");
                u64 t = (p == std::string::npos) ? 0
                                                 : strtoull(l.ops.c_str() + p + 2, nullptr, 16);
                if (t) for (int i = 0; i <= 7; ++i) if (isEnv[i]) out.calls.push_back({t, i});
            }
            // AAPCS64: x0-x18 do not survive a call, x19-x28 do.
            for (int i = 0; i <= 18; ++i) { isEnv[i] = false; isTable[i] = false; }
            continue;
        }

        auto toks = splitOperands(l.ops);
        if (toks.empty()) continue;
        int d = regNum(toks[0]);

        if (m == "str" || m == "stur" || m == "strb" || m == "strh") {
            i64 off;
            if (d >= 0 && frameOff(l.ops, off)) slotIsEnv[off] = isEnv[d];
            continue;                          // a store defines no register
        }
        if (d < 0) continue;

        if (m == "mov" && toks.size() >= 2) {
            int sn = regNum(toks[1]);
            isEnv[d] = (sn >= 0 && isEnv[sn]);
            isTable[d] = (sn >= 0 && isTable[sn]);
            continue;
        }
        if (m == "ldr" || m == "ldur") {
            i64 off;
            int base; u64 disp;
            if (frameOff(l.ops, off)) {
                auto it = slotIsEnv.find(off);
                isEnv[d] = (it != slotIsEnv.end() && it->second);
                isTable[d] = false;
            } else if (memBase(l.ops, base, disp)) {
                // "ldr x8, [x8]" is ordinary, so read what the base held before
                // the destination is cleared — they are often the same register.
                bool baseWasEnv = isEnv[base];
                bool baseWasTable = isTable[base];
                // *env is the function table; *(table + slot) is one function.
                isEnv[d] = false;
                isTable[d] = (disp == 0 && baseWasEnv);
                if (disp != 0 && baseWasTable) out.slots.push_back(disp);
            } else {
                isEnv[d] = false;
                isTable[d] = false;
            }
            continue;
        }
        isEnv[d] = false;                      // any other definition kills both
        isTable[d] = false;
    }
}

// Every slot called through the pointer has to name a real JNI function. A C++
// virtual call on `this` has exactly this shape, so where the offsets land is
// the only thing that tells the two apart: one in the four reserved slots, or
// past the end of the table, is proof the object is something else.
static bool slotsLookLikeJni(const std::vector<u64>& slots) {
    if (slots.empty()) return false;
    const u64 kFirst = 4 * 8;
    const u64 kLast = u64(jni::kNativeInterfaceCount) * 8;
    for (u64 off : slots)
        if (off % 8 != 0 || off < kFirst || off >= kLast) return false;
    return true;
}

// Every slot this function calls through a double indirection, whatever the
// pointer came from. Once a parameter is declared JNIEnv* the decompiler
// resolves calls through it by type, including ones the argument trace did not
// follow, so the trace's own coverage is not enough to vouch for the claim: a
// function that mixes an interface pointer with a C++ vtable would have the
// vtable slots printed as JNI functions too.
static void allIndirectSlots(const std::vector<AsmLine>& lines, std::vector<u64>& out) {
    std::map<std::string, bool> isTable;       // register holds a *something table
    for (const AsmLine& l : lines) {
        if (l.mnem == "bl" || l.mnem == "blr") { isTable.clear(); continue; }
        if (l.mnem != "ldr" && l.mnem != "ldur") continue;
        auto toks = splitOperands(l.ops);
        if (toks.size() < 2) continue;
        size_t lb = l.ops.find('['), rb = l.ops.find(']');
        if (lb == std::string::npos || rb == std::string::npos) continue;
        std::string inner = l.ops.substr(lb + 1, rb - lb - 1);
        size_t comma = inner.find(',');
        std::string base = (comma == std::string::npos) ? inner : inner.substr(0, comma);
        while (!base.empty() && base.back() == ' ') base.pop_back();
        if (base == "sp" || base == "x29") { isTable.erase(toks[0]); continue; }
        if (comma == std::string::npos) { isTable[toks[0]] = true; continue; }
        size_t h = inner.find('#', comma);
        if (h == std::string::npos) { isTable.erase(toks[0]); continue; }
        auto it = isTable.find(base);
        bool baseWasTable = (it != isTable.end() && it->second);
        u64 disp = strtoull(inner.c_str() + h + 1, nullptr,
                            inner.compare(h + 1, 2, "0x") == 0 ? 16 : 10);
        if (baseWasTable && disp) out.push_back(disp);
        isTable.erase(toks[0]);
    }
}

// Which argument, if any, is a JNIEnv*.
static int detectJniEnvArg(const std::vector<AsmLine>& lines, const std::string& arch) {
    if (arch != "ARM64") return -1;            // only ARM64 is pattern-matched here
    std::vector<u64> all;
    allIndirectSlots(lines, all);
    if (!all.empty() && !slotsLookLikeJni(all)) return -1;
    for (int a = 0; a <= 7; ++a) {
        JniTrace t;
        traceJniEnv(lines, a, t);
        if (slotsLookLikeJni(t.slots)) return a;
    }
    return -1;
}

// Seed from what is certain, then follow the pointer across calls until
// nothing new is learned. An entry point's signature is fixed by the JNI
// specification and its name; a helper that loads the interface table out of
// one of its arguments identifies itself; everything after that is reached by
// seeing one of those hand the pointer on.
void Engine::computeJniEnvArgs(Ctx& c) {
    if (c.jniEnvArgDone) return;
    c.jniEnvArgDone = true;
    if (c.arch != "ARM64" || c.backend.empty()) return;

    auto disasmOf = [&](const FuncInfo& fn) -> std::vector<AsmLine> {
        u64 o = vaToOff(c, fn.addr);
        if (o == ~u64(0) || o >= c.bin.data.size()) return {};
        u64 sz = std::min<u64>(fn.size ? fn.size : 512, 65536);
        sz = std::min<u64>(sz, u64(c.bin.data.size()) - o);
        if (!sz) return {};
        return c.dis.disassemble(c.bin.data.data() + o, size_t(sz), fn.addr, 4096);
    };

    std::map<u64, const FuncInfo*> byAddr;
    for (auto& fn : c.funcs) byAddr[fn.addr] = &fn;

    std::vector<u64> work;
    auto learn = [&](u64 addr, int arg) {
        if (arg < 0 || arg > 7) return;
        if (!byAddr.count(addr)) return;
        if (c.jniEnvArg.count(addr)) return;   // first claim wins; no oscillation
        c.jniEnvArg[addr] = arg;
        work.push_back(addr);
    };

    // Seeds. A Java_* export takes (JNIEnv*, jobject, ...) by definition.
    for (auto& fn : c.funcs) {
        if (fn.name.rfind("Java_", 0) == 0) { learn(fn.addr, 0); continue; }
        auto lines = disasmOf(fn);
        if (lines.empty()) continue;
        int a = detectJniEnvArg(lines, c.arch);
        if (a >= 0) learn(fn.addr, a);
    }
    size_t seeded = c.jniEnvArg.size();

    // Fixpoint. Bounded so a pathological call graph cannot spin.
    size_t guard = 0;
    while (!work.empty() && guard++ < 200000) {
        u64 addr = work.back();
        work.pop_back();
        auto fit = byAddr.find(addr);
        if (fit == byAddr.end()) continue;
        auto lines = disasmOf(*fit->second);
        if (lines.empty()) continue;
        JniTrace t;
        traceJniEnv(lines, c.jniEnvArg[addr], t);
        // Propagation proposes; the callee's own code decides. If it calls a
        // slot through that argument which no JNI function occupies, then
        // whatever it was handed is not an interface pointer — withdraw the
        // claim rather than print a call to a reserved slot, and do not spread
        // it further.
        std::vector<u64> all;
        allIndirectSlots(lines, all);
        if (!all.empty() && !slotsLookLikeJni(all)) {
            c.jniEnvArg.erase(addr);
            continue;
        }
        for (auto& cl : t.calls) learn(cl.first, cl.second);
    }

    if (!c.jniEnvArg.empty())
        c.notes.push_back("JNIEnv reaches " + std::to_string(c.jniEnvArg.size()) +
                          " functions (" + std::to_string(seeded) + " found directly, " +
                          std::to_string(c.jniEnvArg.size() - seeded) + " by propagation)");
}

std::string Engine::ghidraPseudo(Ctx& c, const std::string& path, const FuncInfo& fn,
                                 const std::vector<AsmLine>& lines) {
    if (!ghidraReady(c, path)) return std::string();
    computeJniEnvArgs(c);
    std::string err;
    auto it = c.jniEnvArg.find(fn.addr);
    int env = (it != c.jniEnvArg.end()) ? it->second
                                        : detectJniEnvArg(lines, c.arch);
    std::string text = GhidraDecomp::instance().decompile(fn.addr, fn.name, err, env);
    if (text.empty()) ghidraNote_ = err.empty() ? "no output" : err;
    return text;
}

std::string Engine::decompilerStatus(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream out;
    bool ok = false;
    std::string backend, note;
    if (!path.empty() && ensureCtx(path)) {
        ok = ghidraReady(ctx_, path);
        backend = ok ? GhidraDecomp::instance().backendName() : std::string();
        note = ghidraNote_;
    } else {
        note = GhidraDecomp::compiledIn() ? "no binary analysed"
                                          : "engine built without the Ghidra decompiler";
    }
    out << "{\"compiledIn\":" << (GhidraDecomp::compiledIn() ? "true" : "false")
        << ",\"selected\":" << q(decompiler_)
        << ",\"specsInstalled\":" << (sleighDir_.empty() ? "false" : "true")
        << ",\"active\":" << (ok ? "true" : "false")
        << ",\"backend\":" << q(backend)
        << ",\"note\":" << q(note) << "}";
    return out.str();
}

u64 Engine::vaToOff(const Ctx& c, u64 va) {
    switch (c.fmt) {
        case Fmt::ELF: return elfVaToOff(c.elf, va);
        case Fmt::PE:  return peVaToOff(c.pe, va);
        default:       return va < c.bin.data.size() ? va : ~u64(0);
    }
}

// ---------------------------------------------------------------- context --
/**
 * Function discovery is capped, like the call-edge list and the two graph
 * arrays — but unlike them it used to throw the pre-cut count away, so the
 * engine could not report its own truncation even in a note. This is the same
 * sentence the other three caps write, in the same place.
 */
static void noteFunctionCap(std::vector<std::string>& notes, size_t have, size_t found) {
    if (found <= have) return;
    notes.push_back("Function discovery: carrying " + std::to_string(have)
                    + " of " + std::to_string(found)
                    + " functions found, lowest address first");
}

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
            size_t nFound = 0;
            c.funcs = discoverFunctionsElf(c.bin, c.elf, &nFound);
            noteFunctionCap(c.notes, c.funcs.size(), nFound);
            u64 va = 0, size = 0;
            if (elfExecRange(c.elf, va, size)) {
                u64 off = elfVaToOff(c.elf, va);
                if (off != ~u64(0) && off + size <= n) {
                    c.xrefs = buildXrefs(c.arch, p + off, size, va);
                    // Data references too, so "what reads this string" has an
                    // answer. Bounded to the addresses the file actually maps.
                    u64 lo = ~u64(0), hi = 0;
                    for (auto& sg : c.elf.segments)
                        if (sg.type == "LOAD" && sg.memsz) {
                            lo = std::min(lo, sg.vaddr);
                            hi = std::max(hi, sg.vaddr + sg.memsz);
                        }
                    if (lo < hi) addDataXrefs(c.arch, p + off, size, va, lo, hi, c.xrefs);
                }
            }
            c.names = buildAddrNamesElf(c.bin, c.elf);
            // Functions found by the scan are not in the symbol table, so a
            // pointer to one printed as a bare address. Registering them lets
            // the decompiler name callbacks and vtable entries, which is most
            // of what a function pointer is used for in the binaries this
            // tool is pointed at.
            for (auto& fn : c.funcs) c.names.add(fn.addr, fn.name);
            c.cg = buildCallGraph(c.xrefs, c.funcs, c.names);
            if (!c.cg.edges.empty())
                c.notes.push_back("Call graph: " + std::to_string(c.cg.edges.size())
                                  + " call edges from " + std::to_string(c.cg.callSites)
                                  + " call sites");
            // strings from alloc non-exec sections (or whole file fallback).
            // The cap is the decompiler's address->string table, not the list
            // the UI shows: at 3000 it ran out inside .rodata and never reached
            // .data, so references there stayed as bare addresses.
            {
                std::vector<FoundString> all;
                bool any = false;
                for (auto& s : c.elf.sections) {
                    if (s.flags.find('A') == std::string::npos) continue;
                    if (s.flags.find('X') != std::string::npos) continue;
                    if (s.type != "PROGBITS" || s.offset == 0 || s.size == 0) continue;
                    if (s.offset + s.size > n) continue;
                    auto v = extractPrintableStrings(p + s.offset, s.size, s.addr, kStringCap, 4);
                    if (!v.empty()) any = true;
                    for (auto& fs : v) { if (all.size() < kStringCap) all.push_back(fs); else break; }
                    if (all.size() >= kStringCap) break;
                }
                if (!any) all = extractPrintableStrings(p, n, c.elf.base, kStringCap, 5);
                c.strings = std::move(all);
            }
            if (c.funcs.empty()) c.notes.push_back("No function symbols — used linear scan");
            break;
        }
        case Fmt::PE: {
            c.pe = parsePe(c.bin);
            c.arch = c.pe.archEnum;
            size_t nFound = 0;
            c.funcs = discoverFunctionsPe(c.bin, c.pe, &nFound);
            noteFunctionCap(c.notes, c.funcs.size(), nFound);
            u64 va = 0, size = 0;
            if (peExecRange(c.pe, va, size)) {
                u64 off = peVaToOff(c.pe, va);
                if (off != ~u64(0) && off + size <= n) {
                    c.xrefs = buildXrefs(c.arch, p + off, size, va);
                    u64 lo = ~u64(0), hi = 0;
                    for (auto& sc : c.pe.sections)
                        if (sc.size) {
                            lo = std::min(lo, sc.addr);
                            hi = std::max(hi, sc.addr + sc.size);
                        }
                    if (lo < hi) addDataXrefs(c.arch, p + off, size, va, lo, hi, c.xrefs);
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
    // Notes discovered while serialising (i.e. anything the JSON had to leave
    // out). The notes array is emitted last, so they can still be appended.
    std::vector<std::string> extraNotes;

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

    // Call graph. The edge list is sorted by (calling function, target) —
    // see DeepAnalysis.h — so a cap, if one is ever hit, removes a documented
    // suffix instead of the silent slice the old target-ordered cap removed.
    // callEdgesTotal is always emitted: the array length is a rendering
    // decision, the total is the measurement.
    out << ",\"callEdgesTotal\":" << num(c.cg.edges.size())
        << ",\"callSitesTotal\":" << num(c.cg.callSites)
        << ",\"callEdges\":[";
    {
        size_t cap = std::min<size_t>(c.cg.edges.size(), kCallEdgesInJson);
        for (size_t i = 0; i < cap; ++i) {
            if (i) out << ",";
            auto& e = c.cg.edges[i];
            out << "{\"from\":" << hq(e.from) << ",\"to\":" << hq(e.to)
                << ",\"site\":" << hq(e.site) << ",\"sites\":" << e.sites
                << ",\"fromName\":" << q(e.fromName) << ",\"toName\":" << q(e.toName)
                << ",\"kind\":" << q(e.kind) << "}";
        }
        if (cap < c.cg.edges.size())
            extraNotes.push_back("Call graph: JSON carries " + std::to_string(cap) + " of "
                                 + std::to_string(c.cg.edges.size())
                                 + " edges, lowest caller address first");
    }
    out << "]";

    // strings
    out << ",\"strings\":[";
    size_t nStr = c.strings.size() < kStringsInJson ? c.strings.size() : kStringsInJson;
    for (size_t i = 0; i < nStr; ++i) {
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
    for (size_t i = 0; i < extraNotes.size(); ++i) {
        if (i || !c.notes.empty()) out << ",";
        out << q(extraNotes[i]);
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
            // codeOff 0 means "no code item": such a method is not in
            // meta.functions either, and reading a code header at file offset 0
            // returns the DEX magic dressed up as an instruction count.
            if (!m.codeOff || m.codeOff != addr) continue;
            found = true;
            u32 sz = 0;
            if (addr + 16 <= c.bin.data.size()) sz = 16 + rd32(c.bin.data.data() + addr + 12) * 2;
            std::string nm = dexShortClass(m.clazz) + "." + m.name;
            auto ce = c.cg.callees.find(addr);
            auto cr = c.cg.callers.find(addr);
            // hq() brings its own quotes — this line used to add a second
            // pair, so every DEX method detail was malformed JSON and the
            // Kotlin parser rejected all of them.
            out << "{\"ok\":true,\"addr\":" << hq(addr) << ",\"size\":" << num(sz)
                << ",\"name\":" << q(nm) << ",\"displayName\":" << q(nm)
                << ",\"from\":\"dex\",\"backend\":\"dalvik\",\"arch\":\"DEX\""
                << ",\"pseudoMode\":\"dex\""
                // Same two numbers, from the same maps, as the functions list:
                // a DEX method must not read "3 in" on one screen and "0" here.
                << ",\"nCallees\":" << (ce == c.cg.callees.end() ? 0 : int(ce->second.size()))
                << ",\"nCallers\":" << (cr == c.cg.callers.end() ? 0 : int(cr->second.size()))
                << ",\"asm\":[]"
                << ",\"pseudo\":" << q(std::string("// Dalvik bytecode — DEX disassembler backend on the roadmap\n")
                    + "// class: " + m.clazz + "\n// proto: " + m.proto
                    + "\n// code: " + std::to_string(sz) + " bytes\n"
                    + "// callees: " + std::to_string(ce == c.cg.callees.end() ? 0 : (int)ce->second.size())
                    + " · callers: " + std::to_string(cr == c.cg.callers.end() ? 0 : (int)cr->second.size()) + "\n")
                << ",\"blocks\":[],\"xrefsInTotal\":0,\"xrefsIn\":[]"
                << ",\"xrefsOutTotal\":0,\"xrefsOut\":[]}";
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

    // Ghidra's p-code decompiler when a specification covers this target,
    // otherwise the built-in IR lifter, otherwise the heuristic printer.
    IrResult ir;
    std::string pseudo = ghidraPseudo(c, path, *fn, lines);
    std::string pseudoMode = "Ghidra";
    std::string pseudoBackend = pseudo.empty() ? std::string()
                                               : GhidraDecomp::instance().backendName();
    if (pseudo.empty()) {
        ir = decompileIR(lines, c.arch, fn->addr, fn->name, c.names, c.strings);
        pseudo = ir.ok ? ir.text : genPseudo(lines, c.arch, fn->addr, fn->name, labels);
        pseudoMode = ir.ok ? "IR" : "heuristic";
        pseudoBackend = ghidraNote_;
    }

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
        << ",\"pseudoBackend\":" << q(pseudoBackend)
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

    // Cross-references. Two different things are reported here and they are
    // named apart on purpose:
    //   nCallers / nCallees — degrees in the call graph, one entry per calling
    //     or called FUNCTION, identical to the numbers the functions list shows
    //     (same maps, same definition — see DeepAnalysis.h);
    //   xrefsIn / xrefsOut  — one row per reference SITE, which is what the
    //     sheet lists: xrefsIn covers every call or jump landing anywhere in
    //     this function's body, xrefsOut every call instruction in it. Several
    //     sites in one caller are several rows here and one edge there, so
    //     these numbers legitimately differ from the degrees above; they are
    //     never two answers to the same question.
    // Both arrays are capped for the sheet; xrefsInTotal / xrefsOutTotal give
    // the real count so the UI can render "64 of 312" instead of "312".
    {
        auto ce = c.cg.callees.find(fn->addr);
        auto cr = c.cg.callers.find(fn->addr);
        out << ",\"nCallees\":" << (ce == c.cg.callees.end() ? 0 : int(ce->second.size()))
            << ",\"nCallers\":" << (cr == c.cg.callers.end() ? 0 : int(cr->second.size()));
    }

    {
        // c.xrefs is keyed by TARGET address, so the call sites that land in
        // this function are one contiguous range of it — no full-map scan.
        u64 lo = fn->addr, hi = fn->addr + std::max<u64>(fn->size, 4);
        size_t total = 0;
        std::vector<Xref> in;
        for (auto it = c.xrefs.lower_bound(lo); it != c.xrefs.end() && it->first < hi; ++it) {
            total += it->second.size();
            for (auto& x : it->second)
                if (in.size() < kXrefRowsInJson) in.push_back(x);
        }
        out << ",\"xrefsInTotal\":" << num(total) << ",\"xrefsIn\":[";
        for (size_t i = 0; i < in.size(); ++i) {
            if (i) out << ",";
            out << "{\"from\":" << hq(in[i].from) << ",\"to\":" << hq(in[i].to)
                << ",\"type\":" << q(in[i].type) << "}";
        }
        out << "]";
    }
    {
        size_t total = 0;
        std::vector<Xref> outs;
        for (auto& l : lines) {
            if ((c.arch == "ARM64" && l.mnem == "bl") || (c.arch.find("X86") == 0 && l.mnem == "call")) {
                size_t p2 = l.ops.find("0x");
                if (p2 != std::string::npos) {
                    u64 t = strtoull(l.ops.c_str() + p2 + 2, nullptr, 16);
                    if (t) {
                        ++total;
                        if (outs.size() < kXrefRowsInJson) outs.push_back(Xref{l.addr, t, "call"});
                    }
                }
            }
        }
        out << ",\"xrefsOutTotal\":" << num(total) << ",\"xrefsOut\":[";
        for (size_t i = 0; i < outs.size(); ++i) {
            if (i) out << ",";
            out << "{\"from\":" << hq(outs[i].from) << ",\"to\":" << hq(outs[i].to)
                << ",\"type\":" << q(outs[i].type) << "}";
        }
        out << "]";
    }
    out << "}";
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

    // Pass 1: which edges belong in the answer. `focus` keeps the edges that
    // touch that function; an edge's `from` is already the calling function's
    // start (DeepAnalysis.h), so this is a comparison, not a range search.
    u64 fa = focus;                       // the focus function's start address
    if (focus)
        for (auto& f : c.funcs)
            if (focus >= f.addr && focus < f.addr + std::max<u64>(f.size, 4)) { fa = f.addr; break; }
    std::vector<const CallEdge*> keep;
    for (auto& e : c.cg.edges) {
        if (focus && e.from != fa && e.to != fa) continue;
        keep.push_back(&e);
    }

    // The count is emitted before the array and is the count of everything
    // found, not of what fits: the old loop wrote its separator before testing
    // the cap, so a truncated graph also went out as a trailing comma.
    size_t shown = std::min<size_t>(keep.size(), kCallGraphEdgesInJson);
    out << "{\"ok\":true,\"focus\":\"" << hexAddr(focus) << "\""
        << ",\"edgesTotal\":" << num(keep.size())
        << ",\"funcsTotal\":" << num(c.funcs.size())
        << ",\"edges\":[";
    for (size_t i = 0; i < shown; ++i) {
        if (i) out << ",";
        const CallEdge& e = *keep[i];
        out << "{\"from\":" << hq(e.from) << ",\"to\":" << hq(e.to)
            << ",\"site\":" << hq(e.site) << ",\"sites\":" << e.sites
            << ",\"fromName\":" << q(e.fromName) << ",\"toName\":" << q(e.toName)
            << ",\"kind\":" << q(e.kind) << "}";
    }
    out << "],\"funcs\":[";
    size_t nf = std::min<size_t>(c.funcs.size(), kCallGraphFuncsInJson);
    for (size_t i = 0; i < nf; ++i) {
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

// --------------------------------------------------------------- emulate --
// Bind the emulator to the loaded image. Unlike the decompiler there is no
// second-best: if this fails the caller gets the reason, not a fallback.
bool Engine::ghidraEmuReady(Ctx& c, const std::string& path, std::string& why) {
    why.clear();
    if (!GhidraEmu::compiledIn()) { why = "this build has no p-code engine"; return false; }
    if (sleighDir_.empty()) { why = "no SLEIGH specifications installed"; return false; }
    if (c.bin.data.empty()) { why = "no image loaded"; return false; }
    if (c.fmt != Fmt::ELF && c.fmt != Fmt::PE) {
        why = "only ELF and PE images can be emulated";
        return false;
    }

    std::vector<GhidraSeg> segs;
    if (c.fmt == Fmt::ELF) {
        for (auto& sg : c.elf.segments)
            if (sg.type == "LOAD" && sg.filesz)
                segs.push_back({sg.vaddr, sg.offset, sg.filesz,
                                sg.memsz ? sg.memsz : sg.filesz,
                                sg.flags.find('W') != std::string::npos});
    } else {
        for (auto& sc : c.pe.sections)
            if (sc.size)
                segs.push_back({sc.addr, sc.offset, sc.size, sc.size,
                                sc.flags.find('W') != std::string::npos});
    }
    if (segs.empty())
        segs.push_back({0, 0, u64(c.bin.data.size()), u64(c.bin.data.size()), true});

    // What must not be executed. A PLT entry in a shared library jumps
    // through a GOT slot the loader has not filled in, so running it would
    // branch to whatever the file happens to hold there — usually zero.
    std::vector<std::pair<u64, std::string>> stubs;
    for (auto& kv : c.elf.pltNames)
        if (kv.first && !kv.second.empty()) stubs.push_back({kv.first, kv.second});

    std::string err;
    if (!GhidraEmu::instance().open(path, c.arch, c.bin.data.data(), c.bin.data.size(),
                                    segs, stubs, c.elf.armMapping, err)) {
        why = err.empty() ? "could not build the architecture" : err;
        return false;
    }
    return true;
}

namespace {

// The request format is the flat one every other JSON command in this engine
// uses, so the same MiniJson parses it. Lists are ';'-separated because a
// nested parser would be the only nested parser in the file.
std::vector<std::string> splitSemi(const std::string& v) {
    std::vector<std::string> out;
    size_t at = 0;
    while (at <= v.size()) {
        size_t n = v.find(';', at);
        std::string tok = (n == std::string::npos) ? v.substr(at) : v.substr(at, n - at);
        while (!tok.empty() && (tok.front() == ' ' || tok.front() == '\t')) tok.erase(tok.begin());
        while (!tok.empty() && (tok.back() == ' ' || tok.back() == '\t')) tok.pop_back();
        if (!tok.empty()) out.push_back(tok);
        if (n == std::string::npos) break;
        at = n + 1;
    }
    return out;
}

std::vector<u8> fromHex(const std::string& h) {
    std::vector<u8> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(u8(strtoul(h.substr(i, 2).c_str(), nullptr, 16)));
    return out;
}

u64 parseAddr(const std::string& v) {
    if (v.rfind("0x", 0) == 0 || v.rfind("0X", 0) == 0)
        return strtoull(v.c_str() + 2, nullptr, 16);
    return strtoull(v.c_str(), nullptr, 0);
}

std::string bytesHex(const std::vector<u8>& b) {
    std::string out;
    char h[3];
    for (u8 c : b) { snprintf(h, sizeof h, "%02x", c); out += h; }
    return out;
}

// The same bytes as text, so the panel does not have to decode hex to see
// that a decrypt worked.
std::string bytesText(const std::vector<u8>& b) {
    std::string out;
    for (u8 c : b) out += (c >= 0x20 && c < 0x7F) ? char(c) : '.';
    return out;
}

// The longest run of printable bytes in a block, and where it starts. This is
// the answer to "did this function decrypt a string", and it is computed here
// rather than in the plugin because NocturneScript has no substring operator:
// a script can ask whether a byte is printable but cannot cut the run out.
std::string bytesBestRun(const std::vector<u8>& b, size_t* startOut = nullptr) {
    size_t best = 0, bestAt = 0, run = 0, at = 0;
    for (size_t i = 0; i < b.size(); ++i) {
        if (b[i] >= 0x20 && b[i] < 0x7F) {
            if (run == 0) at = i;
            if (++run > best) { best = run; bestAt = at; }
        } else run = 0;
    }
    if (startOut) *startOut = bestAt;
    return best ? std::string((const char*)b.data() + bestAt, best) : std::string();
}

// One emulator argument in the flat text form the JSON API already uses:
//   42 / 0x2a   a scalar
//   buf:256     allocate 256 zeroed bytes, pass the address
//   str:TEXT    allocate a NUL-terminated copy of TEXT, pass the address
//   hex:AABB    allocate those bytes, pass the address
// Shared by Engine::emulate and by the script builtin so there is one spelling
// of an argument in this engine, not two.
EmuArg parseEmuArg(const std::string& a) {
    EmuArg arg;
    if (a.rfind("buf:", 0) == 0) {
        arg.kind = EmuArg::Buffer;
        arg.len = u32(strtoul(a.c_str() + 4, nullptr, 0));
        if (arg.len > 65536) arg.len = 65536;
    } else if (a.rfind("hex:", 0) == 0) {
        arg.kind = EmuArg::Data;
        arg.data = fromHex(a.substr(4));
    } else if (a.rfind("str:", 0) == 0) {
        arg.kind = EmuArg::Data;
        for (size_t k = 4; k < a.size(); ++k) arg.data.push_back(u8(a[k]));
        arg.data.push_back(0);
    } else {
        arg.kind = EmuArg::Value;
        arg.value = parseAddr(a);
    }
    return arg;
}

// Shannon entropy of a byte range, in bits per byte. Eight is incompressible
// — packed, encrypted or already-compressed; a normal .text sits near six and
// English .rodata near four and a half.
double byteEntropy(const u8* p, size_t n) {
    if (!p || n == 0) return 0;
    u64 hist[256] = {0};
    for (size_t i = 0; i < n; ++i) hist[p[i]]++;
    double h = 0;
    for (int i = 0; i < 256; ++i) {
        if (!hist[i]) continue;
        double pr = double(hist[i]) / double(n);
        h -= pr * (std::log(pr) / std::log(2.0));
    }
    return h;
}

} // namespace

std::string Engine::emulate(const std::string& path, const std::string& reqJson) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureCtx(path);
    Ctx& c = ctx_;
    std::ostringstream out;

    MiniJson j = MiniJson::parse(reqJson);

    std::string why;
    if (!ghidraEmuReady(c, path, why)) {
        out << "{\"ok\":false,\"stop\":\"setup\",\"detail\":" << q(why) << "}";
        return out.str();
    }

    EmuRequest req;
    req.entry = j.num("entry");
    if (req.entry == 0) {
        out << "{\"ok\":false,\"stop\":\"setup\",\"detail\":\"no entry address\"}";
        return out.str();
    }
    req.stopAt = j.num("stopAt");
    if (j.has("maxInstr"))  req.limits.maxInstructions = j.num("maxInstr");
    if (j.has("timeoutMs")) req.limits.timeoutMs = u32(j.num("timeoutMs"));
    if (j.has("maxPages"))  req.limits.maxPages = u32(j.num("maxPages"));
    if (j.has("maxCalls"))  req.limits.maxCalls = u32(j.num("maxCalls"));
    req.limits.strictUserops = j.num("strictUserops", 0) != 0;

    for (const std::string& a : splitSemi(j.str("args"))) {
        req.args.push_back(parseEmuArg(a));
        if (req.args.size() >= 16) break;
    }
    for (const std::string& r : splitSemi(j.str("regs"))) {
        size_t eq = r.find('=');
        if (eq == std::string::npos) continue;
        req.regs.push_back({r.substr(0, eq), parseAddr(r.substr(eq + 1))});
    }
    for (const std::string& w : splitSemi(j.str("write"))) {
        size_t eq = w.find('=');
        if (eq == std::string::npos) continue;
        EmuBytes b;
        b.addr = parseAddr(w.substr(0, eq));
        b.bytes = fromHex(w.substr(eq + 1));
        if (!b.bytes.empty()) req.seeds.push_back(b);
    }
    for (const std::string& r : splitSemi(j.str("read"))) {
        size_t colon = r.rfind(':');
        if (colon == std::string::npos) continue;
        req.windows.push_back({parseAddr(r.substr(0, colon)),
                               u32(strtoul(r.c_str() + colon + 1, nullptr, 0))});
    }

    EmuResult r = GhidraEmu::instance().run(req);

    // A name for the entry, so the panel does not have to look it up again.
    std::string fname;
    for (auto& f : c.funcs) if (f.addr == req.entry) { fname = f.name; break; }
    if (fname.empty()) {
        auto it = c.elf.pltNames.find(req.entry);
        if (it != c.elf.pltNames.end()) fname = it->second;
    }

    out << "{\"ok\":" << (r.ok ? "true" : "false")
        << ",\"stop\":" << q(emuStopName(r.stop))
        << ",\"detail\":" << q(r.detail)
        << ",\"approximate\":" << (r.approximate ? "true" : "false")
        << ",\"entry\":" << hq(r.entry)
        << ",\"name\":" << q(fname)
        << ",\"instructions\":" << num(r.instructions)
        << ",\"ms\":" << int(r.ms + 0.5)
        << ",\"backend\":" << q(r.backend)
        << ",\"retReg\":" << q(r.retReg)
        << ",\"ret\":" << hq(r.ret)
        << ",\"stackBase\":" << hq(r.stackBase)
        << ",\"heapBase\":" << hq(r.heapBase)
        << ",\"heapUsed\":" << num(r.heapUsed)
        << ",\"limits\":{\"maxInstr\":" << num(req.limits.maxInstructions)
        << ",\"timeoutMs\":" << req.limits.timeoutMs
        << ",\"maxPages\":" << req.limits.maxPages
        << ",\"maxCalls\":" << req.limits.maxCalls << "}"
        << ",\"regs\":[";
    for (size_t i = 0; i < r.regs.size(); ++i) {
        if (i) out << ",";
        out << "{\"n\":" << q(r.regs[i].first) << ",\"v\":" << hq(r.regs[i].second) << "}";
    }
    out << "],\"args\":[";
    for (size_t i = 0; i < r.args.size(); ++i) {
        if (i) out << ",";
        const EmuArg& a = r.args[i];
        out << "{\"i\":" << i << ",\"reg\":" << q(a.reg)
            << ",\"v\":" << hq(a.value)
            << ",\"kind\":" << q(a.kind == EmuArg::Buffer ? "buffer"
                               : a.kind == EmuArg::Data   ? "data" : "value")
            << ",\"len\":" << a.len << "}";
    }
    out << "],\"memory\":[";
    for (size_t i = 0; i < r.memory.size(); ++i) {
        if (i) out << ",";
        out << "{\"addr\":" << hq(r.memory[i].addr)
            << ",\"label\":" << q(r.memory[i].label)
            << ",\"len\":" << r.memory[i].bytes.size()
            << ",\"data\":" << q(bytesHex(r.memory[i].bytes))
            << ",\"text\":" << q(bytesText(r.memory[i].bytes)) << "}";
    }
    out << "],\"dirtyBytes\":" << num(r.dirtyBytes)
        << ",\"dirtyRanges\":" << r.dirtyRanges
        << ",\"memoryTruncated\":" << (r.memoryTruncated ? "true" : "false")
        << ",\"callsTotal\":" << num(r.callsTotal)
        << ",\"calls\":[";
    for (size_t i = 0; i < r.calls.size(); ++i) {
        if (i) out << ",";
        const EmuCall& cc = r.calls[i];
        out << "{\"n\":" << q(cc.name) << ",\"at\":" << hq(cc.site)
            << ",\"ret\":" << hq(cc.ret)
            << ",\"modelled\":" << (cc.modelled ? "true" : "false")
            << ",\"note\":" << q(cc.note) << ",\"args\":[";
        for (size_t k = 0; k < cc.args.size(); ++k) {
            if (k) out << ",";
            out << hq(cc.args[k]);
        }
        out << "]}";
    }
    out << "],\"userops\":[";
    for (size_t i = 0; i < r.userops.size(); ++i) {
        if (i) out << ",";
        out << "{\"n\":" << q(r.userops[i].name) << ",\"count\":" << r.userops[i].count
            << ",\"harmless\":" << (r.userops[i].harmless ? "true" : "false") << "}";
    }
    out << "],\"tail\":[";
    for (size_t i = 0; i < r.tail.size(); ++i) {
        if (i) out << ",";
        out << hq(r.tail[i]);
    }
    out << "]}";
    return out.str();
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
        // An undefined dynsym has st_value 0, so `addr` was 0 for every import
        // of every shared library and count_xrefs_to(imp.addr) answered 0 for
        // all of them — attack-surface reported "0 call sites" 13 times in a
        // row on a library that calls mmap. The address a call to an import
        // actually reaches is its PLT stub; that is what the xref map is keyed
        // by, so that is what `addr` has to be when the symbol has none.
        u64 plt = 0;
        if (c.fmt == Fmt::ELF) {
            const std::string& want = (*v)[i].name;
            for (auto& kv : c.elf.pltNames)
                if (kv.second == want) { plt = kv.first; break; }
        }
        auto o = std::make_shared<ScriptObj>();
        (*o)["name"] = ScriptValue::ofStr((*v)[i].name);
        (*o)["addr"] = ScriptValue::ofNum(double((*v)[i].addr ? (*v)[i].addr : plt));
        (*o)["plt"]  = ScriptValue::ofNum(double(plt));
        (*o)["sym"]  = ScriptValue::ofNum(double((*v)[i].addr));
        return ScriptValue::ofObj(o);
    });
    script.setBuiltin("demangle", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        return ScriptValue::ofStr(a.empty() ? "" : demangle(a[0].str));
    });
    script.setBuiltin("classify", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        const char* r = a.empty() ? nullptr : classifyImport(a[0].str);
        return r ? ScriptValue::ofStr(r) : ScriptValue::nil();
    });
    // The xref map holds code references and, since data references were added
    // to it, data ones too. These two default to CODE references only, because
    // ten plugins were written when that was all the map held and "how many
    // callers does this function have" must not start counting vtable slots
    // underneath them. An explicit kind — "call", "jmp", "data", "code",
    // "any" — selects otherwise.
    auto xrefKind = [](const std::vector<ScriptValue>& a, size_t idx) {
        std::string k = a.size() > idx ? a[idx].str : std::string();
        return k.empty() ? std::string("code") : k;
    };
    auto xrefWanted = [](const Xref& x, const std::string& kind) {
        if (kind == "any") return true;
        if (kind == "code") return x.type != "data";
        return x.type == kind;
    };
    script.setBuiltin("count_xrefs_to", [&, xrefKind, xrefWanted]
                      (const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.empty()) return ScriptValue::ofNum(0);
        auto it = c.xrefs.find(u64(a[0].num));
        if (it == c.xrefs.end()) return ScriptValue::ofNum(0);
        std::string kind = xrefKind(a, 1);
        size_t n = 0;
        for (auto& x : it->second) if (xrefWanted(x, kind)) ++n;
        return ScriptValue::ofNum(double(n));
    });
    script.setBuiltin("xref_to_at", [&, xrefKind, xrefWanted]
                      (const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::nil();
        auto it = c.xrefs.find(u64(a[0].num));
        if (it == c.xrefs.end()) return ScriptValue::nil();
        std::string kind = xrefKind(a, 2);
        size_t want = size_t(a[1].num), seen = 0;
        for (auto& x : it->second) {
            if (!xrefWanted(x, kind)) continue;
            if (seen++ != want) continue;
            auto o = std::make_shared<ScriptObj>();
            (*o)["from"] = ScriptValue::ofNum(double(x.from));
            (*o)["type"] = ScriptValue::ofStr(x.type);
            return ScriptValue::ofObj(o);
        }
        return ScriptValue::nil();
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
        // hexAddr already writes the 0x prefix. Adding a second one made every
        // address a plugin has ever logged read "0x0x2630C".
        if (a.empty()) return ScriptValue::ofStr("0x0");
        return ScriptValue::ofStr(hexAddr(u64(a[0].num)));
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

    // ------------------------------------------------------------------
    // Everything below is what the engine knows and a plugin could not see.
    // All of it follows the one convention the language forces: with no
    // arrays, a list is count_X() plus X_at(i), never a value.
    // ------------------------------------------------------------------

    auto funcObj = [](const FuncInfo& f) {
        auto o = std::make_shared<ScriptObj>();
        (*o)["addr"] = ScriptValue::ofNum(double(f.addr));
        (*o)["size"] = ScriptValue::ofNum(double(f.size));
        (*o)["name"] = ScriptValue::ofStr(f.name);
        (*o)["from"] = ScriptValue::ofStr(f.from);
        return ScriptValue::ofObj(o);
    };

    // Which function is this address inside? A plugin gets instruction
    // addresses from xref_to_at and had no way to turn one into a function
    // without scanning all 1,319 in the script — 1.7 million interpreter
    // steps for one lookup, which is why no existing plugin tries.
    //
    // Built once per run and binary-searched: a linear scan here is O(n) per
    // lookup, and the obfuscation profiler does one lookup per function, so on
    // a library with 4,000 functions that is 16 million comparisons and the
    // plugin took 16 seconds. Sorted, it takes 0.9.
    // Indices, not pointers: functionDetail appends a synthetic FuncInfo to
    // c.funcs when it is asked about an address no symbol covers, and it holds
    // a different lock than this does. An index survives that reallocation; a
    // pointer into the vector would not.
    auto byAddr = std::make_shared<std::vector<std::pair<u64, size_t>>>();
    byAddr->reserve(c.funcs.size());
    for (size_t i = 0; i < c.funcs.size(); ++i) byAddr->push_back({c.funcs[i].addr, i});
    std::sort(byAddr->begin(), byAddr->end());
    auto containing = [&c, byAddr](u64 addr) -> const FuncInfo* {
        // The last function whose start is <= addr.
        auto it = std::upper_bound(byAddr->begin(), byAddr->end(), addr,
                                   [](u64 v, const std::pair<u64, size_t>& e) {
                                       return v < e.first;
                                   });
        if (it == byAddr->begin()) return nullptr;
        size_t idx = (it - 1)->second;
        if (idx >= c.funcs.size()) return nullptr;
        const FuncInfo& f = c.funcs[idx];
        if (f.addr != (it - 1)->first) return nullptr;   // the list moved under us
        if (f.size ? (addr < f.addr + f.size) : (addr == f.addr)) return &f;
        return nullptr;
    };
    script.setBuiltin("func_containing", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.empty()) return ScriptValue::nil();
        const FuncInfo* f = containing(u64(a[0].num));
        return f ? funcObj(*f) : ScriptValue::nil();
    });

    // Where does this exact byte sequence sit in the image? Zero for "nowhere".
    // The point is the zero. A string the emulator hands back is only a
    // *recovered* string if it is not in the file already — otherwise the code
    // copied it out of .rodata and the run proved nothing. That test was done
    // by hand with grep when the emulator landed; this is the same test, one
    // memmem instead of 3,000 interpreter-level string compares.
    script.setBuiltin("find_bytes", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.empty()) return ScriptValue::ofNum(0);
        const std::string& needle = a[0].str;
        if (needle.empty() || needle.size() > c.bin.data.size()) return ScriptValue::ofNum(0);
        const u8* hay = c.bin.data.data();
        size_t n = c.bin.data.size(), m = needle.size();
        // Spelled out rather than memmem(): that is a GNU/BSD extension, and
        // this file is compiled against three libcs.
        size_t at = std::string::npos;
        for (size_t i = 0; i + m <= n; ++i)
            if (hay[i] == u8(needle[0]) && memcmp(hay + i, needle.data(), m) == 0) { at = i; break; }
        if (at == std::string::npos) return ScriptValue::ofNum(0);
        u64 off = u64(at);
        // Report a virtual address when one exists, so it lines up with every
        // other address a plugin sees; fall back to the file offset.
        if (c.fmt == Fmt::ELF) {
            for (auto& sg : c.elf.segments)
                if (sg.type == "LOAD" && off >= sg.offset && off < sg.offset + sg.filesz)
                    return ScriptValue::ofNum(double(sg.vaddr + (off - sg.offset)));
        }
        return ScriptValue::ofNum(double(off));
    });

    // ---- sections ----------------------------------------------------
    const std::vector<Section>* secs = c.fmt == Fmt::ELF ? &c.elf.sections
                                     : c.fmt == Fmt::PE  ? &c.pe.sections : nullptr;
    script.setBuiltin("count_sections", [&](const std::vector<ScriptValue>&) -> ScriptValue {
        return ScriptValue::ofNum(secs ? double(secs->size()) : 0);
    });
    script.setBuiltin("section_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        size_t i = size_t(a.empty() ? 0 : a[0].num);
        if (!secs || i >= secs->size()) return ScriptValue::nil();
        const Section& s = (*secs)[i];
        auto o = std::make_shared<ScriptObj>();
        (*o)["name"]   = ScriptValue::ofStr(s.name);
        (*o)["type"]   = ScriptValue::ofStr(s.type);
        (*o)["flags"]  = ScriptValue::ofStr(s.flags);
        (*o)["addr"]   = ScriptValue::ofNum(double(s.addr));
        (*o)["offset"] = ScriptValue::ofNum(double(s.offset));
        (*o)["size"]   = ScriptValue::ofNum(double(s.size));
        // What the loader will actually map this as. Section flags are a
        // linker's opinion; the PT_LOAD that covers the section is what the
        // kernel honours, and a plugin that says ".rodata is writable" has to
        // be reading the second one to be telling the truth.
        std::string perm = "?";
        if (c.fmt == Fmt::ELF && s.addr) {
            for (auto& sg : c.elf.segments) {
                if (sg.type != "LOAD" || !sg.memsz) continue;
                if (s.addr < sg.vaddr || s.addr >= sg.vaddr + sg.memsz) continue;
                perm.clear();
                perm += sg.flags.find('R') != std::string::npos ? 'r' : '-';
                perm += sg.flags.find('W') != std::string::npos ? 'w' : '-';
                perm += sg.flags.find('X') != std::string::npos ? 'x' : '-';
                break;
            }
        }
        (*o)["perm"] = ScriptValue::ofStr(perm);
        // Entropy needs a 256-bucket histogram. The language has no arrays, so
        // this is one of the numbers a plugin can only be given.
        double ent = 0;
        if (s.type != "NOBITS" && s.size && s.offset + s.size <= c.bin.data.size())
            ent = byteEntropy(c.bin.data.data() + s.offset, size_t(s.size));
        (*o)["entropy"] = ScriptValue::ofNum(ent);
        return ScriptValue::ofObj(o);
    });

    // ---- exports -----------------------------------------------------
    // The dynamic exports are the boundary: on a JNI library they are
    // JNI_OnLoad and the Java_* methods, and they are the only addresses
    // something outside this file can call. They cannot be read off func_at:
    // an export that also has a symtab entry is recorded as "symtab", so on
    // libanort.so all three exports report from="symtab" and a plugin looking
    // for from=="export" finds nothing.
    const std::vector<Symbol>* exps = c.fmt == Fmt::ELF ? &c.elf.exports
                                    : c.fmt == Fmt::PE  ? &c.pe.exports : nullptr;
    script.setBuiltin("count_exports", [&](const std::vector<ScriptValue>&) -> ScriptValue {
        return ScriptValue::ofNum(exps ? double(exps->size()) : 0);
    });
    script.setBuiltin("export_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        size_t i = size_t(a.empty() ? 0 : a[0].num);
        if (!exps || i >= exps->size()) return ScriptValue::nil();
        auto o = std::make_shared<ScriptObj>();
        (*o)["name"] = ScriptValue::ofStr((*exps)[i].name);
        (*o)["addr"] = ScriptValue::ofNum(double((*exps)[i].addr));
        (*o)["size"] = ScriptValue::ofNum(double((*exps)[i].size));
        (*o)["kind"] = ScriptValue::ofStr((*exps)[i].kind);
        return ScriptValue::ofObj(o);
    });

    // ---- DT_NEEDED ---------------------------------------------------
    script.setBuiltin("count_needed", [&](const std::vector<ScriptValue>&) -> ScriptValue {
        return ScriptValue::ofNum(c.fmt == Fmt::ELF ? double(c.elf.needed.size()) : 0);
    });
    script.setBuiltin("needed_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        size_t i = size_t(a.empty() ? 0 : a[0].num);
        if (c.fmt != Fmt::ELF || i >= c.elf.needed.size()) return ScriptValue::nil();
        return ScriptValue::ofStr(c.elf.needed[i]);
    });

    // ---- xrefs OUT ---------------------------------------------------
    // count_xrefs_to/xref_to_at answer "who calls this". Nothing answered
    // "what does this call", so no plugin could follow an edge forwards --
    // which is the direction reachability runs in.
    auto calleesOf = [&](u64 addr) -> const std::vector<u64>* {
        auto it = c.cg.callees.find(addr);
        return it == c.cg.callees.end() ? nullptr : &it->second;
    };
    script.setBuiltin("count_callees", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.empty()) return ScriptValue::ofNum(0);
        auto* v = calleesOf(u64(a[0].num));
        return ScriptValue::ofNum(v ? double(v->size()) : 0);
    });
    script.setBuiltin("callee_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::nil();
        u64 from = u64(a[0].num);
        auto* v = calleesOf(from);
        size_t i = size_t(a[1].num);
        if (!v || i >= v->size()) return ScriptValue::nil();
        u64 to = (*v)[i];
        auto o = std::make_shared<ScriptObj>();
        (*o)["addr"] = ScriptValue::ofNum(double(to));
        std::string nm = c.names.lookup(to);
        std::string kind = "unknown";
        u32 sites = 0;
        for (auto& e : c.cg.edges) {
            if (e.from != from || e.to != to) continue;
            kind = e.kind;
            sites = e.sites;
            if (!e.toName.empty()) nm = e.toName;
            break;
        }
        (*o)["name"]  = ScriptValue::ofStr(nm);
        (*o)["kind"]  = ScriptValue::ofStr(kind);
        (*o)["sites"] = ScriptValue::ofNum(double(sites));
        return ScriptValue::ofObj(o);
    });

    // Can `from` reach `to` through the call graph, and in how few hops?
    // Returns the hop count, 0 for the same function, -1 for no path.
    //
    // This one is here because the language cannot express it. A search needs
    // a worklist and a visited set; NocturneScript has neither, and a
    // depth-limited recursion without a visited set re-walks a diamond
    // exponentially — on a graph with 5,203 edges that is not a slow plugin,
    // it is a plugin that never returns. Bounded here at 20,000 expansions so
    // one call stays microseconds whatever the graph looks like.
    script.setBuiltin("reaches", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::ofNum(-1);
        u64 from = u64(a[0].num), to = u64(a[1].num);
        if (from == to) return ScriptValue::ofNum(0);
        if (!from || !to) return ScriptValue::ofNum(-1);
        std::map<u64, int> depth;
        std::vector<u64> frontier{from}, next;
        depth[from] = 0;
        int d = 0, expansions = 0;
        const int kMaxExpansions = 20000;
        while (!frontier.empty() && expansions < kMaxExpansions) {
            ++d;
            next.clear();
            for (u64 f : frontier) {
                auto it = c.cg.callees.find(f);
                if (it == c.cg.callees.end()) continue;
                for (u64 t : it->second) {
                    if (++expansions > kMaxExpansions) break;
                    if (t == to) return ScriptValue::ofNum(double(d));
                    if (depth.emplace(t, d).second) next.push_back(t);
                }
            }
            frontier.swap(next);
        }
        return ScriptValue::ofNum(-1);
    });

    // ---- disassembly -------------------------------------------------
    // The instruction stream, with the same auto-comments the Assembly tab
    // shows -- which is the point: autoComment resolves adrp+add pairs to the
    // string they build, so a plugin can see that an instruction loads
    // "/proc/self/status" without doing pointer arithmetic it has no
    // arithmetic for.
    // Comments are applied lazily, because autoComment() rebuilds an
    // address->string map of the whole binary on every call. insn_stats never
    // looks at a comment, and profiling a 17 MB library is 4,000 calls: with
    // the comments eager that was 16 seconds, of which 15 were rebuilding the
    // same 20,000-entry map 4,000 times.
    struct InsnCache { u64 fn = ~u64(0); u64 end = 0; bool commented = false;
                       std::vector<AsmLine> lines; };
    auto icache = std::make_shared<InsnCache>();
    // Built on first use of a commented listing, not at start-up: most plugins
    // never ask for one, and on a 17 MB library this is 20,000 entries.
    auto refFrom = std::make_shared<std::map<u64, u64>>();
    auto strAt   = std::make_shared<std::map<u64, std::string>>();
    auto linesFor = [&, icache, containing, refFrom, strAt](u64 addr, bool withComments)
                        -> const std::vector<AsmLine>* {
        const FuncInfo* f = containing(addr);
        if (!f || c.backend.empty()) return nullptr;
        if (icache->fn != f->addr) {
            u64 off = vaToOff(c, f->addr);
            if (off == ~u64(0) || off >= c.bin.data.size()) return nullptr;
            u64 size = std::min<u64>(f->size ? f->size : 512, 65536);
            size = std::min<u64>(size, u64(c.bin.data.size()) - off);
            if (c.dis.armDualMode()) c.dis.setDefaultThumb(f->thumb);
            icache->lines = c.dis.disassemble(c.bin.data.data() + off, size_t(size), f->addr, 4096);
            icache->fn = f->addr;
            icache->end = f->addr + size;
            icache->commented = false;
        }
        if (withComments && !icache->commented) {
            autoComment(c.arch, icache->lines, c.names, c.strings, icache->fn, icache->end);
            // Fill in what autoComment left blank from the xref map, which is
            // now the one place a data reference is recorded. Two payoffs: the
            // answers agree by construction — an instruction is commented with
            // a string exactly when count_xrefs_to on that string counts it —
            // and the ADRP+ADD pairs autoComment's operand parsing misses
            // (it reads the '#' of "#0x6d4" as the start of the number and
            // resolves the offset to 0) stop being invisible.
            if (refFrom->empty() && !c.xrefs.empty()) {
                for (auto& kv : c.xrefs)
                    for (auto& x : kv.second)
                        if (x.type == "data") refFrom->emplace(x.from, x.to);
                for (auto& s : c.strings) strAt->emplace(s.addr, s.value);
            }
            for (AsmLine& l : icache->lines) {
                if (!l.comment.empty()) continue;
                auto it = refFrom->find(l.addr);
                if (it == refFrom->end()) continue;
                auto sit = strAt->find(it->second);
                if (sit != strAt->end())
                    l.comment = "\"" + sit->second.substr(0, 64) + "\"";
                else {
                    std::string nm = c.names.lookup(it->second);
                    if (!nm.empty()) l.comment = nm;
                }
            }
            icache->commented = true;
        }
        return &icache->lines;
    };
    script.setBuiltin("count_insns", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.empty()) return ScriptValue::ofNum(0);
        auto* l = linesFor(u64(a[0].num), false);
        return ScriptValue::ofNum(l ? double(l->size()) : 0);
    });
    // The instruction mix of one function, in one pass of C++.
    //
    // A plugin can already walk insn_at and compare mnemonics, and the first
    // version of the obfuscation profiler did: 272,898 instructions times ten
    // string compares each is 2.7 million interpreter steps, and it took 16.3
    // seconds to profile libanort.so. The same counters here take 0.6. That is
    // the whole justification -- and a second one comes free: these are
    // CATEGORIES, not mnemonics, so a plugin written against them says
    // something true about an x86 binary as well as an ARM one, which a script
    // full of `m == "movk"` never can.
    //
    // distinct_imm is the interesting one and the reason this is not just a
    // histogram: it counts how many DIFFERENT constants a function builds in
    // registers. Control-flow flattening gives every basic block a random
    // 32-bit state number, and on AArch64 a 32-bit constant cannot be an
    // operand -- it has to be assembled with movz+movk. So a flattened
    // function materialises dozens of unrelated constants, and an ordinary one
    // materialises a handful.
    script.setBuiltin("insn_stats", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.empty()) return ScriptValue::nil();
        auto* lines = linesFor(u64(a[0].num), false);
        if (!lines) return ScriptValue::nil();
        u64 movimm = 0, pcrel = 0, cmp = 0, cbranch = 0, branch = 0, call = 0,
            indirect = 0, ret = 0, nop = 0, other = 0;
        std::map<u64, int> imms;
        for (const AsmLine& l : *lines) {
            std::string m;
            for (char ch : l.mnem) m += char(tolower((unsigned char)ch));
            const std::string& o = l.ops;
            auto immOf = [&]() -> bool {
                size_t h = o.find('#');
                if (h == std::string::npos) return false;
                u64 v = (o.compare(h + 1, 2, "0x") == 0)
                            ? strtoull(o.c_str() + h + 3, nullptr, 16)
                            : strtoull(o.c_str() + h + 1, nullptr, 10);
                if (imms.size() < 4096) imms[v]++;
                return true;
            };
            bool armMovImm = (m == "movz" || m == "movk" || m == "movn" ||
                              m == "movw" || m == "movt" ||
                              ((m == "mov" || m == "movi") && o.find('#') != std::string::npos));
            bool x86MovImm = (m == "mov" || m == "movl" || m == "movq" || m == "movabs") &&
                             o.find("0x") != std::string::npos && o.find('[') == std::string::npos;
            if (armMovImm)      { ++movimm; immOf(); }
            else if (x86MovImm) { ++movimm;
                                  size_t h = o.find("0x");
                                  u64 v = strtoull(o.c_str() + h + 2, nullptr, 16);
                                  if (imms.size() < 4096) imms[v]++; }
            else if (m == "adrp" || m == "adr" || m == "adrl") ++pcrel;
            else if (m == "lea" && o.find("rip") != std::string::npos) ++pcrel;
            else if (m == "cmp" || m == "cmn" || m == "tst" || m == "teq" ||
                     m == "test" || m == "cmpl" || m == "cmpq" || m == "cmpw") ++cmp;
            else if (m.rfind("b.", 0) == 0 || m == "cbz" || m == "cbnz" ||
                     m == "tbz" || m == "tbnz" ||
                     (m.size() > 1 && m[0] == 'j' && m != "jmp" && m != "jmpq")) ++cbranch;
            else if (m == "br" || m == "blr" || m == "bx" || m == "blx") ++indirect;
            else if ((m == "jmp" || m == "jmpq" || m == "call" || m == "callq") &&
                     o.find("0x") == std::string::npos) ++indirect;
            else if (m == "bl" || m == "call" || m == "callq") ++call;
            else if (m == "b" || m == "jmp" || m == "jmpq") ++branch;
            else if (m == "ret" || m == "retq" || m == "eret") ++ret;
            else if (m == "nop" || m == "hint") ++nop;
            else ++other;
        }
        auto o = std::make_shared<ScriptObj>();
        (*o)["n"]            = ScriptValue::ofNum(double(lines->size()));
        (*o)["movimm"]       = ScriptValue::ofNum(double(movimm));
        (*o)["distinct_imm"] = ScriptValue::ofNum(double(imms.size()));
        (*o)["pcrel"]        = ScriptValue::ofNum(double(pcrel));
        (*o)["cmp"]          = ScriptValue::ofNum(double(cmp));
        (*o)["cbranch"]      = ScriptValue::ofNum(double(cbranch));
        (*o)["branch"]       = ScriptValue::ofNum(double(branch));
        (*o)["call"]         = ScriptValue::ofNum(double(call));
        (*o)["indirect"]     = ScriptValue::ofNum(double(indirect));
        (*o)["ret"]          = ScriptValue::ofNum(double(ret));
        (*o)["nop"]          = ScriptValue::ofNum(double(nop));
        (*o)["other"]        = ScriptValue::ofNum(double(other));
        return ScriptValue::ofObj(o);
    });

    script.setBuiltin("insn_at", [&](const std::vector<ScriptValue>& a) -> ScriptValue {
        if (a.size() < 2) return ScriptValue::nil();
        auto* l = linesFor(u64(a[0].num), true);
        size_t i = size_t(a[1].num);
        if (!l || i >= l->size()) return ScriptValue::nil();
        const AsmLine& x = (*l)[i];
        auto o = std::make_shared<ScriptObj>();
        (*o)["addr"]    = ScriptValue::ofNum(double(x.addr));
        (*o)["mnem"]    = ScriptValue::ofStr(x.mnem);
        (*o)["ops"]     = ScriptValue::ofStr(x.ops);
        (*o)["bytes"]   = ScriptValue::ofStr(x.bytes);
        (*o)["comment"] = ScriptValue::ofStr(x.comment);
        return ScriptValue::ofObj(o);
    });

    // ---- the p-code emulator -----------------------------------------
    // The one call in the engine that executes the analysed binary's own
    // instructions, reached from a loop written by whoever wrote the plugin.
    // The panel runs one function because a person pressed a button; a plugin
    // runs 1,319 because a `for` said so, and the difference is the whole
    // safety argument. So a script gets:
    //
    //   * its own per-call defaults, an order tighter than the panel's
    //     (20k instructions / 250 ms / 256 pages / 512 stubbed calls),
    //   * a ceiling it cannot raise past (200k / 1000 ms), and
    //   * an aggregate budget across the whole run -- 20 seconds of emulation
    //     and 4096 runs. A full blind sweep of libanort.so is 1,319 runs in
    //     9.5 s, so the budget clears real work by 2x and still bounds the
    //     worst case: 1,319 hostile functions that each burn their 250 ms
    //     stop at 20 s, not at 5.5 minutes.
    //
    // Exhaustion is not an error and never a hang: emulate() returns
    // stop="budget" with the numbers in `detail`, so the plugin can say so.
    struct EmuScriptState {
        bool tried = false, ready = false;
        std::string why;
        int runs = 0;
        double msUsed = 0;
        EmuResult last;
        bool haveLast = false;
    };
    auto es = std::make_shared<EmuScriptState>();
    const u64 kEmuDefInstr = 20000, kEmuCeilInstr = 200000;
    const u32 kEmuDefMs = 250, kEmuCeilMs = 1000;
    const int kEmuMaxRuns = 4096;
    const double kEmuBudgetMs = 20000;

    script.setBuiltin("emulate", [&, es](const std::vector<ScriptValue>& a) -> ScriptValue {
        auto o = std::make_shared<ScriptObj>();
        auto fail = [&](const char* stop, const std::string& detail) {
            (*o)["ok"] = ScriptValue::ofBool(false);
            (*o)["stop"] = ScriptValue::ofStr(stop);
            (*o)["detail"] = ScriptValue::ofStr(detail);
            (*o)["ret"] = ScriptValue::ofNum(0);
            (*o)["instructions"] = ScriptValue::ofNum(0);
            (*o)["ms"] = ScriptValue::ofNum(0);
            (*o)["approximate"] = ScriptValue::ofBool(false);
            (*o)["writes"] = ScriptValue::ofNum(0);
            (*o)["calls"] = ScriptValue::ofNum(0);
            (*o)["runs"] = ScriptValue::ofNum(double(es->runs));
            (*o)["budget_left"] = ScriptValue::ofNum(kEmuBudgetMs - es->msUsed);
            es->haveLast = false;
            es->last = EmuResult();
            return ScriptValue::ofObj(o);
        };
        if (a.empty() || u64(a[0].num) == 0) return fail("setup", "no entry address");
        // "exhausted", not "budget": "budget" is already this emulator's word
        // for one run running out of instructions, and a plugin has to be
        // able to tell "this function is a loop" from "stop calling me".
        if (es->runs >= kEmuMaxRuns)
            return fail("exhausted", "this plugin has already emulated " +
                                     std::to_string(kEmuMaxRuns) + " times");
        if (es->msUsed >= kEmuBudgetMs) {
            std::ostringstream m;
            m << "this plugin has used its whole " << int(kEmuBudgetMs / 1000)
              << " s of emulation (" << es->runs << " runs)";
            return fail("exhausted", m.str());
        }

        std::lock_guard<std::mutex> elock(mutex_);
        auto t0 = std::chrono::steady_clock::now();
        if (!es->tried) {
            es->tried = true;
            es->ready = ghidraEmuReady(c, path, es->why);
            // Building the architecture parses the whole .sla. It is paid once
            // per run and it counts against the budget like anything else.
            es->msUsed += std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - t0).count();
        }
        if (!es->ready) return fail("setup", es->why.empty() ? "emulator unavailable" : es->why);

        EmuRequest req;
        req.entry = u64(a[0].num);
        for (const std::string& s : splitSemi(a.size() > 1 ? a[1].render() : std::string())) {
            req.args.push_back(parseEmuArg(s));
            if (req.args.size() >= 16) break;
        }
        req.limits.maxInstructions = kEmuDefInstr;
        req.limits.timeoutMs = kEmuDefMs;
        req.limits.maxPages = 256;
        req.limits.maxCalls = 512;
        if (a.size() > 2 && a[2].num > 0)
            req.limits.maxInstructions = std::min<u64>(u64(a[2].num), kEmuCeilInstr);
        if (a.size() > 3 && a[3].num > 0)
            req.limits.timeoutMs = std::min<u32>(u32(a[3].num), kEmuCeilMs);
        // Never let one call outlive what is left of the aggregate budget.
        double left = kEmuBudgetMs - es->msUsed;
        if (left < req.limits.timeoutMs) req.limits.timeoutMs = u32(left > 1 ? left : 1);

        auto t1 = std::chrono::steady_clock::now();
        EmuResult r = GhidraEmu::instance().run(req);
        es->msUsed += std::chrono::duration<double, std::milli>(
                          std::chrono::steady_clock::now() - t1).count();
        es->runs++;
        es->last = r;
        es->haveLast = true;

        (*o)["ok"] = ScriptValue::ofBool(r.ok);
        (*o)["stop"] = ScriptValue::ofStr(emuStopName(r.stop));
        (*o)["detail"] = ScriptValue::ofStr(r.detail);
        (*o)["ret"] = ScriptValue::ofNum(double(r.ret));
        (*o)["retreg"] = ScriptValue::ofStr(r.retReg);
        (*o)["instructions"] = ScriptValue::ofNum(double(r.instructions));
        (*o)["ms"] = ScriptValue::ofNum(r.ms);
        (*o)["approximate"] = ScriptValue::ofBool(r.approximate);
        (*o)["writes"] = ScriptValue::ofNum(double(r.memory.size()));
        (*o)["calls"] = ScriptValue::ofNum(double(r.calls.size()));
        (*o)["runs"] = ScriptValue::ofNum(double(es->runs));
        (*o)["budget_left"] = ScriptValue::ofNum(kEmuBudgetMs - es->msUsed);
        return ScriptValue::ofObj(o);
    });

    // What the last run wrote. Every range the guest actually changed, worked
    // out by diffing its dirty pages against the file, plus the buffers the
    // sandbox allocated for `buf:` arguments.
    script.setBuiltin("count_emu_writes", [&, es](const std::vector<ScriptValue>&) -> ScriptValue {
        return ScriptValue::ofNum(es->haveLast ? double(es->last.memory.size()) : 0);
    });
    script.setBuiltin("emu_write_at", [&, es](const std::vector<ScriptValue>& a) -> ScriptValue {
        size_t i = size_t(a.empty() ? 0 : a[0].num);
        if (!es->haveLast || i >= es->last.memory.size()) return ScriptValue::nil();
        const EmuBytes& m = es->last.memory[i];
        size_t at = 0;
        std::string best = bytesBestRun(m.bytes, &at);
        // `best` goes into a comment and a bookmark label. `bestlen` keeps the
        // true length, so a clamp here loses nothing a plugin can act on: a
        // 65 KiB buffer of repeated alphabet is one finding, not a label.
        const size_t kBestLabelCap = 192;
        std::string bestShown = best.size() > kBestLabelCap ? best.substr(0, kBestLabelCap) : best;
        auto o = std::make_shared<ScriptObj>();
        (*o)["addr"]    = ScriptValue::ofNum(double(m.addr));
        (*o)["label"]   = ScriptValue::ofStr(m.label);
        (*o)["len"]     = ScriptValue::ofNum(double(m.bytes.size()));
        (*o)["text"]    = ScriptValue::ofStr(bytesText(m.bytes));
        (*o)["hex"]     = ScriptValue::ofStr(bytesHex(m.bytes));
        (*o)["best"]    = ScriptValue::ofStr(bestShown);
        (*o)["bestlen"] = ScriptValue::ofNum(double(best.size()));
        (*o)["bestat"]  = ScriptValue::ofNum(double(m.addr + at));
        return ScriptValue::ofObj(o);
    });

    // What the last run called instead of executing: the import stubs it
    // entered, with the arguments the model looked at. This is how a plugin
    // tells a decrypt routine (malloc, memcpy) from a detector
    // (__system_property_get, fopen).
    script.setBuiltin("count_emu_calls", [&, es](const std::vector<ScriptValue>&) -> ScriptValue {
        return ScriptValue::ofNum(es->haveLast ? double(es->last.calls.size()) : 0);
    });
    script.setBuiltin("emu_call_at", [&, es](const std::vector<ScriptValue>& a) -> ScriptValue {
        size_t i = size_t(a.empty() ? 0 : a[0].num);
        if (!es->haveLast || i >= es->last.calls.size()) return ScriptValue::nil();
        const EmuCall& cc = es->last.calls[i];
        auto o = std::make_shared<ScriptObj>();
        (*o)["name"]      = ScriptValue::ofStr(cc.name);
        (*o)["at"]        = ScriptValue::ofNum(double(cc.site));
        (*o)["ret"]       = ScriptValue::ofNum(double(cc.ret));
        (*o)["modelled"]  = ScriptValue::ofBool(cc.modelled);
        (*o)["note"]      = ScriptValue::ofStr(cc.note);
        (*o)["nargs"]     = ScriptValue::ofNum(double(cc.args.size()));
        for (int k = 0; k < 4; ++k)
            (*o)["a" + std::to_string(k)] =
                ScriptValue::ofNum(size_t(k) < cc.args.size() ? double(cc.args[k]) : 0);
        return ScriptValue::ofObj(o);
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

// --------------------------------------------------------------- export --
namespace {

// Decompile one function exactly the way functionDetail does, so an exported
// listing matches what the Pseudo-C tab shows — same disassembly, same
// auto-comments, same IR-with-heuristic-fallback choice.
struct FnSource {
    std::vector<AsmLine> lines;
    std::string pseudo;
    std::string mode;
    u64 size = 0;
};

// Prototype for the header stub. Taken from the decompiled body so the stub and
// the exported source agree; a lifter that recovered two parameters should not
// publish a (void) prototype next to a definition that takes them.
std::string fnSignature(const FuncInfo& f, const std::string& pseudo) {
    size_t brace = pseudo.find('{');
    if (brace != std::string::npos) {
        std::string sig = pseudo.substr(0, brace);
        while (!sig.empty() && (sig.back() == ' ' || sig.back() == '\n')) sig.pop_back();
        if (sig.find('(') != std::string::npos && sig.find(')') != std::string::npos &&
            sig.find('\n') == std::string::npos)
            return sig;
    }
    std::string n = f.name;
    if (looksMangled(n)) {
        std::string d = demangle(n);
        if (!d.empty()) n = d;
    }
    return "u64 " + n + "(void)";
}

} // namespace

std::string Engine::exportSource(const std::string& path, const std::string& kind,
                                 u64 addr, const std::string& outPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureCtx(path);
    Ctx& c = ctx_;
    std::ostringstream st;

    if (c.backend.empty()) {
        st << "{\"ok\":false,\"error\":\"No disassembler for this architecture\"}";
        return st.str();
    }

    std::ofstream f(outPath, std::ios::binary | std::ios::trunc);
    if (!f) {
        st << "{\"ok\":false,\"error\":\"Cannot write the output file\"}";
        return st.str();
    }

    const bool wantAsm = (kind == "asm-all");
    const bool wantHdr = (kind == "h-all");
    const bool wantOne = (kind == "c-one");
    const bool useGhidra = !wantAsm && ghidraReady(c, path);
    if (useGhidra) computeJniEnvArgs(c);

    std::string base = c.bin.path;
    size_t slash = base.find_last_of('/');
    if (slash != std::string::npos) base = base.substr(slash + 1);

    f << "/*\n";
    f << " * " << (wantAsm ? "Assembly listing" : wantHdr ? "Header stub" : "Decompiled source")
      << " produced by Nocturne\n";
    f << " *\n";
    f << " * Binary      : " << base << "\n";
    f << " * Format      : " << (c.fmt == Fmt::ELF ? "ELF" : c.fmt == Fmt::PE ? "PE"
                                 : c.fmt == Fmt::DEX ? "DEX" : "raw") << "\n";
    f << " * Architecture: " << (c.arch.empty() ? "-" : c.arch) << "\n";
    f << " * Disassembler: " << c.backend << "\n";
    f << " * Decompiler  : "
      << (useGhidra ? GhidraDecomp::instance().backendName()
                    : std::string("Nocturne IR lifter"))
      << "\n";
    f << " *\n";
    f << " * This is reconstructed from machine code, not original source. It will\n";
    f << " * not recompile as-is.\n";
    if (useGhidra) {
        f << " *\n";
        f << " *   - Types are inferred from how values are used, not read from\n";
        f << " *     debug information. undefinedN means the width is known and\n";
        f << " *     nothing more. Structs, classes and vtables stay as offsets.\n";
        f << " *   - An argument list is only as good as the callee's recovered\n";
        f << " *     prototype; a call may show fewer arguments than it passes.\n";
        f << " *   - Blocks the analysis proves unreachable are dropped, and say\n";
        f << " *     so in a WARNING comment above the function.\n";
        f << " *   - Exception handling and unwind tables are not reconstructed.\n";
    } else {
        f << " * What the lifter does and does not recover:\n";
        f << " *\n";
        f << " *   - Every value is typed by its register or access width, never by\n";
        f << " *     the original C type. Structs, classes and vtables are offsets.\n";
        f << " *   - An argument list holds the registers this function was seen to\n";
        f << " *     set up before the call. f(...) means none were, so the callee's\n";
        f << " *     arguments are unknown rather than absent.\n";
        f << " *   - Values are tracked within a basic block and along single-\n";
        f << " *     predecessor edges. A register named bare in an expression (w8,\n";
        f << " *     x19, fp) reaches that point from a path the lifter did not\n";
        f << " *     merge, and is declared but never assigned.\n";
        f << " *   - CC_xx stands for a condition whose flag-setting instruction was\n";
        f << " *     not traced. A loop prints as do/while only where the back edge\n";
        f << " *     forms a region with one entry; everything else stays as gotos.\n";
        f << " *   - Exception handling and unwind tables are not reconstructed.\n";
    }
    f << " */\n\n";

    if (!wantAsm) {
        f << "#include <stdint.h>\n\n";
        if (useGhidra) {
            // The names Ghidra prints for values whose width is all that is known.
            f << "typedef uint8_t  undefined1;\ntypedef uint16_t undefined2;\n";
            f << "typedef uint32_t undefined4;\ntypedef uint64_t undefined8;\n";
            f << "typedef uint8_t  byte;\ntypedef uint16_t ushort;\n";
            f << "typedef uint32_t uint;\ntypedef uint64_t ulong;\n\n";
        } else {
            f << "typedef uint8_t  u8;\ntypedef uint16_t u16;\n";
            f << "typedef uint32_t u32;\ntypedef uint64_t u64;\n\n";
        }
    }

    std::map<u64, std::string> labels;
    for (auto& fn : c.funcs) labels[fn.addr] = fn.name;

    auto buildFnSource = [&](const FuncInfo& fn, FnSource& out) -> bool {
        u64 o = vaToOff(c, fn.addr);
        if (o == ~u64(0) || o >= c.bin.data.size()) return false;
        u64 sz = std::min<u64>(fn.size ? fn.size : 512, 65536);
        sz = std::min<u64>(sz, u64(c.bin.data.size()) - o);
        if (!sz) return false;

        if (c.dis.armDualMode()) c.dis.setDefaultThumb(fn.thumb);
        out.lines = c.dis.disassemble(c.bin.data.data() + o, size_t(sz), fn.addr, 4096);

        int runStart = -1, run = 0;
        for (size_t i = 0; i < out.lines.size(); ++i) {
            bool allZero = !out.lines[i].bytes.empty();
            for (char ch : out.lines[i].bytes)
                if (ch != '0' && ch != ' ') { allZero = false; break; }
            if (allZero) {
                if (run == 0) runStart = int(i);
                if (++run >= 4) { out.lines.resize(size_t(runStart)); break; }
            } else run = 0;
        }

        autoComment(c.arch, out.lines, c.names, c.strings, fn.addr, fn.addr + sz);
        // Same backend choice the Pseudo-C tab makes, so an exported listing
        // matches what the user was looking at when they exported it.
        if (useGhidra) {
            std::string err;
            auto ea = c.jniEnvArg.find(fn.addr);
            int env = (ea != c.jniEnvArg.end()) ? ea->second
                                                : detectJniEnvArg(out.lines, c.arch);
            out.pseudo = GhidraDecomp::instance().decompile(fn.addr, fn.name, err, env);
            if (!out.pseudo.empty()) {
                out.mode = "Ghidra";
                out.size = sz;
                return true;
            }
        }
        IrResult ir = decompileIR(out.lines, c.arch, fn.addr, fn.name, c.names, c.strings);
        out.pseudo = ir.ok ? ir.text : genPseudo(out.lines, c.arch, fn.addr, fn.name, labels);
        out.mode = ir.ok ? "IR" : "heuristic";
        out.size = sz;
        return true;
    };

    std::vector<const FuncInfo*> targets;
    if (wantOne) {
        for (auto& fn : c.funcs)
            if (fn.addr == addr) { targets.push_back(&fn); break; }
        if (targets.empty()) {
            for (auto& fn : c.funcs)
                if (addr >= fn.addr && addr < fn.addr + fn.size) { targets.push_back(&fn); break; }
        }
        if (targets.empty()) {
            st << "{\"ok\":false,\"error\":\"No function at that address\"}";
            return st.str();
        }
    } else {
        for (auto& fn : c.funcs)
            if (fn.from != "import") targets.push_back(&fn);
    }

    if (wantHdr) {
        f << "/* " << targets.size() << " functions */\n\n";
        FnSource hs;
        for (auto* fn : targets) {
            hs = FnSource{};
            std::string pseudo = buildFnSource(*fn, hs) ? hs.pseudo : std::string();
            f << fnSignature(*fn, pseudo) << ";  /* 0x" << std::hex << std::uppercase
              << fn->addr << std::dec << std::nouppercase << " */\n";
        }
        f << "\n";
        f.flush();
        st << "{\"ok\":true,\"functions\":" << targets.size() << ",\"bytes\":" << u64(f.tellp()) << "}";
        return st.str();
    }

    size_t done = 0, failed = 0;
    FnSource src;
    for (auto* fn : targets) {
        src = FnSource{};
        if (!buildFnSource(*fn, src)) { ++failed; continue; }

        f << "/* ---------------------------------------------------------------\n";
        f << "   " << fn->name << "\n";
        f << "   0x" << std::hex << std::uppercase << fn->addr << std::dec << std::nouppercase
          << "  ·  " << src.size << " bytes";
        if (!wantAsm) f << "  ·  " << src.mode;
        f << "\n   --------------------------------------------------------------- */\n";

        if (wantAsm) {
            for (auto& l : src.lines) {
                char buf[32];
                snprintf(buf, sizeof buf, "%08llX", (unsigned long long)l.addr);
                f << buf << "  " << l.mnem;
                if (!l.ops.empty()) f << " " << l.ops;
                if (!l.comment.empty()) f << "    ; " << l.comment;
                f << "\n";
            }
        } else {
            f << src.pseudo;
            if (!src.pseudo.empty() && src.pseudo.back() != '\n') f << "\n";
        }
        f << "\n";
        ++done;
    }

    f.flush();
    long long bytes = (long long)f.tellp();
    f.close();

    st << "{\"ok\":true,\"functions\":" << done << ",\"failed\":" << failed
       << ",\"bytes\":" << bytes << "}";
    return st.str();
}

} // namespace sako
