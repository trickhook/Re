#include "GhidraEmu.h"
#include "Prototypes.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <map>
#include <algorithm>
#include <mutex>
#include <set>

#ifdef SAKO_HAVE_GHIDRA
#include "architecture.hh"
#include "emulate.hh"
#include "loadimage.hh"
#include "memstate.hh"
#include "sleigh_arch.hh"
#include <sstream>
#endif

namespace sako {

bool GhidraEmu::compiledIn() {
#ifdef SAKO_HAVE_GHIDRA
    return true;
#else
    return false;
#endif
}

const char* emuStopName(EmuStop s) {
    switch (s) {
        case EmuStop::Completed:     return "completed";
        case EmuStop::StopAddress:   return "stopAddress";
        case EmuStop::Budget:        return "budget";
        case EmuStop::Timeout:       return "timeout";
        case EmuStop::MemoryCap:     return "memoryCap";
        case EmuStop::CallCap:       return "callCap";
        case EmuStop::Unimplemented: return "unimplemented";
        case EmuStop::Fault:         return "fault";
        case EmuStop::Aborted:       return "aborted";
        case EmuStop::Setup:         return "setup";
    }
    return "setup";
}

#ifndef SAKO_HAVE_GHIDRA

// ------------------------------------------------------ not compiled in ---
struct GhidraEmu::Impl {};
GhidraEmu& GhidraEmu::instance() { static GhidraEmu g; return g; }
GhidraEmu::~GhidraEmu() = default;
void GhidraEmu::close() {}
void GhidraEmu::translatorRebound() {}
bool GhidraEmu::ready() const { return false; }
std::string GhidraEmu::backendName() const { return std::string(); }
std::vector<std::string> GhidraEmu::modelledImports() { return {}; }
bool GhidraEmu::open(const std::string&, const std::string&, const u8*, size_t,
                     const std::vector<GhidraSeg>&,
                     const std::vector<std::pair<u64, std::string>>&,
                     const std::vector<std::pair<u64, char>>&,
                     std::string& err) {
    err = "built without the Ghidra p-code engine";
    return false;
}
EmuResult GhidraEmu::run(const EmuRequest& req) {
    EmuResult r;
    r.entry = req.entry;
    r.detail = "built without the Ghidra p-code engine";
    return r;
}

#else

using namespace ghidra;

namespace {

std::mutex& emuMutex() { static std::mutex m; return m; }

// ------------------------------------------------------------- control ----
// Thrown to unwind out of the middle of a p-code operation. Ghidra's emulator
// has no cancellation of its own — the halt flag is documented as unused by
// the engine — so an exception is the only way to stop between ops.
struct EmuHalt {
    EmuStop kind;
    std::string detail;
};

std::string hex(u64 v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llX", (unsigned long long)v);
    return std::string(b);
}

// ------------------------------------------------------------- sandbox ----
// Addresses the image does not use, for the stack, the heap the allocator
// models, and the one address that means "the function returned".
struct Sandbox {
    u64 stackLo = 0, stackHi = 0, sp0 = 0;
    u64 heapLo = 0, heapHi = 0, heapNext = 0;
    u64 magic = 0;
    u64 errnoAddr = 0;
    int ptrSize = 8;
    std::vector<std::pair<u64, u64>> allocs;   // what the guest asked us for

    void layout(int ps, u64 shift) {
        ptrSize = ps;
        if (ps == 8) {
            stackLo = 0x00007FF000000000ULL + shift;
            heapLo  = 0x00007FE000000000ULL + shift;
            magic   = 0x00007FCFFFFF0000ULL + shift;
        } else {
            stackLo = 0x70000000u + u32(shift);
            heapLo  = 0x71000000u + u32(shift);
            magic   = 0x7F000000u + u32(shift);
        }
        stackHi = stackLo + kStack;
        heapHi = heapLo + kHeap;
        sp0 = (stackLo + kStack - 0x10000) & ~u64(15);
        heapNext = heapLo + 64;          // leave room for errno and friends
        errnoAddr = heapLo;
    }

    u64 alloc(u64 n) {
        if (n == 0) n = 1;
        if (n > kHeap) return 0;
        u64 a = (heapNext + 15) & ~u64(15);
        if (a + n > heapHi) return 0;
        heapNext = a + n;
        if (allocs.size() < 64) allocs.push_back({a, n});
        return a;
    }

    bool inStack(u64 a) const { return a >= stackLo && a < stackHi; }

    static constexpr u64 kStack = 0x100000;   // 1 MiB
    static constexpr u64 kHeap  = 0x100000;   // 1 MiB
};

// ----------------------------------------------------------------- ABI ----
struct Abi {
    std::vector<std::string> argRegs;
    std::string ret, sp, lr;
    std::vector<std::string> report;
    int ptrSize = 8;
    bool retOnStack = false;     // x86: CALL pushed the return address
};

// True only for the calling conventions this build actually models. The
// decompiler ships SLEIGH specifications for more targets than this — MIPS,
// PowerPC, SPARC, 68000 — and guessing their argument registers would produce
// confident nonsense, so open() refuses them by name instead.
bool abiFor(const std::string& lang, Abi& a) {
    if (lang.rfind("AARCH64", 0) == 0) {
        for (int i = 0; i < 8; ++i) a.argRegs.push_back("x" + std::to_string(i));
        a.ret = "x0"; a.sp = "sp"; a.lr = "x30"; a.ptrSize = 8;
        for (int i = 0; i <= 30; ++i) a.report.push_back("x" + std::to_string(i));
        a.report.push_back("sp");
        return true;
    }
    if (lang.rfind("ARM:", 0) == 0) {
        for (int i = 0; i < 4; ++i) a.argRegs.push_back("r" + std::to_string(i));
        a.ret = "r0"; a.sp = "sp"; a.lr = "lr"; a.ptrSize = 4;
        for (int i = 0; i <= 12; ++i) a.report.push_back("r" + std::to_string(i));
        a.report.push_back("sp"); a.report.push_back("lr");
        return true;
    }
    if (lang.rfind("x86:LE:64", 0) == 0) {
        a.argRegs = {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
        a.ret = "RAX"; a.sp = "RSP"; a.ptrSize = 8; a.retOnStack = true;
        a.report = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"};
        return true;
    }
    if (lang.rfind("x86:LE:32", 0) == 0) {
        // cdecl: every argument on the stack.
        a.ret = "EAX"; a.sp = "ESP"; a.ptrSize = 4; a.retOnStack = true;
        a.report = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"};
        return true;
    }
    return false;
}

// ------------------------------------------------------------- overlay ----
// A page overlay that knows which pages it has written. Two things need that:
// the memory cap, and being able to say afterwards exactly what the run
// changed — which is the whole point of running it.
class TrackedOverlay : public MemoryPageOverlay {
    std::set<u64> dirty_;
    size_t cap_;

    void note(u64 pageAddr) {
        if (dirty_.find(pageAddr) != dirty_.end()) return;
        if (dirty_.size() >= cap_) {
            char b[96];
            std::snprintf(b, sizeof b,
                          "wrote to more than %u pages (%u KiB) of memory",
                          unsigned(cap_), unsigned(cap_ * 4));
            throw EmuHalt{EmuStop::MemoryCap, b};
        }
    }

protected:
    void insert(uintb addr, uintb val) override {
        u64 pa = u64(addr) & ~u64(getPageSize() - 1);
        note(pa);
        // The base allocates the page and fills it from the underlying bank,
        // which reads through the load image. Recording the page only after
        // that is what stops the load image from serving a page back to the
        // very call that is still initialising it.
        MemoryPageOverlay::insert(addr, val);
        dirty_.insert(pa);
    }
    void setPage(uintb addr, const uint1* val, int4 skip, int4 size) override {
        note(u64(addr));
        MemoryPageOverlay::setPage(addr, val, skip, size);
        dirty_.insert(u64(addr));
    }

public:
    TrackedOverlay(AddrSpace* spc, int4 ws, int4 ps, MemoryBank* ul, size_t cap)
        : MemoryPageOverlay(spc, ws, ps, ul), cap_(cap) {}

    const std::set<u64>& dirtyPages() const { return dirty_; }
    bool isDirty(u64 pageAddr) const { return dirty_.find(pageAddr) != dirty_.end(); }
};

// ---------------------------------------------------------- load image ----
// Serves bytes out of the in-memory Binary, exactly like the decompiler's,
// with one addition: once the guest has written a page, instruction fetch
// reads the written bytes. Without that, code a packer unpacks into memory
// would be emulated as the packed bytes still sitting in the file.
class EmuLoadImage : public LoadImage {
    const u8* image_ = nullptr;
    size_t size_ = 0;
    std::vector<GhidraSeg> segs_;
    const TrackedOverlay* ram_ = nullptr;

public:
    EmuLoadImage(const u8* image, size_t size, std::vector<GhidraSeg> segs)
        : LoadImage("nocturne-emu"), image_(image), size_(size), segs_(std::move(segs)) {}

    void attachRam(const TrackedOverlay* r) { ram_ = r; }

    // The file's own bytes, ignoring anything the guest wrote. Used to work
    // out which bytes a run actually changed.
    bool original(u64 va, u8* out, size_t n) const {
        std::memset(out, 0, n);
        bool any = false;
        for (const GhidraSeg& s : segs_) {
            u64 segEnd = s.vaddr + s.memsz;
            if (va + u64(n) <= s.vaddr || va >= segEnd) continue;
            u64 from = va > s.vaddr ? va : s.vaddr;
            u64 to = va + u64(n);
            u64 fileEnd = s.vaddr + s.filesz;
            if (to > fileEnd) to = fileEnd;      // .bss tail stays zero
            if (to <= from) { any = true; continue; }
            u64 src = s.fileoff + (from - s.vaddr);
            if (src > size_ || src + (to - from) > size_) continue;
            std::memcpy(out + (from - va), image_ + src, static_cast<size_t>(to - from));
            any = true;
        }
        return any;
    }

    void loadFill(uint1* ptr, int4 size, const Address& addr) override {
        if (size <= 0) return;
        u64 va = addr.getOffset();

        // Anything the guest has rewritten wins over the file.
        if (ram_ != nullptr) {
            const u64 ps = 4096;
            bool touched = false;
            for (u64 p = va & ~(ps - 1); p < va + u64(size); p += ps)
                if (ram_->isDirty(p)) { touched = true; break; }
            if (touched) {
                MemoryBank* bank = const_cast<TrackedOverlay*>(ram_);
                u64 done = 0;
                while (done < u64(size)) {
                    u64 a = va + done;
                    u64 page = a & ~(ps - 1);
                    u64 take = ps - (a - page);
                    if (take > u64(size) - done) take = u64(size) - done;
                    if (ram_->isDirty(page))
                        bank->getChunk(a, int4(take), ptr + done);
                    else if (!original(a, ptr + done, static_cast<size_t>(take)))
                        std::memset(ptr + done, 0, static_cast<size_t>(take));
                    done += take;
                }
                return;
            }
        }

        if (!original(va, ptr, static_cast<size_t>(size))) {
            // Unmapped. MemoryImage turns this into zeroes for data reads,
            // which is what gives the sandbox stack and heap their contents;
            // for instruction fetch it is the exception that reports the
            // branch into nowhere.
            char buf[56];
            std::snprintf(buf, sizeof buf, "no image data at 0x%llX",
                          (unsigned long long)va);
            throw DataUnavailError(std::string(buf));
        }
    }

    void getReadonly(RangeList&) const override {}   // no constant folding here
    string getArchType(void) const override { return "nocturne-emu"; }
    void adjustVma(long) override {}
};

// SleighArchitecture wants a file; this one is handed the bytes the app
// already has. Deliberately a separate object from the decompiler's: they run
// under different locks, and Sleigh's parser state is not shareable.
class EmuArchitecture : public SleighArchitecture {
    const u8* image_;
    size_t size_;
    std::vector<GhidraSeg> segs_;

    void buildLoader(DocumentStorage&) override {
        collectSpecFiles(*errorstream);
        loader = new EmuLoadImage(image_, size_, segs_);
    }
    void resolveArchitecture(void) override {
        archid = getTarget();
        SleighArchitecture::resolveArchitecture();
    }
    void buildCoreTypes(DocumentStorage&) override {
        // The emulator never prints a type; one void is enough to satisfy the
        // factory, and skipping the rest keeps the second architecture cheap.
        types->setCoreType("void", 1, TYPE_VOID, false);
        types->setCoreType("byte", 1, TYPE_UINT, false);
        types->setCoreType("code", 1, TYPE_CODE, false);
        types->setCoreType("undefined1", 1, TYPE_UNKNOWN, false);
        types->setCoreType("undefined2", 2, TYPE_UNKNOWN, false);
        types->setCoreType("undefined4", 4, TYPE_UNKNOWN, false);
        types->setCoreType("undefined8", 8, TYPE_UNKNOWN, false);
        types->cacheCoreTypes();
    }

public:
    EmuArchitecture(const string& target, ostream* estream,
                    const u8* image, size_t size, std::vector<GhidraSeg> segs)
        : SleighArchitecture("nocturne-emu", target, estream),
          image_(image), size_(size), segs_(std::move(segs)) {}
};

void initLibraryOnce() {
    static bool done = false;
    if (done) return;
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    ArchitectureCapability::sortCapabilities();
    done = true;
}

// ------------------------------------------------------------ machine -----
// Everything the stubs and the run loop share.
struct Machine {
    Translate* trans = nullptr;
    MemoryState* mem = nullptr;
    AddrSpace* ram = nullptr;
    TrackedOverlay* overlay = nullptr;
    EmuLoadImage* img = nullptr;
    Abi abi;
    Sandbox sb;
    EmuLimits limits;

    // reporting
    std::vector<EmuCall> calls;
    u64 callsTotal = 0;
    std::map<std::string, EmuUserop> userops;
    u64 useropsDropped = 0;       // seen past the 64-name table, counted anyway
    std::string pendingNote;      // set by a model, consumed by the record
    bool approximate = false;
    u64 tail[64];
    u32 tailN = 0;

    void pushTail(u64 a) { tail[tailN % 64] = a; ++tailN; }

    // ---- registers ----
    bool reg(const std::string& nm, VarnodeData& out) const {
        try { out = trans->getRegister(nm); return true; }
        catch (LowlevelError&) { return false; }
    }
    u64 getReg(const std::string& nm, bool* ok = nullptr) const {
        VarnodeData v;
        if (!reg(nm, v)) { if (ok) *ok = false; return 0; }
        if (ok) *ok = true;
        return mem->getValue(v.space, v.offset, v.size);
    }
    bool setReg(const std::string& nm, u64 val) {
        VarnodeData v;
        if (!reg(nm, v)) return false;
        mem->setValue(v.space, v.offset, v.size, val);
        return true;
    }

    // ---- memory ----
    u64 rd(u64 a, int n) const { return mem->getValue(ram, a, n); }
    void wr(u64 a, int n, u64 v) { mem->setValue(ram, a, n, v); }
    u64 rdPtr(u64 a) const { return rd(a, abi.ptrSize); }

    void read(u64 a, u8* out, size_t n) const {
        size_t done = 0;
        while (done < n) {
            int4 take = int4(n - done > 4096 ? 4096 : n - done);
            mem->getChunk(out + done, ram, a + done, take);
            done += static_cast<size_t>(take);
        }
    }
    void write(u64 a, const u8* p, size_t n) {
        size_t done = 0;
        while (done < n) {
            int4 take = int4(n - done > 4096 ? 4096 : n - done);
            mem->setChunk(p + done, ram, a + done, take);
            done += static_cast<size_t>(take);
        }
    }

    // A C string out of guest memory, bounded.
    std::string cstr(u64 a, size_t cap = 512) const {
        std::string s;
        for (size_t i = 0; i < cap; ++i) {
            u8 c = u8(rd(a + i, 1));
            if (c == 0) break;
            s += char(c);
        }
        return s;
    }
    u64 strlenGuest(u64 a, u64 cap) const {
        for (u64 i = 0; i < cap; ++i)
            if (rd(a + i, 1) == 0) return i;
        char b[96];
        std::snprintf(b, sizeof b, "a string at 0x%llX had no terminator within %llu bytes",
                      (unsigned long long)a, (unsigned long long)cap);
        throw EmuHalt{EmuStop::Fault, b};
    }
};

// Nothing a model does may be unbounded; these are the ceilings.
const u64 kMaxBlock  = 1u << 20;   // one memcpy/memset
const u64 kMaxScan   = 1u << 16;   // one strlen/strstr scan

void needBlock(const char* fn, u64 n) {
    if (n <= kMaxBlock) return;
    char b[128];
    std::snprintf(b, sizeof b, "%s asked for %llu bytes, past the %llu-byte limit on one call",
                  fn, (unsigned long long)n, (unsigned long long)kMaxBlock);
    throw EmuHalt{EmuStop::Fault, b};
}

// --------------------------------------------------------------- stubs ----
// Which libc functions are worth modelling is decided by one question: what
// does a string-decryption routine actually call? It allocates an output
// buffer, copies into it, measures a string, and logs. Everything else can
// return zero as long as the answer says it did.
enum StubId {
    S_none = 0,
    S_memcpy, S_mempcpy, S_memmove, S_memset, S_memcmp, S_memchr,
    S_strlen, S_strnlen, S_strcpy, S_stpcpy, S_strncpy, S_strcat, S_strncat,
    S_strcmp, S_strncmp, S_strchr, S_strrchr, S_strstr, S_strdup, S_strndup,
    S_malloc, S_calloc, S_realloc, S_free, S_new, S_delete,
    S_abort, S_exit, S_stackfail, S_assert,
    S_log, S_logwrite,
    S_time, S_clockgettime, S_gettimeofday,
    S_getpid, S_gettid, S_pthreadself, S_zero, S_errno,
    S_toupper, S_tolower, S_isalpha, S_isdigit, S_isspace, S_isalnum,
    S_isupper, S_islower, S_isxdigit, S_atoi
};

struct StubName { const char* name; StubId id; };

// Bionic compiles with _FORTIFY_SOURCE on, so the __*_chk spellings are what
// an Android import table actually holds; both are here for the same reason
// Prototypes.cpp carries both.
const StubName kStubs[] = {
    {"memcpy", S_memcpy}, {"__memcpy_chk", S_memcpy}, {"mempcpy", S_mempcpy},
    {"memmove", S_memmove}, {"__memmove_chk", S_memmove},
    {"memset", S_memset}, {"__memset_chk", S_memset},
    {"memcmp", S_memcmp}, {"bcmp", S_memcmp}, {"memchr", S_memchr},
    {"strlen", S_strlen}, {"__strlen_chk", S_strlen}, {"strnlen", S_strnlen},
    {"strcpy", S_strcpy}, {"__strcpy_chk", S_strcpy}, {"stpcpy", S_stpcpy},
    {"strncpy", S_strncpy}, {"__strncpy_chk", S_strncpy},
    {"strcat", S_strcat}, {"__strcat_chk", S_strcat}, {"strncat", S_strncat},
    {"strcmp", S_strcmp}, {"strncmp", S_strncmp},
    {"strchr", S_strchr}, {"index", S_strchr},
    {"strrchr", S_strrchr}, {"rindex", S_strrchr},
    {"strstr", S_strstr}, {"strdup", S_strdup}, {"strndup", S_strndup},
    {"malloc", S_malloc}, {"calloc", S_calloc}, {"realloc", S_realloc},
    {"free", S_free},
    {"_Znwm", S_new}, {"_Znam", S_new}, {"_Znwj", S_new}, {"_Znaj", S_new},
    {"_ZdlPv", S_delete}, {"_ZdaPv", S_delete},
    {"_ZdlPvm", S_delete}, {"_ZdaPvm", S_delete},
    {"abort", S_abort}, {"exit", S_exit}, {"_exit", S_exit},
    {"__stack_chk_fail", S_stackfail},
    {"__assert", S_assert}, {"__assert2", S_assert},
    {"__android_log_assert", S_assert},
    {"__android_log_print", S_log}, {"__android_log_vprint", S_log},
    {"__android_log_write", S_logwrite},
    {"time", S_time}, {"clock_gettime", S_clockgettime},
    {"gettimeofday", S_gettimeofday},
    {"getpid", S_getpid}, {"getppid", S_getpid}, {"gettid", S_gettid},
    {"pthread_self", S_pthreadself},
    {"pthread_mutex_lock", S_zero}, {"pthread_mutex_unlock", S_zero},
    {"pthread_mutex_init", S_zero}, {"pthread_mutex_destroy", S_zero},
    {"pthread_once", S_zero},
    {"__errno", S_errno}, {"__errno_location", S_errno},
    {"toupper", S_toupper}, {"tolower", S_tolower},
    {"isalpha", S_isalpha}, {"isdigit", S_isdigit}, {"isspace", S_isspace},
    {"isalnum", S_isalnum}, {"isupper", S_isupper}, {"islower", S_islower},
    {"isxdigit", S_isxdigit},
    {"atoi", S_atoi}, {"atol", S_atoi},
};
const int kStubCount = int(sizeof(kStubs) / sizeof(kStubs[0]));

StubId stubFor(const std::string& raw) {
    std::string nm = raw;
    size_t at = nm.find('@');            // "memcpy@plt"
    if (at != std::string::npos) nm.resize(at);
    for (int i = 0; i < kStubCount; ++i)
        if (nm == kStubs[i].name) return kStubs[i].id;
    return S_none;
}

// Does this import have a known signature? Prototypes.cpp already answers
// that for 150 names; reusing it means the default stub can at least return
// the right width and the answer can say whether the shape was known.
bool knownProto(const std::string& raw, char* retKind) {
    std::string nm = raw;
    size_t at = nm.find('@');
    if (at != std::string::npos) nm.resize(at);
    for (int i = 0; i < proto::kKnownProtoCount; ++i) {
        if (nm == proto::kKnownProtos[i].name) {
            if (retKind) *retKind = proto::kKnownProtos[i].ret[0];
            return true;
        }
    }
    return false;
}

struct StubEntry {
    std::string name;
    StubId id = S_none;
    bool known = false;
    char retKind = 'i';
};

class Emu;   // forward

// One BreakCallBack for every stubbed address. Ghidra looks the breakpoint up
// by address, so a single object can serve all of them and dispatch on the
// address it is handed.
class StubBreak : public BreakCallBack {
public:
    Machine* m = nullptr;
    std::map<u64, StubEntry>* table = nullptr;
    bool addressCallback(const Address& addr) override;
private:
    u64 arg(int i);
    void ret(u64 v);
    void doReturn();
    bool model(StubEntry& e, const Address& addr);
};

// The CALLOTHER handler. A SLEIGH specification emits user-defined ops for
// everything it declines to give semantics to — barriers, hints, exclusive
// monitors, system register access. Refusing to run at the first one would
// make the emulator useless on real ARM64; pretending they all return zero
// without saying so would make it dishonest. So: zero, counted, named, and
// the result is flagged approximate unless the op is one where zero is right.
class UseropBreak : public BreakCallBack {
public:
    Machine* m = nullptr;
    std::vector<std::string> names;

    // A trap is not something to model as zero and carry on from: on an
    // obfuscated library a BRK or an undefined instruction is usually the
    // anti-debug check firing, and that is the answer the user came for.
    static bool trap(const std::string& n) {
        std::string l;
        for (char c : n) l += char(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        static const char* bad[] = {"undefinedinstruction", "softwarebreakpoint",
                                    "softwareinterrupt", "breakpoint", "halt",
                                    "supervisorcall", "hypervisorcall"};
        for (const char* k : bad) if (l.find(k) != std::string::npos) return true;
        return false;
    }

    static bool harmless(const std::string& n) {
        std::string l;
        for (char c : n) l += char(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        static const char* ok[] = {"barrier", "hint", "nop", "yield", "prefetch",
                                   "isb", "dmb", "dsb", "sev", "wfe", "wfi",
                                   "cache", "sync", "tlbi", "flush", "clrex",
                                   // ARM's setISAMode: in this emulator the
                                   // ARM/Thumb decode mode comes from the
                                   // TMode context the mapping symbols set,
                                   // not from this op, so ignoring it changes
                                   // nothing.
                                   "isamode"};
        for (const char* k : ok) if (l.find(k) != std::string::npos) return true;
        return false;
    }

    bool pcodeCallback(PcodeOpRaw* op) override {
        u64 idx = op->getInput(0)->offset;
        std::string nm = idx < names.size() ? names[static_cast<size_t>(idx)] : std::string("userop");
        if (nm.empty()) nm = "userop" + std::to_string(idx);
        if (trap(nm))
            throw EmuHalt{EmuStop::Aborted, "the code executed " + nm};
        bool ok = harmless(nm);
        auto it = m->userops.find(nm);
        if (it == m->userops.end()) {
            EmuUserop u; u.name = nm; u.count = 1; u.harmless = ok;
            if (m->userops.size() < 64) m->userops[nm] = u;
            else ++m->useropsDropped;   // a 65th distinct name: counted, not kept
        } else {
            ++it->second.count;
        }
        VarnodeData* out = op->getOutput();
        if (out != nullptr) {
            if (!ok) m->approximate = true;
            if (out->size <= int4(sizeof(uintb)))
                m->mem->setValue(out->space, out->offset, out->size, 0);
        }
        if (m->limits.strictUserops) {
            throw EmuHalt{EmuStop::Unimplemented,
                          "no semantics for the p-code operation '" + nm + "'"};
        }
        return true;      // we performed it (as zero)
    }
};

// ------------------------------------------------------------ emulator ----
class Emu : public EmulatePcodeCache {
    Machine* m_;
    u64 magic_;

    static bool isWide(const VarnodeData* v) {
        return v != nullptr && v->size > int4(sizeof(uintb));
    }

    void guard(const VarnodeData* v, const char* what) {
        if (!isWide(v)) return;
        char b[160];
        std::snprintf(b, sizeof b,
                      "a %d-byte %s at 0x%llX needs arithmetic wider than the emulator's "
                      "8-byte word (128-bit SIMD lanes with carries are not modelled)",
                      int(v->size), what,
                      (unsigned long long)getExecuteAddress().getOffset());
        throw EmuHalt{EmuStop::Unimplemented, b};
    }

    // Ghidra's MemoryState is exactly one uintb wide, so a 128-bit NEON
    // varnode cannot pass through getValue/setValue at all. But most of what
    // a compiler emits those varnodes for has no carry between bytes — a
    // move, a load, a store, a bitwise op, a concatenation, a truncation —
    // and on the bytes themselves those are exact. Doing them here is what
    // lets an ordinary -O2 loop that clang vectorised run to the end; an
    // operation that really does need 128-bit arithmetic still stops, and
    // says which one it was.
    void readVn(const VarnodeData* v, std::vector<u8>& out, bool be) {
        out.assign(static_cast<size_t>(v->size), 0);
        if (v->space->getType() == IPTR_CONSTANT) {
            // A constant carries its value in the offset, not in memory.
            uintb c = v->offset;
            for (uint4 i = 0; i < v->size && i < uint4(sizeof(uintb)); ++i)
                out[static_cast<size_t>(be ? v->size - 1 - i : i)] = u8((c >> (8 * i)) & 0xFF);
            return;
        }
        memstate->getChunk(out.data(), v->space, v->offset, v->size);
    }
    void writeVn(const VarnodeData* v, const std::vector<u8>& in) {
        memstate->setChunk(in.data(), v->space, v->offset, v->size);
    }
    // Place `a` in the low-order end of `r`, filling the rest with `fill`.
    static void extend(std::vector<u8>& r, const std::vector<u8>& a, u8 fill, bool be) {
        std::fill(r.begin(), r.end(), fill);
        if (be) std::copy(a.begin(), a.end(), r.end() - long(a.size()));
        else    std::copy(a.begin(), a.end(), r.begin());
    }

public:
    Emu(Translate* t, MemoryState* s, BreakTable* b, Machine* m, u64 magic)
        : EmulatePcodeCache(t, s, b), m_(m), magic_(magic) {}

    // The one place a return can be caught. An address breakpoint would be
    // checked only after the instruction at that address had been decoded,
    // and the trampoline address deliberately has nothing to decode.
    void setExecuteAddress(const Address& addr) override {
        if (addr.getOffset() == magic_)
            throw EmuHalt{EmuStop::Completed, "returned to the caller"};
        EmulatePcodeCache::setExecuteAddress(addr);
    }

    void executeUnary(void) override {
        VarnodeData* out = currentOp->getOutput();
        VarnodeData* a = currentOp->getInput(0);
        if (isWide(out) || isWide(a)) {
            OpCode op = currentBehave->getOpcode();
            bool be = out->space->isBigEndian();
            std::vector<u8> av;
            readVn(a, av, be);
            if (op == CPUI_COPY && out->size == a->size) { writeVn(out, av); return; }
            if ((op == CPUI_INT_ZEXT || op == CPUI_INT_SEXT) && out->size >= a->size) {
                u8 fill = 0;
                if (op == CPUI_INT_SEXT && !av.empty())
                    fill = (av[be ? 0 : av.size() - 1] & 0x80) ? 0xFF : 0x00;
                std::vector<u8> r(static_cast<size_t>(out->size));
                extend(r, av, fill, be);
                writeVn(out, r);
                return;
            }
            if (op == CPUI_INT_NEGATE && out->size == a->size) {
                for (size_t i = 0; i < av.size(); ++i) av[i] = u8(~av[i]);
                writeVn(out, av);
                return;
            }
        }
        guard(a, "operand");
        guard(out, "result");
        EmulateMemory::executeUnary();
    }

    void executeBinary(void) override {
        VarnodeData* out = currentOp->getOutput();
        VarnodeData* a = currentOp->getInput(0);
        VarnodeData* b = currentOp->getInput(1);
        if (isWide(out) || isWide(a) || isWide(b)) {
            OpCode op = currentBehave->getOpcode();
            bool be = out->space->isBigEndian();
            std::vector<u8> av, bv;
            if (op == CPUI_SUBPIECE && out->size <= a->size) {
                readVn(a, av, be);
                u64 k = memstate->getValue(b);              // bytes truncated off
                if (k + u64(out->size) <= u64(a->size)) {
                    size_t from = static_cast<size_t>(
                        be ? u64(a->size) - k - u64(out->size) : k);
                    std::vector<u8> r(av.begin() + long(from),
                                      av.begin() + long(from) + long(out->size));
                    writeVn(out, r);
                    return;
                }
            } else if (op == CPUI_PIECE && out->size == a->size + b->size) {
                readVn(a, av, be); readVn(b, bv, be);       // a is most significant
                std::vector<u8> r;
                r.reserve(static_cast<size_t>(out->size));
                if (be) { r = av; r.insert(r.end(), bv.begin(), bv.end()); }
                else    { r = bv; r.insert(r.end(), av.begin(), av.end()); }
                writeVn(out, r);
                return;
            } else if ((op == CPUI_INT_AND || op == CPUI_INT_OR || op == CPUI_INT_XOR) &&
                       out->size == a->size && a->size == b->size) {
                readVn(a, av, be); readVn(b, bv, be);
                for (size_t i = 0; i < av.size(); ++i)
                    av[i] = op == CPUI_INT_AND ? u8(av[i] & bv[i])
                          : op == CPUI_INT_OR  ? u8(av[i] | bv[i])
                                               : u8(av[i] ^ bv[i]);
                writeVn(out, av);
                return;
            } else if ((op == CPUI_INT_EQUAL || op == CPUI_INT_NOTEQUAL) &&
                       a->size == b->size && !isWide(out)) {
                readVn(a, av, be); readVn(b, bv, be);
                bool eq = av == bv;
                memstate->setValue(out, (op == CPUI_INT_EQUAL) == eq ? 1 : 0);
                return;
            }
        }
        guard(a, "operand");
        guard(b, "operand");
        guard(out, "result");
        EmulateMemory::executeBinary();
    }

    void executeLoad(void) override {
        VarnodeData* out = currentOp->getOutput();
        if (isWide(out)) {
            uintb off = memstate->getValue(currentOp->getInput(1));
            AddrSpace* spc = currentOp->getInput(0)->getSpaceFromConst();
            off = AddrSpace::addressToByte(off, spc->getWordSize());
            std::vector<u8> buf(static_cast<size_t>(out->size));
            memstate->getChunk(buf.data(), spc, off, out->size);
            writeVn(out, buf);
            return;
        }
        EmulateMemory::executeLoad();
    }

    void executeStore(void) override {
        VarnodeData* val = currentOp->getInput(2);
        if (isWide(val)) {
            uintb off = memstate->getValue(currentOp->getInput(1));
            AddrSpace* spc = currentOp->getInput(0)->getSpaceFromConst();
            off = AddrSpace::addressToByte(off, spc->getWordSize());
            std::vector<u8> buf;
            readVn(val, buf, spc->isBigEndian());
            memstate->setChunk(buf.data(), spc, off, val->size);
            return;
        }
        EmulateMemory::executeStore();
    }
};

// ---- StubBreak, now that Emu is complete --------------------------------
u64 StubBreak::arg(int i) {
    if (i < int(m->abi.argRegs.size())) return m->getReg(m->abi.argRegs[static_cast<size_t>(i)]);
    int slot = i - int(m->abi.argRegs.size());
    u64 sp = m->getReg(m->abi.sp);
    // On x86 the return address occupies the first slot.
    u64 base = sp + (m->abi.retOnStack ? u64(m->abi.ptrSize) : 0);
    return m->rd(base + u64(slot) * u64(m->abi.ptrSize), m->abi.ptrSize);
}

void StubBreak::ret(u64 v) { m->setReg(m->abi.ret, v); }

void StubBreak::doReturn() {
    u64 to;
    if (m->abi.retOnStack) {
        u64 sp = m->getReg(m->abi.sp);
        to = m->rd(sp, m->abi.ptrSize);
        m->setReg(m->abi.sp, sp + u64(m->abi.ptrSize));
    } else {
        to = m->getReg(m->abi.lr);
    }
    emulate->setExecuteAddress(Address(m->ram, to));
}

bool StubBreak::addressCallback(const Address& addr) {
    auto it = table->find(addr.getOffset());
    if (it == table->end()) return false;      // not ours; run the code
    StubEntry& e = it->second;

    if (++m->callsTotal > m->limits.maxCalls) {
        char b[110];
        std::snprintf(b, sizeof b,
                      "called stubbed imports %llu times, past the limit of %u",
                      (unsigned long long)m->callsTotal, m->limits.maxCalls);
        throw EmuHalt{EmuStop::CallCap, b};
    }

    EmuCall rec;
    rec.name = e.name;
    rec.site = addr.getOffset();
    int nshow = e.id == S_none ? 4 : 4;
    for (int i = 0; i < nshow && i < 8; ++i) rec.args.push_back(arg(i));

    m->pendingNote.clear();
    bool modelled = model(e, addr);
    rec.modelled = modelled;
    rec.ret = m->getReg(m->abi.ret);
    if (!modelled) {
        m->approximate = true;
        rec.note = e.known ? "not modelled; returned 0" : "unknown import; returned 0";
    } else if (!m->pendingNote.empty()) {
        rec.note = m->pendingNote;
        m->pendingNote.clear();
    }
    if (m->calls.size() < 256) m->calls.push_back(rec);
    return true;
}

bool StubBreak::model(StubEntry& e, const Address& addr) {
    Machine& M = *m;
    Sandbox& sb = M.sb;
    bool done = true;

    switch (e.id) {
        case S_memcpy: case S_mempcpy: case S_memmove: {
            u64 d = arg(0), s = arg(1), n = arg(2);
            needBlock(e.name.c_str(), n);
            if (n) {
                std::vector<u8> tmp(static_cast<size_t>(n));
                M.read(s, tmp.data(), static_cast<size_t>(n));
                M.write(d, tmp.data(), static_cast<size_t>(n));
            }
            ret(e.id == S_mempcpy ? d + n : d);
            break;
        }
        case S_memset: {
            u64 d = arg(0), c = arg(1), n = arg(2);
            needBlock("memset", n);
            if (n) {
                std::vector<u8> tmp(static_cast<size_t>(n), u8(c));
                M.write(d, tmp.data(), static_cast<size_t>(n));
            }
            ret(d);
            break;
        }
        case S_memcmp: {
            u64 a = arg(0), b = arg(1), n = arg(2);
            needBlock("memcmp", n);
            i64 r = 0;
            for (u64 i = 0; i < n; ++i) {
                int x = int(M.rd(a + i, 1)), y = int(M.rd(b + i, 1));
                if (x != y) { r = x - y; break; }
            }
            ret(u64(r));
            break;
        }
        case S_memchr: {
            u64 a = arg(0), c = arg(1) & 0xFF, n = arg(2);
            needBlock("memchr", n);
            u64 found = 0;
            for (u64 i = 0; i < n; ++i)
                if (M.rd(a + i, 1) == c) { found = a + i; break; }
            ret(found);
            break;
        }
        case S_strlen: ret(M.strlenGuest(arg(0), kMaxScan)); break;
        case S_strnlen: {
            u64 a = arg(0), cap = arg(1);
            if (cap > kMaxScan) cap = kMaxScan;
            u64 n = 0;
            while (n < cap && M.rd(a + n, 1) != 0) ++n;
            ret(n);
            break;
        }
        case S_strcpy: case S_stpcpy: {
            u64 d = arg(0), s = arg(1);
            u64 n = M.strlenGuest(s, kMaxScan);
            std::vector<u8> tmp(static_cast<size_t>(n) + 1);
            M.read(s, tmp.data(), static_cast<size_t>(n) + 1);
            M.write(d, tmp.data(), static_cast<size_t>(n) + 1);
            ret(e.id == S_stpcpy ? d + n : d);
            break;
        }
        case S_strncpy: {
            u64 d = arg(0), s = arg(1), n = arg(2);
            needBlock("strncpy", n);
            std::vector<u8> tmp(static_cast<size_t>(n), 0);
            u64 i = 0;
            for (; i < n; ++i) {
                u8 c = u8(M.rd(s + i, 1));
                tmp[static_cast<size_t>(i)] = c;
                if (c == 0) break;
            }
            if (n) M.write(d, tmp.data(), static_cast<size_t>(n));
            ret(d);
            break;
        }
        case S_strcat: case S_strncat: {
            u64 d = arg(0), s = arg(1);
            u64 dn = M.strlenGuest(d, kMaxScan);
            u64 sn = M.strlenGuest(s, kMaxScan);
            if (e.id == S_strncat) { u64 lim = arg(2); if (sn > lim) sn = lim; }
            std::vector<u8> tmp(static_cast<size_t>(sn) + 1, 0);
            if (sn) M.read(s, tmp.data(), static_cast<size_t>(sn));
            M.write(d + dn, tmp.data(), static_cast<size_t>(sn) + 1);
            ret(d);
            break;
        }
        case S_strcmp: case S_strncmp: {
            u64 a = arg(0), b = arg(1);
            u64 lim = e.id == S_strncmp ? arg(2) : kMaxScan;
            if (lim > kMaxScan) lim = kMaxScan;
            i64 r = 0;
            for (u64 i = 0; i < lim; ++i) {
                int x = int(M.rd(a + i, 1)), y = int(M.rd(b + i, 1));
                if (x != y) { r = x - y; break; }
                if (x == 0) break;
            }
            ret(u64(r));
            break;
        }
        case S_strchr: case S_strrchr: {
            u64 a = arg(0); u8 c = u8(arg(1));
            u64 n = M.strlenGuest(a, kMaxScan);
            u64 found = 0;
            for (u64 i = 0; i <= n; ++i) {
                if (u8(M.rd(a + i, 1)) == c) {
                    found = a + i;
                    if (e.id == S_strchr) break;
                }
            }
            ret(found);
            break;
        }
        case S_strstr: {
            u64 h = arg(0), nd = arg(1);
            u64 hn = M.strlenGuest(h, kMaxScan), nn = M.strlenGuest(nd, kMaxScan);
            u64 found = 0;
            if (nn == 0) found = h;
            else if (nn <= hn) {
                std::vector<u8> hb(static_cast<size_t>(hn)), nb(static_cast<size_t>(nn));
                M.read(h, hb.data(), static_cast<size_t>(hn));
                M.read(nd, nb.data(), static_cast<size_t>(nn));
                for (u64 i = 0; i + nn <= hn; ++i)
                    if (std::memcmp(hb.data() + i, nb.data(), static_cast<size_t>(nn)) == 0) {
                        found = h + i; break;
                    }
            }
            ret(found);
            break;
        }
        case S_strdup: case S_strndup: {
            u64 s = arg(0);
            u64 n = M.strlenGuest(s, kMaxScan);
            if (e.id == S_strndup) { u64 lim = arg(1); if (n > lim) n = lim; }
            u64 p = sb.alloc(n + 1);
            if (p) {
                std::vector<u8> tmp(static_cast<size_t>(n) + 1, 0);
                if (n) M.read(s, tmp.data(), static_cast<size_t>(n));
                M.write(p, tmp.data(), static_cast<size_t>(n) + 1);
            }
            ret(p);
            break;
        }
        case S_malloc: case S_new: {
            u64 n = arg(0);
            u64 p = sb.alloc(n);
            ret(p);
            break;
        }
        case S_calloc: {
            u64 n = arg(0) * arg(1);
            needBlock("calloc", n);
            u64 p = sb.alloc(n);
            if (p && n) {
                std::vector<u8> z(static_cast<size_t>(n), 0);
                M.write(p, z.data(), static_cast<size_t>(n));
            }
            ret(p);
            break;
        }
        case S_realloc: {
            u64 old = arg(0), n = arg(1);
            needBlock("realloc", n);
            u64 p = sb.alloc(n);
            if (p && old && n) {
                // The old size is not knowable; copy what the new block holds,
                // which is the most a caller can legitimately read back.
                std::vector<u8> tmp(static_cast<size_t>(n));
                M.read(old, tmp.data(), static_cast<size_t>(n));
                M.write(p, tmp.data(), static_cast<size_t>(n));
            }
            ret(p);
            break;
        }
        case S_free: case S_delete: ret(0); break;

        case S_abort: case S_stackfail: {
            throw EmuHalt{EmuStop::Aborted,
                          std::string("the code called ") + e.name +
                          " at " + hex(addr.getOffset())};
        }
        case S_exit: {
            char b[96];
            std::snprintf(b, sizeof b, "the code called exit(%lld)",
                          (long long)i64(arg(0)));
            throw EmuHalt{EmuStop::Aborted, b};
        }
        case S_assert: {
            throw EmuHalt{EmuStop::Aborted,
                          "the code failed an assertion (" + e.name + ")"};
        }

        case S_log: {
            // The tag and format string are usually the most informative
            // thing an obfuscated library hands us for free.
            std::string tag = M.cstr(arg(1), 96);
            std::string fmt = M.cstr(arg(2), 200);
            M.pendingNote = tag.empty() ? fmt : (tag + ": " + fmt);
            ret(1);
            break;
        }
        case S_logwrite: {
            std::string tag = M.cstr(arg(1), 96);
            std::string msg = M.cstr(arg(2), 200);
            M.pendingNote = tag.empty() ? msg : (tag + ": " + msg);
            ret(1);
            break;
        }

        // Deterministic, so a timing check folds the same way every run.
        case S_time: {
            u64 t = 1700000000ULL;
            if (arg(0)) M.wr(arg(0), M.abi.ptrSize, t);
            ret(t);
            break;
        }
        case S_clockgettime: {
            u64 p = arg(1);
            if (p) { M.wr(p, M.abi.ptrSize, 1700000000ULL);
                     M.wr(p + u64(M.abi.ptrSize), M.abi.ptrSize, 0); }
            ret(0);
            break;
        }
        case S_gettimeofday: {
            u64 p = arg(0);
            if (p) { M.wr(p, M.abi.ptrSize, 1700000000ULL);
                     M.wr(p + u64(M.abi.ptrSize), M.abi.ptrSize, 0); }
            ret(0);
            break;
        }
        case S_getpid: ret(1234); break;
        case S_gettid: ret(1234); break;
        case S_pthreadself: ret(sb.stackHi); break;
        case S_errno: ret(sb.errnoAddr); break;
        case S_zero: ret(0); break;

        case S_toupper: { u64 c = arg(0); ret(c >= 'a' && c <= 'z' ? c - 32 : c); break; }
        case S_tolower: { u64 c = arg(0); ret(c >= 'A' && c <= 'Z' ? c + 32 : c); break; }
        case S_isalpha: { u64 c = arg(0); ret((c|32) >= 'a' && (c|32) <= 'z'); break; }
        case S_isdigit: { u64 c = arg(0); ret(c >= '0' && c <= '9'); break; }
        case S_isalnum: { u64 c = arg(0);
                          ret(((c|32) >= 'a' && (c|32) <= 'z') || (c >= '0' && c <= '9')); break; }
        case S_isupper: { u64 c = arg(0); ret(c >= 'A' && c <= 'Z'); break; }
        case S_islower: { u64 c = arg(0); ret(c >= 'a' && c <= 'z'); break; }
        case S_isspace: { u64 c = arg(0);
                          ret(c == ' ' || (c >= 9 && c <= 13)); break; }
        case S_isxdigit: { u64 c = arg(0);
                           ret((c >= '0' && c <= '9') || ((c|32) >= 'a' && (c|32) <= 'f')); break; }
        case S_atoi: {
            std::string s = M.cstr(arg(0), 32);
            ret(u64(i64(strtoll(s.c_str(), nullptr, 10))));
            break;
        }

        case S_none:
        default:
            // Everything else: zero, and the answer says so by name.
            ret(0);
            done = false;
            break;
    }

    doReturn();
    return done;
}

} // namespace

// ------------------------------------------------------------------ Impl --
struct GhidraEmu::Impl {
    EmuArchitecture* arch = nullptr;
    std::string key, language, backend;
    std::map<u64, StubEntry> stubs;

    // Enough to build the architecture again. SleighArchitecture keeps one
    // Sleigh per language in a process-wide static map and rebinds it to the
    // loader and context of whichever Architecture was built last — so when
    // the decompiler binds itself to a different image, ours has to be built
    // again before it can be trusted to read bytes.
    // SleighArchitecture keeps this pointer and writes to it from
    // printWarning() for the whole life of the architecture, so it cannot be
    // a local in the function that builds one.
    std::ostringstream errors;
    const u8* image = nullptr;
    size_t size = 0;
    std::vector<GhidraSeg> segs;
    std::vector<std::pair<u64, char>> armMapping;
    bool rebind = false;

    bool build(std::string& err);
    ~Impl() { delete arch; }
};

bool GhidraEmu::Impl::build(std::string& err) {
    delete arch;
    arch = nullptr;
    errors.str(std::string());
    try {
        initLibraryOnce();
        arch = new EmuArchitecture(language, &errors, image, size, segs);
        DocumentStorage store;
        arch->init(store);
        backend = "Ghidra p-code (" + language + ")";
    } catch (LowlevelError& e) {
        err = e.explain.empty() ? errors.str() : e.explain;
        if (err.empty()) err = "could not build the architecture";
        delete arch; arch = nullptr;
        return false;
    } catch (std::exception& e) {
        err = e.what();
        delete arch; arch = nullptr;
        return false;
    } catch (...) {
        err = "unknown failure building the architecture";
        delete arch; arch = nullptr;
        return false;
    }

    // Same reason as the decompiler: without the mapping symbols every Thumb
    // region would be emulated as ARM, one confident instruction at a time.
    if (language == "ARM:LE:32:v7" && !armMapping.empty()) {
        try {
            ContextDatabase* ctx = arch->context;
            AddrSpace* code = arch->getDefaultCodeSpace();
            for (size_t i = 0; i < armMapping.size(); ++i) {
                char kind = armMapping[i].second;
                if (kind != 'a' && kind != 't') continue;
                u64 from = armMapping[i].first;
                u64 to = (i + 1 < armMapping.size()) ? armMapping[i + 1].first : from + 4;
                if (to <= from) continue;
                ctx->setVariableRegion("TMode", Address(code, from),
                                       Address(code, to - 1), kind == 't' ? 1 : 0);
            }
        } catch (...) {}
    }
    rebind = false;
    return true;
}

GhidraEmu& GhidraEmu::instance() { static GhidraEmu g; return g; }
GhidraEmu::~GhidraEmu() { delete impl_; }

bool GhidraEmu::ready() const { return impl_ != nullptr && impl_->arch != nullptr; }

std::string GhidraEmu::backendName() const {
    return impl_ ? impl_->backend : std::string();
}

void GhidraEmu::close() {
    std::lock_guard<std::mutex> lock(emuMutex());
    delete impl_;
    impl_ = nullptr;
}

void GhidraEmu::translatorRebound() {
    std::lock_guard<std::mutex> lock(emuMutex());
    if (impl_) impl_->rebind = true;
}

std::vector<std::string> GhidraEmu::modelledImports() {
    std::vector<std::string> out;
    out.reserve(static_cast<size_t>(kStubCount));
    for (int i = 0; i < kStubCount; ++i) out.push_back(kStubs[i].name);
    return out;
}

bool GhidraEmu::open(const std::string& key, const std::string& arch,
                     const u8* image, size_t size,
                     const std::vector<GhidraSeg>& segs,
                     const std::vector<std::pair<u64, std::string>>& stubs,
                     const std::vector<std::pair<u64, char>>& armMapping,
                     std::string& err) {
    err.clear();
    if (image == nullptr || size == 0) { err = "empty image"; return false; }

    std::string lang = GhidraDecomp::languageFor(arch);
    if (lang.empty()) { err = "no SLEIGH specification for " + arch; return false; }
    {
        Abi probe;
        if (!abiFor(lang, probe)) {
            err = "no calling convention modelled for " + lang +
                  " (the emulator covers AArch64, ARM32 and x86)";
            return false;
        }
    }

    std::lock_guard<std::mutex> lock(emuMutex());
    if (impl_ && impl_->arch && impl_->key == key && impl_->language == lang) return true;

    delete impl_;
    impl_ = new Impl();
    impl_->key = key;
    impl_->language = lang;
    impl_->image = image;
    impl_->size = size;
    impl_->segs = segs;
    impl_->armMapping = armMapping;

    if (!impl_->build(err)) { delete impl_; impl_ = nullptr; return false; }

    for (const auto& s : stubs) {
        if (s.second.empty() || s.first == 0) continue;
        StubEntry e;
        e.name = s.second;
        e.id = stubFor(s.second);
        e.known = knownProto(s.second, &e.retKind);
        impl_->stubs[s.first] = e;
    }
    return true;
}

EmuResult GhidraEmu::run(const EmuRequest& req) {
    EmuResult res;
    res.entry = req.entry;
    res.args = req.args;

    std::lock_guard<std::mutex> lock(emuMutex());
    if (!impl_ || !impl_->arch) {
        res.detail = "no architecture bound";
        return res;
    }
    res.backend = impl_->backend;

    if (impl_->rebind) {
        std::string err;
        if (!impl_->build(err)) {
            res.detail = "could not rebuild the architecture: " + err;
            return res;
        }
    }

    EmuArchitecture* arch = impl_->arch;
    Translate* trans = const_cast<Translate*>(arch->translate);
    AddrSpace* ram = arch->getDefaultCodeSpace();
    EmuLoadImage* img = static_cast<EmuLoadImage*>(arch->loader);


    Machine M;
    M.trans = trans;
    M.ram = ram;
    M.img = img;
    if (!abiFor(impl_->language, M.abi)) {
        res.detail = "the emulator does not model the calling convention for " +
                     impl_->language + " yet";
        return res;
    }
    M.limits = req.limits;
    if (M.limits.maxInstructions == 0 || M.limits.maxInstructions > 20000000)
        M.limits.maxInstructions = 200000;
    if (M.limits.timeoutMs == 0 || M.limits.timeoutMs > 60000)
        M.limits.timeoutMs = 3000;
    if (M.limits.maxPages == 0 || M.limits.maxPages > 16384) M.limits.maxPages = 1024;
    if (M.limits.maxCalls == 0) M.limits.maxCalls = 4096;

    // Keep the sandbox clear of anything the image maps. A library built for
    // a fixed base could in principle sit anywhere.
    u64 shift = 0;
    // (the layout constants are chosen above any ELF/PE image we load, but
    //  check rather than assume)
    for (int attempt = 0; attempt < 8; ++attempt) {
        M.sb.layout(M.abi.ptrSize, shift);
        // Ask the load image rather than assume: any sandbox page that reads
        // back as mapped file data would have the guest's stack on top of the
        // binary.
        bool clash = false;
        u8 probe[1];
        if (img->original(M.sb.stackLo, probe, 1) ||
            img->original(M.sb.heapLo, probe, 1) ||
            img->original(M.sb.magic, probe, 1)) clash = true;
        if (!clash) break;
        shift += (M.abi.ptrSize == 8) ? 0x0000010000000000ULL : 0x01000000u;
    }

    const auto t0 = std::chrono::steady_clock::now();

    // Memory: the image underneath, a page overlay on top that records what
    // it writes, and hash overlays for the register and temporary spaces.
    MemoryImage base(ram, M.abi.ptrSize, 4096, img);
    TrackedOverlay overlay(ram, M.abi.ptrSize, 4096, &base, M.limits.maxPages);
    MemoryState mem(trans);
    mem.setMemoryBank(&overlay);
    M.mem = &mem;
    M.overlay = &overlay;

    std::vector<MemoryBank*> extra;
    for (int4 i = 0; i < trans->numSpaces(); ++i) {
        AddrSpace* spc = trans->getSpace(i);
        if (spc == nullptr || spc == ram) continue;
        spacetype t = spc->getType();
        if (t != IPTR_PROCESSOR && t != IPTR_INTERNAL && t != IPTR_SPACEBASE) continue;
        MemoryBank* b = new MemoryHashOverlay(spc, 8, 4096, 4096, (MemoryBank*)0);
        extra.push_back(b);
        mem.setMemoryBank(b);
    }

    // Instruction fetch sees what the guest wrote, so code unpacked in memory
    // is emulated as the bytes that landed, not as the bytes in the file.
    img->attachRam(&overlay);

    std::vector<std::string> useropNames;
    trans->getUserOpNames(useropNames);

    BreakTableCallBack breaks(trans);
    StubBreak stubCb;
    stubCb.m = &M;
    stubCb.table = &impl_->stubs;
    UseropBreak useropCb;
    useropCb.m = &M;
    useropCb.names = useropNames;

    Emu emu(trans, &mem, &breaks, &M, M.sb.magic);

    for (const auto& kv : impl_->stubs)
        breaks.registerAddressCallback(Address(ram, kv.first), &stubCb);
    for (size_t i = 0; i < useropNames.size(); ++i) {
        if (useropNames[i].empty()) continue;
        try { breaks.registerPcodeCallback(useropNames[i], &useropCb); }
        catch (LowlevelError&) {}
    }

    u64 instructions = 0;
    EmuStop stop = EmuStop::Setup;
    std::string detail;

    try {
        // ---- initial state ----
        if (!M.setReg(M.abi.sp, M.sb.sp0))
            throw EmuHalt{EmuStop::Setup,
                          "the specification has no register named '" + M.abi.sp + "'"};
        if (M.abi.retOnStack) {
            u64 sp = M.sb.sp0 - u64(M.abi.ptrSize);
            M.wr(sp, M.abi.ptrSize, M.sb.magic);
            M.setReg(M.abi.sp, sp);
        } else if (!M.abi.lr.empty()) {
            M.setReg(M.abi.lr, M.sb.magic);
        }

        for (const auto& s : req.seeds)
            if (!s.bytes.empty()) M.write(s.addr, s.bytes.data(), s.bytes.size());

        for (size_t i = 0; i < res.args.size(); ++i) {
            EmuArg& a = res.args[i];
            if (a.kind == EmuArg::Buffer) {
                a.value = M.sb.alloc(a.len ? a.len : 1);
                if (a.value == 0)
                    throw EmuHalt{EmuStop::Setup, "the sandbox heap could not hold a buffer that large"};
                if (a.len) {
                    std::vector<u8> z(a.len, 0);
                    M.write(a.value, z.data(), z.size());
                }
            } else if (a.kind == EmuArg::Data) {
                a.value = M.sb.alloc(a.data.empty() ? 1 : a.data.size());
                if (a.value == 0)
                    throw EmuHalt{EmuStop::Setup, "the sandbox heap could not hold an argument that large"};
                if (!a.data.empty()) M.write(a.value, a.data.data(), a.data.size());
                a.len = u32(a.data.size());
            }
            if (i < M.abi.argRegs.size()) {
                a.reg = M.abi.argRegs[i];
                M.setReg(a.reg, a.value);
            } else {
                size_t slot = i - M.abi.argRegs.size();
                u64 sp = M.getReg(M.abi.sp);
                u64 at = sp + (M.abi.retOnStack ? u64(M.abi.ptrSize) : 0)
                            + u64(slot) * u64(M.abi.ptrSize);
                M.wr(at, M.abi.ptrSize, a.value);
                a.reg = "[sp+" + std::to_string(slot * static_cast<size_t>(M.abi.ptrSize)) + "]";
            }
        }

        // Raw overrides run last so they can correct anything above.
        for (const auto& r : req.regs) {
            if (!M.setReg(r.first, r.second))
                throw EmuHalt{EmuStop::Setup, "no register named '" + r.first + "'"};
        }

        emu.setExecuteAddress(Address(ram, req.entry));

        const auto deadline = t0 + std::chrono::milliseconds(M.limits.timeoutMs);
        for (;;) {
            u64 pc = emu.getExecuteAddress().getOffset();
            if (req.stopAt && pc == req.stopAt && instructions > 0) {
                stop = EmuStop::StopAddress;
                detail = "reached " + hex(req.stopAt);
                break;
            }
            if (instructions >= M.limits.maxInstructions) {
                char b[110];
                std::snprintf(b, sizeof b,
                              "instruction budget exhausted after %llu instructions, still at %s",
                              (unsigned long long)instructions, hex(pc).c_str());
                stop = EmuStop::Budget;
                detail = b;
                break;
            }
            if ((instructions & 511u) == 0 &&
                std::chrono::steady_clock::now() > deadline) {
                char b[128];
                std::snprintf(b, sizeof b,
                              "wall-clock limit of %u ms reached after %llu instructions, still at %s",
                              M.limits.timeoutMs, (unsigned long long)instructions,
                              hex(pc).c_str());
                stop = EmuStop::Timeout;
                detail = b;
                break;
            }
            M.pushTail(pc);
            emu.executeInstruction();
            ++instructions;
        }
    } catch (EmuHalt& h) {
        stop = h.kind;
        detail = h.detail;
    } catch (DataUnavailError& e) {
        stop = EmuStop::Fault;
        detail = "executed unmapped memory: " + e.explain;
    } catch (UnimplError& e) {
        // SLEIGH reports a branch to an odd address this way. That is not a
        // gap in the specification, it is the machine being somewhere it
        // cannot be, and calling it "unimplemented" would send the user
        // looking for the wrong thing.
        if (e.explain.find("not aligned") != std::string::npos) {
            stop = EmuStop::Fault;
            detail = "branched to a misaligned address (" + e.explain + ")";
        } else {
            stop = EmuStop::Unimplemented;
            detail = "the specification has no semantics for the instruction at " +
                     hex(emu.getExecuteAddress().getOffset()) +
                     (e.explain.empty() ? std::string() : (" (" + e.explain + ")"));
        }
    } catch (BadDataError& e) {
        stop = EmuStop::Unimplemented;
        detail = "undecodable instruction at " +
                 hex(emu.getExecuteAddress().getOffset()) +
                 (e.explain.empty() ? std::string() : (" (" + e.explain + ")"));
    } catch (LowlevelError& e) {
        stop = EmuStop::Fault;
        detail = e.explain.empty() ? std::string("the emulator could not continue")
                                   : e.explain;
    } catch (std::bad_alloc&) {
        stop = EmuStop::MemoryCap;
        detail = "out of memory";
    } catch (std::exception& e) {
        stop = EmuStop::Fault;
        detail = e.what();
    } catch (...) {
        stop = EmuStop::Fault;
        detail = "unknown emulator failure";
    }

    const auto t1 = std::chrono::steady_clock::now();
    res.ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    res.instructions = instructions;
    res.stop = stop;
    res.detail = detail;
    res.ok = (stop == EmuStop::Completed || stop == EmuStop::StopAddress);
    res.approximate = M.approximate;
    res.calls = M.calls;
    res.callsTotal = M.callsTotal;
    res.stackBase = M.sb.sp0;
    res.heapBase = M.sb.heapLo;
    res.heapUsed = M.sb.heapNext - M.sb.heapLo;
    for (const auto& kv : M.userops) res.userops.push_back(kv.second);
    res.useropsDropped = M.useropsDropped;

    {
        u32 n = M.tailN < 64 ? M.tailN : 64;
        u32 first = M.tailN < 64 ? 0 : M.tailN - 64;
        for (u32 i = 0; i < n; ++i) res.tail.push_back(M.tail[(first + i) % 64]);
    }

    // ---- what came back ----
    // Reading the machine state can itself throw (a register the spec does
    // not have, a page the bank refuses); none of that may lose the stop
    // reason we already have.
    try {
        res.retReg = M.abi.ret;
        res.ret = M.getReg(M.abi.ret);
        for (const auto& r : M.abi.report) {
            bool ok = false;
            u64 v = M.getReg(r, &ok);
            if (ok) res.regs.push_back({r, v});
        }
    } catch (...) {}

    auto grab = [&](u64 addr, u32 len, const std::string& label) {
        if (len == 0) return;
        if (len > 4096) len = 4096;
        EmuBytes b;
        b.addr = addr;
        b.label = label;
        b.bytes.resize(len);
        try { M.read(addr, b.bytes.data(), len); }
        catch (...) { return; }
        res.memory.push_back(b);
    };

    try {
        for (size_t i = 0; i < res.args.size(); ++i) {
            const EmuArg& a = res.args[i];
            if (a.kind == EmuArg::Value || a.value == 0) continue;
            grab(a.value, a.len, "arg" + std::to_string(i));
        }
        for (const auto& w : req.windows) grab(w.first, w.second, "window");
    } catch (...) {}

    // Everything the run changed, worked out by diffing the pages it dirtied
    // against the bytes the file holds. This is the answer to "show me what
    // it wrote", and it is exact: a page is in the set only because a store
    // landed on it.
    try {
        const u64 ps = 4096;
        std::vector<u8> now(static_cast<size_t>(ps)), was(static_cast<size_t>(ps));
        std::vector<std::pair<u64, u64>> ranges;    // [lo, hi)
        u64 changed = 0;
        for (u64 page : overlay.dirtyPages()) {
            if (M.sb.inStack(page)) continue;       // the stack is noise
            M.read(page, now.data(), static_cast<size_t>(ps));
            if (!img->original(page, was.data(), static_cast<size_t>(ps)))
                std::memset(was.data(), 0, static_cast<size_t>(ps));
            u64 i = 0;
            while (i < ps) {
                if (now[static_cast<size_t>(i)] == was[static_cast<size_t>(i)]) { ++i; continue; }
                u64 lo = i, gap = 0, hi = i;
                while (i < ps && gap <= 16) {
                    if (now[static_cast<size_t>(i)] != was[static_cast<size_t>(i)]) { hi = i + 1; gap = 0; }
                    else ++gap;
                    ++i;
                }
                changed += hi - lo;
                if (!ranges.empty() && ranges.back().second == page + lo)
                    ranges.back().second = page + hi;
                else
                    ranges.push_back({page + lo, page + hi});
            }
        }
        res.dirtyBytes = changed;
        res.dirtyRanges = u32(ranges.size());
        u64 budget = 4096;
        for (const auto& r : ranges) {
            if (budget == 0 || res.memory.size() >= 24) { res.memoryTruncated = true; break; }
            u64 len = r.second - r.first;
            if (len > budget) { len = budget; res.memoryTruncated = true; }
            grab(r.first, u32(len), "wrote");
            budget -= len;
        }
    } catch (...) {}

    img->attachRam(nullptr);
    for (MemoryBank* b : extra) delete b;
    return res;
}

#endif // SAKO_HAVE_GHIDRA

} // namespace sako
