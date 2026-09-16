#include "GhidraArch.h"

#include <cstdio>
#include <cstring>
#include <mutex>

#ifdef SAKO_HAVE_GHIDRA
#include "architecture.hh"
#include "funcdata.hh"
#include "loadimage.hh"
#include "printc.hh"
#include "sleigh_arch.hh"
#include <sstream>
#endif

namespace sako {

bool GhidraDecomp::compiledIn() {
#ifdef SAKO_HAVE_GHIDRA
    return true;
#else
    return false;
#endif
}

std::string GhidraDecomp::languageFor(const std::string& arch) {
    // Only the specifications shipped in assets/sleigh. Anything else falls
    // back to the built-in IR lifter rather than failing.
    if (arch == "ARM64")  return "AARCH64:LE:64:v8A";
    if (arch == "ARM")    return "ARM:LE:32:v7";
    if (arch == "THUMB")  return "ARM:LE:32:v7";
    if (arch == "X86_64") return "x86:LE:64:default";
    if (arch == "X86")    return "x86:LE:32:default";
    return std::string();
}

#ifndef SAKO_HAVE_GHIDRA

// ------------------------------------------------------ not compiled in ---
struct GhidraDecomp::Impl {};
GhidraDecomp& GhidraDecomp::instance() { static GhidraDecomp g; return g; }
GhidraDecomp::~GhidraDecomp() = default;
void GhidraDecomp::setSpecDir(const std::string& d) { specDir_ = d; }
void GhidraDecomp::close() {}
bool GhidraDecomp::ready() const { return false; }
std::string GhidraDecomp::backendName() const { return std::string(); }
bool GhidraDecomp::open(const std::string&, const std::string&, const u8*, size_t,
                        const std::vector<GhidraSeg>&,
                        const std::vector<std::pair<u64, std::string>>&,
                        const std::vector<FoundString>&,
                        std::string& err) {
    err = "built without the Ghidra decompiler";
    return false;
}
std::string GhidraDecomp::decompile(u64, const std::string&, std::string& err) {
    err = "built without the Ghidra decompiler";
    return std::string();
}

#else

using namespace ghidra;

namespace {

std::mutex& ghidraMutex() { static std::mutex m; return m; }

// The decompiler reads bytes through this, not from a file. Unmapped
// addresses must raise DataUnavailError: the flow follower uses it to decide
// where code stops, and zero-filling instead would make it decode padding.
class MemLoadImage : public LoadImage {
    const u8* image_ = nullptr;
    size_t size_ = 0;
    std::vector<GhidraSeg> segs_;
    AddrSpace* space_ = nullptr;

public:
    MemLoadImage(const u8* image, size_t size, std::vector<GhidraSeg> segs)
        : LoadImage("nocturne"), image_(image), size_(size), segs_(std::move(segs)) {}

    void attachToSpace(AddrSpace* s) { space_ = s; }

    void loadFill(uint1* ptr, int4 size, const Address& addr) override {
        if (size <= 0) return;
        uint64_t va = addr.getOffset();
        std::memset(ptr, 0, size_t(size));
        bool any = false;
        for (const GhidraSeg& s : segs_) {
            uint64_t segEnd = s.vaddr + s.memsz;
            if (va + uint64_t(size) <= s.vaddr || va >= segEnd) continue;
            uint64_t from = va > s.vaddr ? va : s.vaddr;
            uint64_t to = va + uint64_t(size);
            uint64_t fileEnd = s.vaddr + s.filesz;
            if (to > fileEnd) to = fileEnd;        // .bss tail stays zero
            if (to <= from) continue;
            uint64_t src = s.fileoff + (from - s.vaddr);
            if (src > size_ || src + (to - from) > size_) continue;
            std::memcpy(ptr + (from - va), image_ + src, size_t(to - from));
            any = true;
        }
        if (!any) {
            // getShortcut() returns a char, so concatenating it onto a string
            // literal would be pointer arithmetic past the end of the literal.
            char buf[48];
            std::snprintf(buf, sizeof buf, "no image data at 0x%llX",
                          (unsigned long long)va);
            throw DataUnavailError(std::string(buf));
        }
    }

    // Marking the non-writable segments read-only is what lets constants be
    // folded out of .rodata — and with them, string literals recognised.
    void getReadonly(RangeList& list) const override {
        if (space_ == nullptr) return;
        for (const GhidraSeg& s : segs_) {
            if (s.writable || !s.filesz) continue;
            list.insertRange(space_, s.vaddr, s.vaddr + s.filesz - 1);
        }
    }

    string getArchType(void) const override { return "nocturne"; }
    void adjustVma(long) override {}
};

// SleighArchitecture wants to open a file; this one is handed its bytes.
class MemArchitecture : public SleighArchitecture {
    const u8* image_;
    size_t size_;
    std::vector<GhidraSeg> segs_;

    void buildLoader(DocumentStorage& store) override {
        collectSpecFiles(*errorstream);
        loader = new MemLoadImage(image_, size_, segs_);
    }
    void resolveArchitecture(void) override {
        archid = getTarget();     // the caller already chose the language
        SleighArchitecture::resolveArchitecture();
    }
    void postSpecFile(void) override {
        Architecture::postSpecFile();
        static_cast<MemLoadImage*>(loader)->attachToSpace(getDefaultCodeSpace());
    }
    // Without a <coretypes> document the base class names unknown types
    // "xunknown4". These are the names Ghidra's own output uses.
    void buildCoreTypes(DocumentStorage& store) override {
        types->setCoreType("void", 1, TYPE_VOID, false);
        types->setCoreType("bool", 1, TYPE_BOOL, false);
        types->setCoreType("byte", 1, TYPE_UINT, false);
        types->setCoreType("ushort", 2, TYPE_UINT, false);
        types->setCoreType("uint", 4, TYPE_UINT, false);
        types->setCoreType("ulong", 8, TYPE_UINT, false);
        types->setCoreType("char", 1, TYPE_INT, true);
        types->setCoreType("short", 2, TYPE_INT, false);
        types->setCoreType("int", 4, TYPE_INT, false);
        types->setCoreType("long", 8, TYPE_INT, false);
        types->setCoreType("float", 4, TYPE_FLOAT, false);
        types->setCoreType("double", 8, TYPE_FLOAT, false);
        types->setCoreType("float10", 10, TYPE_FLOAT, false);
        types->setCoreType("float16", 16, TYPE_FLOAT, false);
        types->setCoreType("undefined1", 1, TYPE_UNKNOWN, false);
        types->setCoreType("undefined2", 2, TYPE_UNKNOWN, false);
        types->setCoreType("undefined4", 4, TYPE_UNKNOWN, false);
        types->setCoreType("undefined8", 8, TYPE_UNKNOWN, false);
        types->setCoreType("code", 1, TYPE_CODE, false);
        types->setCoreType("wchar2", 2, TYPE_INT, true);
        types->setCoreType("wchar4", 4, TYPE_INT, true);
        types->cacheCoreTypes();
    }

public:
    MemArchitecture(const string& target, ostream* estream,
                    const u8* image, size_t size, std::vector<GhidraSeg> segs)
        : SleighArchitecture("nocturne", target, estream),
          image_(image), size_(size), segs_(std::move(segs)) {}
};

// One-time registration of the decompiler's capabilities. startDecompilerLibrary()
// would do this too, but it lives in libdecomp.cc, which drags in the console
// front end we deliberately do not vendor.
void initLibraryOnce() {
    static bool done = false;
    if (done) return;
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    ArchitectureCapability::sortCapabilities();
    done = true;
}

} // namespace

struct GhidraDecomp::Impl {
    MemArchitecture* arch = nullptr;
    std::string key, language, backend;
    std::vector<std::string> addedPaths;

    ~Impl() { delete arch; }
};

GhidraDecomp& GhidraDecomp::instance() { static GhidraDecomp g; return g; }

GhidraDecomp::~GhidraDecomp() { delete impl_; }

void GhidraDecomp::setSpecDir(const std::string& dir) {
    std::lock_guard<std::mutex> lock(ghidraMutex());
    if (dir == specDir_) return;
    specDir_ = dir;
    initLibraryOnce();
    // specpaths is static and append-only upstream, so only ever add a
    // directory once; a duplicate would make every spec lookup scan it twice.
    static std::vector<std::string> seen;
    for (const std::string& s : seen) if (s == dir) return;
    seen.push_back(dir);
    SleighArchitecture::specpaths.addDir2Path(dir);
}

bool GhidraDecomp::ready() const { return impl_ != nullptr && impl_->arch != nullptr; }

std::string GhidraDecomp::backendName() const {
    return impl_ ? impl_->backend : std::string();
}

void GhidraDecomp::close() {
    std::lock_guard<std::mutex> lock(ghidraMutex());
    delete impl_;
    impl_ = nullptr;
}

bool GhidraDecomp::open(const std::string& key, const std::string& arch,
                        const u8* image, size_t size,
                        const std::vector<GhidraSeg>& segs,
                        const std::vector<std::pair<u64, std::string>>& funcs,
                        const std::vector<FoundString>& strings,
                        std::string& err) {
    err.clear();
    if (specDir_.empty()) { err = "no SLEIGH specification directory"; return false; }
    if (image == nullptr || size == 0) { err = "empty image"; return false; }

    std::string lang = languageFor(arch);
    if (lang.empty()) { err = "no SLEIGH specification for " + arch; return false; }

    std::lock_guard<std::mutex> lock(ghidraMutex());
    if (impl_ && impl_->arch && impl_->key == key && impl_->language == lang) return true;

    delete impl_;
    impl_ = new Impl();
    impl_->key = key;
    impl_->language = lang;

    std::ostringstream estream;
    try {
        initLibraryOnce();
        impl_->arch = new MemArchitecture(lang, &estream, image, size, segs);
        DocumentStorage store;
        impl_->arch->init(store);
        // A runaway function must not take the process with it.
        impl_->arch->max_instructions = 200000;
        impl_->backend = "Ghidra p-code (" + lang + ")";
    } catch (LowlevelError& e) {
        err = e.explain;
        if (err.empty()) err = estream.str();
        delete impl_; impl_ = nullptr;
        return false;
    } catch (DecoderError& e) {
        err = e.explain;
        delete impl_; impl_ = nullptr;
        return false;
    } catch (std::exception& e) {
        err = e.what();
        delete impl_; impl_ = nullptr;
        return false;
    } catch (...) {
        err = "unknown failure building the architecture";
        delete impl_; impl_ = nullptr;
        return false;
    }

    // Publishing the known functions is what turns a call into a name. Doing
    // it up front also gives the decompiler somewhere to stop following flow.
    try {
        Scope* scope = impl_->arch->symboltab->getGlobalScope();
        AddrSpace* code = impl_->arch->getDefaultCodeSpace();
        for (const auto& f : funcs) {
            if (f.second.empty()) continue;
            Address a(code, f.first);
            if (scope->queryFunction(a) != nullptr) continue;
            try { scope->addFunction(a, f.second); } catch (LowlevelError&) {}
        }
    } catch (...) {
        // Names are a nicety; a failure here must not lose the architecture.
    }

    // Typing the extracted strings as char arrays is what makes a pointer to
    // one print as the text instead of as its address. Without this the
    // decompiler has no reason to believe those bytes are a string.
    try {
        Scope* scope = impl_->arch->symboltab->getGlobalScope();
        AddrSpace* code = impl_->arch->getDefaultCodeSpace();
        Datatype* ch = impl_->arch->types->getTypeChar(1);
        size_t n = 0;
        for (const FoundString& fs : strings) {
            if (fs.value.empty() || fs.addr == 0) continue;
            if (++n > 20000) break;             // bounded: this is a nicety
            Address a(code, fs.addr);
            if (scope->queryContainer(a, 1, Address()) != nullptr) continue;
            Datatype* arr = impl_->arch->types->getTypeArray(int4(fs.value.size() + 1), ch);
            // Ghidra's own convention: put the text in the symbol name. A
            // literal would need the callee's prototype to declare char*,
            // which a stripped binary does not give us, so the name is where
            // the string becomes readable.
            std::string tag;
            for (char ch2 : fs.value) {
                if (tag.size() >= 24) break;
                if ((ch2 >= 'a' && ch2 <= 'z') || (ch2 >= 'A' && ch2 <= 'Z') ||
                    (ch2 >= '0' && ch2 <= '9') || ch2 == '_') tag += ch2;
                else if (!tag.empty() && tag.back() != '_') tag += '_';
            }
            while (!tag.empty() && tag.back() == '_') tag.pop_back();
            char addrbuf[24];
            std::snprintf(addrbuf, sizeof addrbuf, "%08llX", (unsigned long long)fs.addr);
            std::string sym = tag.empty() ? ("s_" + std::string(addrbuf))
                                          : ("s_" + tag + "_" + addrbuf);
            try {
                scope->addSymbol(sym, arr, a, Address());
            } catch (LowlevelError&) {}
        }
    } catch (...) {
        // Same: string typing is an improvement, not a requirement.
    }
    return true;
}

std::string GhidraDecomp::decompile(u64 addr, const std::string& name, std::string& err) {
    err.clear();
    std::lock_guard<std::mutex> lock(ghidraMutex());
    if (!impl_ || !impl_->arch) { err = "no architecture bound"; return std::string(); }

    try {
        Architecture* glb = impl_->arch;
        Address a(glb->getDefaultCodeSpace(), addr);
        Scope* scope = glb->symboltab->getGlobalScope();
        Funcdata* fd = scope->queryFunction(a);
        if (fd == nullptr) {
            std::string n = name.empty() ? ("sub_" + hexAddr(addr).substr(2)) : name;
            fd = scope->addFunction(a, n)->getFunction();
        }
        if (fd == nullptr) { err = "no function at that address"; return std::string(); }

        // A Funcdata already taken through the pipeline cannot be run again;
        // clearing it puts it back to the state a fresh one would be in.
        if (fd->isProcStarted()) {
            scope->removeSymbolMappings(fd->getSymbol());
            fd = scope->addFunction(a, fd->getName())->getFunction();
        }

        glb->allacts.setCurrent("decompile");
        Action* act = glb->allacts.getCurrent();
        act->reset(*fd);
        act->perform(*fd);

        std::ostringstream out;
        glb->print->setOutputStream(&out);
        glb->print->setMarkup(false);
        glb->print->docFunction(fd);
        std::string text = out.str();
        if (text.empty()) err = "decompiler produced no output";
        return text;
    } catch (LowlevelError& e) {
        err = e.explain.empty() ? std::string("decompiler error") : e.explain;
    } catch (DecoderError& e) {
        err = e.explain.empty() ? std::string("decoder error") : e.explain;
    } catch (std::bad_alloc&) {
        err = "out of memory decompiling this function";
    } catch (std::exception& e) {
        err = e.what();
    } catch (...) {
        err = "unknown decompiler failure";
    }
    return std::string();
}

#endif // SAKO_HAVE_GHIDRA

} // namespace sako
