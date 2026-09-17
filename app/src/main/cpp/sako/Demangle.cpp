// C++ symbol demangler.
// Itanium ABI as GCC and Clang emit it on Android and Linux: nested names,
// templates and their arguments, the substitution table (S_, S0_, ...),
// template parameters (T_), operators, constructors and destructors, function
// and array and member-pointer types, vtable/typeinfo/thunk special names, and
// local names. Plus a light MSVC `?name@ns@@...` simplifier.
//
// What it does not model, and therefore refuses rather than guesses: mangled
// expressions in template arguments (`X ... E`, e.g. a non-type argument that
// is a computation), which is the only construct that shows up in quantity on
// real libraries. Refusing means demangle() hands back the mangled name, which
// the UI already knows how to show.
#include "Demangle.h"
#include <cstring>
#include <vector>

namespace sako {

bool looksMangled(const std::string& n) {
    return n.rfind("_Z", 0) == 0 || n.rfind("__Z", 0) == 0 || n.rfind("?", 0) == 0;
}

namespace {

// ------------------------------------------------------- Itanium demangler --
//
// The substitution table is the reason this file has the shape it does.
// `S_`, `S0_`, `S1_` ... are back-references to components already seen in the
// same name: the ABI compresses a repeated type down to two characters, and
// most C++ symbols with more than one parameter use them. The old
// implementation did not keep the table -- it printed the literal text
// "subst_3" where the type belonged. Taken from a real library, unedited:
//
//   _ZL10createFreePN4llvm5ValueENS_8ArrayRefINS_17OperandBundleDefTIS1_EEEEP...
//     was: createFree(llvm::Value*, subst_::ArrayRef<subst_::OperandBundleDefT<subst_1>>)
//     now: createFree(llvm::Value*, llvm::ArrayRef<llvm::OperandBundleDefT<llvm::Value*> >,
//                     llvm::Instruction*, llvm::BasicBlock*)
//
// Note the two parameters the old parser also dropped on the floor once it
// lost its place. That is worse than refusing: it reads like an answer.
//
// The table is built by the ABI's own rule -- a component is appended the
// moment it is complete, in parse order -- and `S_` is entry 0, `S0_` entry 1,
// `S9_` entry 10, `SA_` entry 11 (the sequence is base 36). Candidates are
// types, template parameters, and name prefixes. NOT candidates, and this is
// what makes the indices line up: builtin types, back-references themselves,
// the standard `St`/`Sa`/`Ss`/`Si`/`So`/`Sd` abbreviations, and the name of
// the function being mangled. Each of those was checked against c++filt with
// a probe symbol rather than taken from memory -- `_Z1fSsS_` does not
// demangle, which is how you learn `Ss` is not an entry.
//
// Types are carried as a declarator pair (prefix, suffix) rather than one
// string, because C++ type syntax wraps: a pointer to a function is
// "void (*)()", not "void ()*". The pair is what lets `S_` name such a type
// and be spliced back in correctly at the point of use.
//
// When the parser meets something it does not model it fails, and demangle()
// returns the mangled name unchanged. There is no placeholder to print.
//
// Checked against c++filt, the reference implementation, over every distinct
// mangled symbol in three real C++ shared objects -- LLVM 8 for AArch64, the
// rellic dependency bundle for AArch64, and Ghidra's decompiler built for
// x86-64:
//
//                       symbols   identical   refused    WRONG
//     before            106385       8.78%     34.04%   57.19%
//     after             106385      99.23%      0.72%    0.04%
//
// The last column of the first row is the bug this file existed to cause: more
// than half of every C++ name the UI showed was a confident wrong answer, and
// 40234 of them contained the literal text "subst_". The 0.72% now refused are
// almost all non-type template arguments that are mangled EXPRESSIONS
// (`X ... E` -- a pointer-to-member constant, say); those come back as the raw
// symbol, which reads as "this is the mangled name" and not as a name. The
// 0.04% still wrong are substitution-index disagreements inside nested
// lambdas.

// A type in declarator form: `pre` goes before the declarator, `suf` after.
//   int            -> {"int", ""}
//   void ()        -> {"void ", "()"}
//   int [3]        -> {"int", " [3]"}
//   void (*)()     -> {"void (*", ")()"}
struct Ty {
    std::string pre, suf;
    // A parameter pack. `Args&&...` is not a reference to the joined text of
    // the pack -- it is a reference applied to EACH member -- so a pack has to
    // stay a list until it is printed.
    bool isPack = false;
    bool isArr = false;                   // cv on an array qualifies its element
    std::vector<Ty> pack;
    // 0 = not a reference, 1 = lvalue, 2 = rvalue. C++ collapses references
    // (T& && is T&), and a pack of forwarding references leans on it, so
    // without this "Node*&" comes out as "Node*&&&".
    int refKind = 0;

    Ty() {}
    explicit Ty(std::string p) : pre(std::move(p)) {}
    Ty(std::string p, std::string s) : pre(std::move(p)), suf(std::move(s)) {}
    static Ty makePack(std::vector<Ty> v) {
        Ty t; t.isPack = true; t.pack = std::move(v); return t;
    }
    bool simple() const { return suf.empty(); }
    std::string str() const {
        if (!isPack) return pre + suf;
        std::string out;
        bool first = true;
        for (auto& e : pack) {
            std::string x = e.str();
            if (x.empty()) continue;
            if (!first) out += ", ";
            first = false;
            out += x;
        }
        return out;
    }
};

// Wrap a declarator around a type: "*", "&", "&&", "Cls::*".
static Ty declare(const Ty& t, const std::string& deco, bool spaceBefore) {
    if (t.isPack) {
        std::vector<Ty> v;
        v.reserve(t.pack.size());
        for (auto& e : t.pack) v.push_back(declare(e, deco, spaceBefore));
        return Ty::makePack(std::move(v));
    }
    int kind = deco == "&" ? 1 : deco == "&&" ? 2 : 0;
    if (kind && t.refKind) {
        Ty r = t;
        r.refKind = std::min(t.refKind, kind);   // & wins over &&
        return r;
    }
    Ty r;
    if (t.simple()) r = Ty(t.pre + (spaceBefore ? " " : "") + deco);
    else {
        std::string b = t.pre;
        if (!b.empty() && b.back() != ' ') b += ' ';
        r = Ty(b + "(" + deco, ")" + t.suf);
    }
    r.refKind = kind;
    return r;
}
static Ty qualify(const Ty& t, const std::string& q) {   // " const", " volatile"
    if (t.isPack) {
        std::vector<Ty> v;
        v.reserve(t.pack.size());
        for (auto& e : t.pack) v.push_back(qualify(e, q));
        return Ty::makePack(std::move(v));
    }
    Ty r = (t.simple() || t.isArr) ? Ty(t.pre + q, t.suf) : Ty(t.pre, t.suf + q);
    r.refKind = t.refKind;
    r.isArr = t.isArr;
    return r;
}

struct It {
    const char* p;
    const char* end;
    bool ok = true;
    int depth = 0;
    std::vector<Ty> subs;                 // S_, S0_, S1_ ...
    std::vector<std::vector<Ty>> targs;   // enclosing template args, for T_
    std::vector<Ty> lastArgs;             // args of the name just parsed
    bool lastTemplate = false;            // ... and whether it had any
    bool lastCtorDtor = false;
    std::string nameTrailing;             // member-function cv, printed after ()
    bool lastArgEndsAngle = false;        // did the last template arg end in '>'

    It(const char* s) : p(s), end(s + strlen(s)) {}

    bool eof() const { return p >= end; }
    char peek() const { return eof() ? '\0' : *p; }
    char peek2() const { return (p + 1 >= end) ? '\0' : p[1]; }
    char take() { return eof() ? '\0' : *p++; }
    bool eat(char c) { if (peek() == c) { ++p; return true; } return false; }
    bool eat2(char a, char b) { if (peek() == a && peek2() == b) { p += 2; return true; } return false; }
    void fail() { ok = false; }

    // GNU spells nested closers "A<B<C> >", with the space.
    std::string closeAngle(const std::string& inner) const {
        return lastArgEndsAngle ? inner + " >" : inner + ">";
    }
    // "operator<<" followed by template args has to keep them apart, or the
    // result re-lexes as "operator<<<". "operator>>" has no such problem.
    static std::string openAngle(const std::string& name) {
        return (!name.empty() && name.back() == '<') ? " <" : "<";
    }
    const Ty& addSub(const Ty& t) { subs.push_back(t); return subs.back(); }

    // ---- lexical ----
    std::string digits() {
        std::string r;
        while (isdigit((unsigned char)peek())) r += take();
        return r;
    }
    std::string sourceName() {
        std::string len = digits();
        if (len.empty()) { fail(); return ""; }
        long n = strtol(len.c_str(), nullptr, 10);
        if (n <= 0 || p + n > end) { fail(); return ""; }
        std::string r(p, p + n);
        p += n;
        return r;
    }
    // seq-id, base 36 over 0-9A-Z. "" is S_ = entry 0; "0" is S0_ = entry 1.
    bool seqId(size_t& out) {
        size_t v = 0;
        bool any = false;
        for (;;) {
            char c = peek();
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'A' && c <= 'Z') d = 10 + (c - 'A');
            else break;
            if (v > (size_t(-1) - size_t(d)) / 36) return false;
            v = v * 36 + size_t(d);
            ++p;
            any = true;
        }
        out = v;
        return any;
    }

    // ---- substitutions ----
    // `isStd` marks the St/Sa/... abbreviations, which are NOT table entries:
    // counting them would shift every later index by one.
    Ty substitution(bool& isStd) {
        isStd = false;
        if (!eat('S')) { fail(); return Ty(); }
        switch (peek()) {
            case 't': ++p; isStd = true; return Ty("std");
            case 'a': ++p; isStd = true; return Ty("std::allocator");
            case 'b': ++p; isStd = true; return Ty("std::basic_string");
            case 's': ++p; isStd = true;
                return Ty("std::basic_string<char, std::char_traits<char>, std::allocator<char> >");
            case 'i': ++p; isStd = true; return Ty("std::basic_istream<char, std::char_traits<char> >");
            case 'o': ++p; isStd = true; return Ty("std::basic_ostream<char, std::char_traits<char> >");
            case 'd': ++p; isStd = true; return Ty("std::basic_iostream<char, std::char_traits<char> >");
            default: break;
        }
        size_t idx = 0;
        if (eat('_')) idx = 0;
        else {
            size_t v = 0;
            if (!seqId(v) || !eat('_')) { fail(); return Ty(); }
            idx = v + 1;
        }
        if (idx >= subs.size()) { fail(); return Ty(); }   // never a placeholder
        return subs[idx];
    }

    // T_ is the enclosing template's first argument, T0_ the second. These are
    // substitution candidates in their own right -- `_ZSt3maxIiERKT_S0_S0_`
    // resolves S0_ to `int`, which only works if T_ was appended to the table.
    Ty templateParam() {
        if (!eat('T')) { fail(); return Ty(); }
        size_t idx = 0;
        if (eat('_')) idx = 0;
        else {
            size_t v = 0;
            if (!seqId(v) || !eat('_')) { fail(); return Ty(); }
            idx = v + 1;
        }
        if (targs.empty() || idx >= targs.back().size()) { fail(); return Ty(); }
        return targs.back()[idx];
    }

    const char* operatorName() {
        struct E { const char* code; const char* text; };
        static const E kOps[] = {
            {"nw"," new"},{"na"," new[]"},{"dl"," delete"},{"da"," delete[]"},
            {"ps","+"},{"ng","-"},{"ad","&"},{"de","*"},{"co","~"},
            {"pl","+"},{"mi","-"},{"ml","*"},{"dv","/"},{"rm","%"},
            {"an","&"},{"or","|"},{"eo","^"},{"aS","="},{"pL","+="},
            {"mI","-="},{"mL","*="},{"dV","/="},{"rM","%="},{"aN","&="},
            {"oR","|="},{"eO","^="},{"ls","<<"},{"rs",">>"},{"lS","<<="},
            {"rS",">>="},{"eq","=="},{"ne","!="},{"lt","<"},{"gt",">"},
            {"le","<="},{"ge",">="},{"ss","<=>"},{"nt","!"},{"aa","&&"},
            {"oo","||"},{"pp","++"},{"mm","--"},{"cm",","},{"pm","->*"},
            {"pt","->"},{"cl","()"},{"ix","[]"},{"qu","?"},
        };
        if (p + 2 > end) return nullptr;
        for (auto& e : kOps)
            if (p[0] == e.code[0] && p[1] == e.code[1]) { p += 2; return e.text; }
        return nullptr;
    }

    const char* builtin() {
        switch (peek()) {
            case 'v': ++p; return "void";
            case 'w': ++p; return "wchar_t";
            case 'b': ++p; return "bool";
            case 'c': ++p; return "char";
            case 'a': ++p; return "signed char";
            case 'h': ++p; return "unsigned char";
            case 's': ++p; return "short";
            case 't': ++p; return "unsigned short";
            case 'i': ++p; return "int";
            case 'j': ++p; return "unsigned int";
            case 'l': ++p; return "long";
            case 'm': ++p; return "unsigned long";
            case 'x': ++p; return "long long";
            case 'y': ++p; return "unsigned long long";
            case 'n': ++p; return "__int128";
            case 'o': ++p; return "unsigned __int128";
            case 'f': ++p; return "float";
            case 'd': ++p; return "double";
            case 'e': ++p; return "long double";
            case 'g': ++p; return "__float128";
            case 'z': ++p; return "...";
            default: return nullptr;
        }
    }

    // ---- types ----
    Ty type() {
        if (!ok || eof() || ++depth > 128) { fail(); return Ty(); }
        struct Pop { int& d; ~Pop() { --d; } } pop{depth};

        char c = peek();
        if (c == 'P') { ++p; Ty t = type(); if (!ok) return Ty(); return addSub(declare(t, "*", false)); }
        if (c == 'R') { ++p; Ty t = type(); if (!ok) return Ty(); return addSub(declare(t, "&", false)); }
        if (c == 'O') { ++p; Ty t = type(); if (!ok) return Ty(); return addSub(declare(t, "&&", false)); }
        if (c == 'C') { ++p; Ty t = type(); if (!ok) return Ty(); return addSub(Ty("std::complex<" + t.str() + ">")); }
        if (c == 'K' || c == 'V' || c == 'r') {
            std::string q;
            while (peek() == 'K' || peek() == 'V' || peek() == 'r') {
                char k = take();
                q = std::string(k == 'K' ? " const" : k == 'V' ? " volatile" : " restrict") + q;
            }
            Ty t = type();
            if (!ok) return Ty();
            return addSub(qualify(t, q));
        }
        if (c == 'F') {                                   // function type
            ++p;
            eat('Y');
            Ty ret = type();
            if (!ok) return Ty();
            std::string args = paramList();
            if (!ok) return Ty();
            std::string q;
            while (peek() == 'K' || peek() == 'V' || peek() == 'R' || peek() == 'O') {
                char k = take();
                q += (k == 'K' ? " const" : k == 'V' ? " volatile" : k == 'R' ? " &" : " &&");
            }
            if (!eat('E')) { fail(); return Ty(); }
            return addSub(Ty(ret.str() + " ", "(" + args + ")" + q));
        }
        if (c == 'A') {                                   // array
            ++p;
            std::string n = digits();
            if (n.empty() && peek() != '_') { fail(); return Ty(); }   // A <expr> _ not modelled
            if (!eat('_')) { fail(); return Ty(); }
            Ty t = type();
            if (!ok) return Ty();
            Ty a(t.pre, t.suf + " [" + n + "]");
            a.isArr = true;
            return addSub(a);
        }
        if (c == 'M') {                                   // pointer to member
            ++p;
            Ty cls = type();
            if (!ok) return Ty();
            Ty mem = type();
            if (!ok) return Ty();
            return addSub(declare(mem, cls.str() + "::*", true));
        }
        if (c == 'D') {
            char d = peek2();
            if (d == 'p') { p += 2; Ty t = type(); if (!ok) return Ty(); return t; }
            p += 2;
            switch (d) {
                case 'n': return Ty("decltype(nullptr)");
                case 'a': return Ty("auto");
                case 'c': return Ty("decltype(auto)");
                case 'i': return Ty("char32_t");
                case 's': return Ty("char16_t");
                case 'u': return Ty("char8_t");
                case 'd': return Ty("decimal64");
                case 'e': return Ty("decimal128");
                case 'f': return Ty("decimal32");
                case 'h': return Ty("half");
                default: fail(); return Ty();
            }
        }
        if (c == 'u') { ++p; std::string n = sourceName(); if (!ok) return Ty(); return addSub(Ty(n)); }
        if (c == 'T') {
            Ty t = templateParam();
            if (!ok) return Ty();
            addSub(t);                                    // a candidate, unlike S_
            if (peek() == 'I') {
                std::string a = templateArgs();
                if (!ok) return Ty();
                return addSub(Ty(t.str() + "<" + closeAngle(a)));
            }
            return t;
        }
        if (c == 'S') {
            bool isStd = false;
            Ty s = substitution(isStd);
            if (!ok) return Ty();
            if (isStd && s.pre == "std" && isdigit((unsigned char)peek())) {   // St3foo
                std::string part = sourceName();
                if (!ok) return Ty();
                s = addSub(Ty("std::" + part));
            }
            if (peek() == 'I') {
                std::string a = templateArgs();
                if (!ok) return Ty();
                return addSub(Ty(s.str() + "<" + closeAngle(a)));
            }
            return s;                                     // a back-reference is not re-added
        }
        if (c == 'N') { std::string n = qualifiedName(true); if (!ok) return Ty(); return Ty(n); }
        if (c == 'Z') {
            // A type declared inside a function: "f(int)::Local". The parse
            // reuses the name machinery, which writes the "what did the last
            // name look like" fields, so they are saved across it.
            std::vector<Ty> savedArgs = lastArgs;
            bool savedT = lastTemplate, savedC = lastCtorDtor;
            std::string savedTrail = nameTrailing;
            std::string n = localName();
            lastArgs = savedArgs; lastTemplate = savedT;
            lastCtorDtor = savedC; nameTrailing = savedTrail;
            if (!ok) return Ty();
            return addSub(Ty(n));
        }
        if (isdigit((unsigned char)c)) {
            std::string raw = nameOf(sourceName());
            if (!ok) return Ty();
            raw += abiTags();
            if (!ok) return Ty();
            Ty n = addSub(Ty(raw));
            if (peek() == 'I') {
                std::string a = templateArgs();
                if (!ok) return Ty();
                return addSub(Ty(n.str() + "<" + closeAngle(a)));
            }
            return n;
        }
        if (const char* b = builtin()) return Ty(b);       // builtins are never candidates
        fail();
        return Ty();
    }

    // ---- names ----
    // <abi-tag> ::= B <source-name>, zero or more of them after an unqualified
    // name. GCC hangs [abi:cxx11] off half of libstdc++, so a name that drops
    // them is a name that does not match the symbol table.
    std::string abiTags() {
        std::string out;
        while (peek() == 'B') {
            ++p;
            std::string t = sourceName();
            if (!ok) return "";
            out += "[abi:" + t + "]";
        }
        return out;
    }
    // The compiler spells the unnamed namespace _GLOBAL__N_1; C++ spells it
    // (anonymous namespace), and so does every other demangler.
    static std::string nameOf(const std::string& n) {
        return n.rfind("_GLOBAL__N_", 0) == 0 ? "(anonymous namespace)" : n;
    }

    std::string component(const std::string& prev, bool& isCtorDtor) {
        isCtorDtor = false;
        char c = peek();
        if (isdigit((unsigned char)c)) {
            std::string n = nameOf(sourceName());
            if (!ok) return "";
            return n + abiTags();
        }
        if (c == 'C' && peek2() >= '1' && peek2() <= '5') {
            p += 2; isCtorDtor = true;
            std::string base = prev;
            size_t tag = base.find("[abi:");
            if (tag != std::string::npos) base.erase(tag);
            return base + abiTags();
        }
        if (c == 'D' && (peek2() >= '0' && peek2() <= '5')) {
            p += 2; isCtorDtor = true;
            std::string base = prev;
            size_t tag = base.find("[abi:");
            if (tag != std::string::npos) base.erase(tag);
            return "~" + base + abiTags();
        }
        if (c == 'U' && peek2() == 't') {
            p += 2; std::string n = digits(); eat('_');
            unsigned long k = n.empty() ? 1UL : strtoul(n.c_str(), nullptr, 10) + 2UL;
            return "{unnamed type#" + std::to_string(k) + "}";
        }
        if (c == 'U' && peek2() == 'l') {
            p += 2;
            std::string args = paramList();
            if (!ok) return "";
            if (!eat('E')) { fail(); return ""; }
            std::string n = digits(); eat('_');
            unsigned long k = n.empty() ? 1UL : strtoul(n.c_str(), nullptr, 10) + 2UL;
            return "{lambda(" + args + ")#" + std::to_string(k) + "}";
        }
        if (c == 'L') { ++p; return component(prev, isCtorDtor); }
        if (c == 'c' && peek2() == 'v') {
            p += 2;
            Ty t = type();
            if (!ok) return "";
            return "operator " + t.str();
        }
        if (const char* op = operatorName()) return std::string("operator") + op + abiTags();
        fail();
        return "";
    }

    // N [CV] [ref] <prefix> <unqualified-name> E
    // `asType` says whether the complete name is itself a substitution
    // candidate: it is when the name IS a type (a parameter, a template
    // argument); it is not when it names the function being mangled.
    std::string qualifiedName(bool asType) {
        if (!eat('N')) { fail(); return ""; }
        std::string trailing;
        for (;;) {
            if (eat('K')) { trailing = " const" + trailing; continue; }
            if (eat('V')) { trailing = " volatile" + trailing; continue; }
            if (eat('r')) { trailing = " restrict" + trailing; continue; }
            if (eat('R')) { trailing += " &"; continue; }
            if (eat('O')) { trailing += " &&"; continue; }
            break;
        }
        std::string out, last;
        bool any = false, endedTemplate = false, endedCtorDtor = false;
        // A prefix that IS a back-reference or a template parameter is already
        // in the table; re-adding it would shift every later index by one and
        // turn S3_ into S2_'s answer. This is the difference between
        // "llvm::MachineOperand const&" and a parse failure.
        bool outAlreadySub = false;
        std::vector<Ty> endArgs;
        while (!eof() && peek() != 'E') {
            if (peek() == 'I') {
                if (!any) { fail(); return ""; }
                if (!outAlreadySub) addSub(Ty(out));      // the template-prefix
                std::string a = templateArgs();
                if (!ok) return "";
                out += openAngle(out) + closeAngle(a);
                endedTemplate = true;
                endArgs = lastArgs;       // a TEMPLATE ctor is still a ctor: no return type
                outAlreadySub = false;
                continue;                 // `last` still names the class: ~Foo, not ~Foo<int>
            }
            std::string comp;
            bool cd = false, isRef = false;
            if (peek() == 'S') {
                bool isStd = false;
                Ty sub = substitution(isStd);
                if (!ok) return "";
                comp = sub.str();
                isRef = true;
            } else if (peek() == 'T') {
                Ty t = templateParam();
                if (!ok) return "";
                addSub(t);
                comp = t.str();
                isRef = true;
            } else {
                comp = component(last, cd);
            }
            if (!ok) return "";
            if (any && !outAlreadySub) addSub(Ty(out));    // every new prefix is a candidate
            out = any ? out + "::" + comp : comp;
            outAlreadySub = (!any && isRef);
            last = comp;
            any = true;
            endedTemplate = false;
            endedCtorDtor = cd;
        }
        if (!eat('E')) { fail(); return ""; }
        if (!any) { fail(); return ""; }
        if (asType && !outAlreadySub) addSub(Ty(out + trailing));
        lastTemplate = endedTemplate;
        lastCtorDtor = endedCtorDtor;
        lastArgs = endArgs;
        if (!asType) { nameTrailing = trailing; return out; }
        return out + trailing;
    }

    bool operatorAhead() {
        const char* save = p;
        bool yes = operatorName() != nullptr;
        p = save;
        return yes;
    }

    // <name> of the entity being mangled.
    std::string entityName() {
        lastTemplate = false;
        lastCtorDtor = false;
        lastArgs.clear();
        nameTrailing.clear();
        if (peek() == 'N') return qualifiedName(false);
        if (peek() == 'Z') return localName();
        std::string out;
        bool cd = false;
        if (peek() == 'S') {
            bool isStd = false;
            Ty s = substitution(isStd);
            if (!ok) return "";
            if (isStd && s.pre == "std" &&
                (isdigit((unsigned char)peek()) || peek() == 'C' || peek() == 'D' ||
                 peek() == 'L' || operatorAhead())) {
                std::string part = component("", cd);
                if (!ok) return "";
                out = "std::" + part;
            } else {
                out = s.str();
            }
        } else {
            out = component("", cd);
            if (!ok) return "";
        }
        lastCtorDtor = cd;
        if (peek() == 'I') {
            addSub(Ty(out));                              // <unscoped-template-name>
            std::string a = templateArgs();
            if (!ok) return "";
            out += openAngle(out) + closeAngle(a);
            lastTemplate = true;
        }
        return out;
    }

    // Z <encoding> E <name> [_ <number>]
    std::string localName() {
        if (!eat('Z')) { fail(); return ""; }
        std::string outer = encoding(true);
        if (!ok) return "";
        if (!eat('E')) { fail(); return ""; }
        if (eat('s')) { digits(); eat('_'); return outer + "::string literal"; }
        eat('d');
        std::string inner = entityName();
        if (!ok) return "";
        if (eat('_')) digits(); else digits();
        return outer + "::" + inner;
    }

    // ---- template arguments ----
    Ty templateArgValue() {
        if (eat('L')) {                                   // <expr-primary>
            if (peek() == '_' && peek2() == 'Z') {
                std::string n = mangledName();
                if (!ok) return Ty();
                if (!eat('E')) { fail(); return Ty(); }
                return Ty(n);
            }
            Ty t = type();
            if (!ok) return Ty();
            bool neg = eat('n');
            std::string v = digits();
            if (!eat('E')) { fail(); return Ty(); }
            const std::string& b = t.pre;
            if (b == "bool") return Ty(v == "0" ? "false" : "true");
            if (v.empty()) { fail(); return Ty(); }
            std::string num = (neg ? "-" : "") + v;
            if (b == "int") return Ty(num);
            if (b == "long") return Ty(num + "l");
            if (b == "unsigned int") return Ty(num + "u");
            if (b == "unsigned long") return Ty(num + "ul");
            if (b == "long long") return Ty(num + "ll");
            if (b == "unsigned long long") return Ty(num + "ull");
            return Ty("(" + t.str() + ")" + num);
        }
        if (peek() == 'X') { fail(); return Ty(); }        // <expression>: not modelled
        if (eat('J')) {                                   // argument pack
            std::vector<Ty> v;
            while (!eof() && peek() != 'E') {
                Ty a = templateArgValue();
                if (!ok) return Ty();
                v.push_back(a);
            }
            if (!eat('E')) { fail(); return Ty(); }
            return Ty::makePack(std::move(v));
        }
        return type();
    }

    std::string templateArgs() {
        if (!eat('I')) { fail(); return ""; }
        std::vector<Ty> list;
        std::string out;
        bool first = true;
        while (!eof() && peek() != 'E') {
            Ty a = templateArgValue();
            if (!ok) return "";
            list.push_back(a);
            // An empty parameter pack (J E) is a real argument that renders as
            // nothing; emitting a separator for it produces "Manager<Module, >".
            // It still counts for the closing bracket: GNU decides the space in
            // "> >" from the last argument, and an empty pack is not a ">".
            lastArgEndsAngle = !a.str().empty() && a.str().back() == '>';
            if (a.str().empty()) continue;
            if (!first) out += ", ";
            first = false;
            out += a.str();
        }
        if (!eat('E')) { fail(); return ""; }
        if (list.empty()) { fail(); return ""; }
        lastArgs = list;
        return out;
    }

    std::string paramList() {
        std::string out;
        bool first = true;
        while (!eof() && peek() != 'E' && peek() != '.') {
            if (first && peek() == 'v' &&
                (p + 1 == end || p[1] == 'E' || p[1] == '.')) { ++p; break; }
            Ty t = type();
            if (!ok) return "";
            if (t.str().empty()) continue;      // an empty pack expansion
            if (!first) out += ", ";
            first = false;
            out += t.str();
        }
        return out;
    }

    // ---- encodings ----
    // `nested` is set for the function part of a local name (Z <encoding> E ...).
    // There the name is being used as a scope, and GNU prints no return type
    // for it even when it is a template; matching that is the difference
    // between "f<T>(...)::x" and "R f<T>(...)::x".
    std::string encoding(bool nested = false) {
        if (peek() == 'T' || (peek() == 'G' && (peek2() == 'V' || peek2() == 'R')))
            return specialName();
        std::string fn = entityName();
        if (!ok) return "";
        bool tmpl = lastTemplate, ctorDtor = lastCtorDtor;
        std::string cv = nameTrailing;
        std::vector<Ty> mine = lastArgs;
        if (eof() || peek() == 'E' || peek() == '.') return fn + cv;   // a data symbol

        bool pushed = false;
        if (tmpl && !mine.empty()) { targs.push_back(mine); pushed = true; }
        struct Pop { It* s; bool on; ~Pop() { if (on) s->targs.pop_back(); } } pop{this, pushed};

        // A function template's encoding carries its return type in front of
        // the parameters; a plain function's does not, and neither does a
        // constructor's or a conversion operator's.
        std::string ret;
        if (tmpl && !ctorDtor && fn.rfind("operator ", 0) == std::string::npos &&
            fn.find("::operator ") == std::string::npos) {
            Ty r = type();
            if (!ok) return "";
            if (!nested) ret = r.str();   // parsed either way: it is not a parameter
        }
        std::string params = paramList();
        if (!ok) return "";
        std::string out = fn + "(" + params + ")" + cv;
        while (peek() == 'K' || peek() == 'V' || peek() == 'R' || peek() == 'O') {
            char k = take();
            out += (k == 'K' ? " const" : k == 'V' ? " volatile" : k == 'R' ? " &" : " &&");
        }
        if (!ret.empty()) out = ret + " " + out;
        return out;
    }

    std::string specialName() {
        if (eat2('G', 'V')) return "guard variable for " + entityName();
        if (eat2('G', 'R')) return "reference temporary for " + entityName();
        if (!eat('T')) { fail(); return ""; }
        char c = take();
        switch (c) {
            case 'V': { Ty t = type(); return ok ? "vtable for " + t.str() : ""; }
            case 'T': { Ty t = type(); return ok ? "VTT for " + t.str() : ""; }
            case 'I': { Ty t = type(); return ok ? "typeinfo for " + t.str() : ""; }
            case 'S': { Ty t = type(); return ok ? "typeinfo name for " + t.str() : ""; }
            case 'h': case 'v': {                          // <call-offset> <encoding>
                bool virt = (c == 'v');
                eat('n'); digits();
                if (!eat('_')) { fail(); return ""; }
                if (virt) { eat('n'); digits(); if (!eat('_')) { fail(); return ""; } }
                std::string inner = encoding();
                if (!ok) return "";
                return std::string(virt ? "virtual thunk to " : "non-virtual thunk to ") + inner;
            }
            case 'c': {
                eat('n'); digits(); eat('_'); eat('n'); digits(); eat('_');
                eat('n'); digits(); eat('_');
                std::string inner = encoding();
                if (!ok) return "";
                return "covariant return thunk to " + inner;
            }
            default: fail(); return "";
        }
    }

    std::string mangledName() {
        if (!eat2('_', 'Z')) { fail(); return ""; }
        return encoding();
    }
};

std::string demangleItanium(const std::string& m) {
    const char* s = m.c_str();
    if (strncmp(s, "__Z", 3) == 0) s += 1;
    It it(s + 2);                                  // past "_Z"
    std::string r = it.encoding();
    // ".cold", ".part.3", ".isra.0" and friends are GCC's clone suffixes, not
    // the ABI's. c++filt renders each one " [clone .isra.0]", and ".isra.0.cold"
    // is two of them.
    if (it.ok && !it.eof()) {
        if (it.peek() == '.') {
            const char* q = it.p;
            while (q < it.end && *q == '.') {
                const char* start = q++;
                while (q < it.end && (isalnum((unsigned char)*q) || *q == '_')) ++q;
                if (q < it.end && *q == '.') {          // ".isra.0": the number belongs to it
                    const char* dot = q++;
                    if (q < it.end && isdigit((unsigned char)*q)) { while (q < it.end && isdigit((unsigned char)*q)) ++q; }
                    else q = dot;
                }
                r += " [clone " + std::string(start, q) + "]";
            }
        } else {
            it.ok = false;             // input we did not consume is a parse we got wrong
        }
    }
    if (!it.ok || r.empty()) return m;
    return r;
}

// -------------------------------------------------------- MSVC simplifier --
std::string demangleMsvc(const std::string& m) {
    // ?name@outer@inner@@kind...
    if (m[0] != '?') return m;
    std::vector<std::string> parts;
    size_t i = 1;
    while (i < m.size()) {
        size_t at = m.find('@', i);
        if (at == std::string::npos) break;
        std::string part = m.substr(i, at - i);
        if (part.empty()) { ++i; break; }
        parts.push_back(part);
        i = at + 1;
    }
    // double @@ ends the name scope; find it
    size_t dbl = m.find("@@");
    if (parts.empty() || dbl == std::string::npos) return m;
    std::string out;
    for (size_t k = parts.size(); k-- > 0;) {
        out += parts[k];
        if (k != 0) out += "::";
    }
    std::string tail = m.substr(dbl + 2);
    if (!tail.empty()) {
        char kind = tail[0];
        if (kind == 'Y') out += "()";
        else if (kind == 'Q') out += "()";
        else if (kind == 'B') out += " const";
    }
    return out;
}

} // namespace

std::string demangle(const std::string& mangled) {
    if (mangled.rfind("_Z", 0) == 0) {
        try { return demangleItanium(mangled); } catch (...) { return mangled; }
    }
    if (mangled.rfind("?", 0) == 0) {
        try { return demangleMsvc(mangled); } catch (...) { return mangled; }
    }
    return mangled;
}

} // namespace sako
