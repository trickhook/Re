// Compact C++ symbol demangler.
// Supports the common Itanium subset produced by GCC/Clang on Android/Linux:
//   _ZN St/Sa/Sb/Si... substitutions, nested names N...E, templates I...E,
//   builtin types, pointers/refs/const, numbers, function params.
// Plus a light MSVC `?name@ns@@...` simplifier.
#include "Demangle.h"
#include <cstring>

namespace sako {

bool looksMangled(const std::string& n) {
    return n.rfind("_Z", 0) == 0 || n.rfind("__Z", 0) == 0 || n.rfind("?", 0) == 0;
}

namespace {

// ------------------------------------------------------- Itanium demangler --
struct It {
    const char* p;
    const char* end;
    int subs = 0;          // next S-number to assign
    bool ok = true;

    It(const char* s) : p(s), end(s + strlen(s)) {}

    bool eof() const { return p >= end; }
    char peek() const { return eof() ? '\0' : *p; }
    char take() { return eof() ? '\0' : *p++; }
    bool eat(char c) { if (peek() == c) { ++p; return true; } return false; }

    std::string number(bool& neg) {
        neg = false;
        if (peek() == 'n') { neg = true; ++p; }
        std::string r;
        while (isdigit((unsigned char)peek())) r += take();
        return r;
    }

    // source-name: digits + text
    std::string sourceName() {
        bool neg = false;
        std::string len = number(neg);
        if (len.empty() || neg) { ok = false; return ""; }
        long n = strtol(len.c_str(), nullptr, 10);
        if (n < 0 || p + n > end) { ok = false; return ""; }
        std::string r(p, p + n);
        p += n;
        return r;
    }

    // substitution: St, Sa, Sb, Ss, Si, So, Sd, S0_.., Sn_
    std::string substitution() {
        ++p; // 'S'
        char c = take();
        switch (c) {
            case 't': return "std";
            case 'a': return "std::allocator";
            case 'b': return "std::basic_string";
            case 's': return "std::string";
            case 'i': return "std::basic_istream";
            case 'o': return "std::basic_ostream";
            case 'd': return "std::basic_iostream";
            default: break;
        }
        if (c >= '0' && c <= '9') {
            int idx = 10 + (c - '0'); // S0_ is the 11th (index 10)
            std::string r = "S#" + std::to_string(idx - 10 + 0);
            // We don't track full substitution tables — render placeholder.
            eat('_');
            return "subst_" + std::to_string(idx - 10);
        }
        if (c == '_') { eat('_'); return "subst_"; }
        ok = false;
        return "";
    }

    std::string type(bool& isRef) {
        isRef = false;
        std::string cv;
        for (;;) {
            if (eat('K')) cv += "const ";
            else if (eat('V')) cv += "volatile ";
            else if (eat('P')) {
                std::string inner = type(isRef);
                isRef = true;
                return inner + "*";
            } else if (eat('R')) {
                std::string inner = type(isRef);
                isRef = true;
                return inner + "&";
            } else if (eat('O')) {
                std::string inner = type(isRef);
                isRef = true;
                return inner + "&&";
            } else break;
        }
        char c = peek();
        std::string base;
        switch (c) {
            case 'v': base = "void";    ++p; break;
            case 'b': base = "bool";    ++p; break;
            case 'c': base = "char";    ++p; break;
            case 'a': base = "schar";   ++p; break;
            case 'h': base = "uchar";   ++p; break;
            case 's': base = "short";   ++p; break;
            case 't': base = "ushort";  ++p; break;
            case 'i': base = "int";     ++p; break;
            case 'j': base = "uint";    ++p; break;
            case 'l': base = "long";    ++p; break;
            case 'm': base = "ulong";   ++p; break;
            case 'x': base = "longlong";++p; break;
            case 'y': base = "ulonglong";++p; break;
            case 'f': base = "float";   ++p; break;
            case 'd': base = "double";  ++p; break;
            case 'e': base = "longdouble";++p; break;
            case 'n': base = "i128";    ++p; break;
            case 'o': base = "u128";    ++p; break;
            case 'w': base = "wchar";   ++p; break;
            case 'z': base = "...";     ++p; break;
            case 'D': {
                ++p;
                char d = take();
                if (d == 'n') base = "decltype(nullptr)";
                else if (d == 'i') base = "decimal64";
                else { ok = false; return ""; }
                break;
            }
            case 'N': { // prefixed qualified type like NSt6vectorIiEE
                ++p;
                base = nestedName();
                if (eat('I')) base += "<" + templateArgs() + ">";
                if (!eat('E')) { ok = false; return ""; }
                break;
            }
            case 'S': {
                base = substitution();
                if (!ok) return "";
                // substituted template like SaIiE -> std::allocator<int>
                if (eat('I')) base += "<" + templateArgs() + ">";
                break;
            }
            default:
                if (isdigit((unsigned char)c)) base = sourceName();
                else { ok = false; return ""; }
                break;
        }
        return cv + base;
    }

    std::string templateArgs() {
        std::string out;
        bool first = true;
        while (!eof() && peek() != 'E') {
            if (!first) out += ", ";
            first = false;
            bool isRef = false;
            std::string t = type(isRef);
            if (!ok) return "";
            out += t;
            if (t == "void") break;
        }
        return out;
    }

    // name: unscoped / scoped N...E / template
    std::string name() {
        if (eat('N')) {
            std::string out = nestedName();
            // optional template args after nested parts
            if (eat('I')) out += "<" + templateArgs() + ">";
            if (!eat('E')) { ok = false; return ""; }
            return out;
        }
        if (eat('S')) {
            // S... continuation (e.g. St3foo — but St handled in substitution)
            --p; // rewind; treat via sourceName path for simplicity below
            std::string sub = substitution();
            if (!ok) return "";
            std::string out = sub;
            if (eat('I')) out += "<" + templateArgs() + ">";
            // possible ::part
            if (isdigit((unsigned char)peek())) out += "::" + sourceName();
            return out;
        }
        if (isdigit((unsigned char)peek())) {
            std::string out = sourceName();
            if (!ok) return "";
            if (eat('I')) out += "<" + templateArgs() + ">";
            return out;
        }
        if (eat('L')) return sourceName();  // internal linkage literal-ish
        ok = false;
        return "";
    }

    std::string nestedName() {
        std::string out;
        bool first = true;
        std::string cv;
        while (!eof() && peek() != 'E') {
            if (eat('K')) { cv = " const"; continue; }
            if (eat('V')) { cv = " volatile"; continue; }
            if (eat('I')) {
                // template args belong to previous component
                out += "<" + templateArgs() + ">";
                continue;
            }
            if (eat('S')) {
                --p;
                std::string sub = substitution();
                if (!ok) return "";
                if (!first) out += "::";
                out += sub;
                first = false;
                continue;
            }
            char c = peek();
            if (isdigit((unsigned char)c)) {
                std::string part = sourceName();
                if (!ok) return "";
                if (!first) out += "::";
                out += part;
                first = false;
            } else if (c == 'M') { // Ctor/Dtor markers not fully supported
                ++p;
            } else {
                ok = false;
                return "";
            }
        }
        return out + cv;
    }

    std::string run() {
        // p is already past the "_Z" prefix (see demangleItanium)
        if (eat('L')) { /* local */ }
        if (eat('T')) { // template
            char c = take();
            if (c == 'V') return "vtable for " + name();
            if (c == 'T') return "VTT for " + name();
            if (c == 'I') return "typeinfo for " + name();
            if (c == 'S') return "typeinfo name for " + name();
            if (c == 'h') return "thunk(" + name() + ")";
            ok = false;
            return "";
        }
        std::string fn = name();
        if (!ok) return "";
        // params
        if (!eof() && peek() != 'E' && peek() != '.') {
            std::string params;
            bool first = true;
            bool isRef = false;
            while (!eof() && peek() != 'E' && peek() != '.') {
                if (eat('v') && first) { first = false; continue; } // ()
                if (!first) params += ", ";
                first = false;
                std::string t = type(isRef);
                if (!ok) return "";
                params += t;
                if (t == "..." || t == "void") break;
            }
            if (!params.empty()) fn += "(" + params + ")";
        }
        // cv-qualifiers on member functions / const ending
        while (!eof() && (peek() == 'K' || peek() == 'V')) ++p;
        return fn;
    }
};

std::string demangleItanium(const std::string& m) {
    const char* s = m.c_str();
    if (strncmp(s, "__Z", 3) == 0) s += 1;
    It it(s + 2); // past "_Z"
    std::string r = it.run();
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
