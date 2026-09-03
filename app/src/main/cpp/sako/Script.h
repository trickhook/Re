// SakoScript — a tiny interpreter powering the SakoRE plugin system.
// Language: numbers (double), strings, booleans, objects (from host),
// variables, arithmetic, comparisons, if/else, while, for-in-range,
// user functions, and host API builtins (bound to an analysis context).
//
// Host API:
//   log(msg)                     count_functions()        func_at(i)
//   func_by_name(name)           count_strings()          string_at(i)
//   count_imports()              import_at(i)             demangle(name)
//   count_xrefs_to(addr)         xref_to_at(addr, i)      rename(addr, name)
//   comment(addr, text)          bookmark(addr, label)    classify(name)
//   hex(n)                       strlen(s)                str(n)
#pragma once
#include "Types.h"
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace sako {

struct ScriptValue;

using ScriptObj = std::map<std::string, ScriptValue>;

struct ScriptValue {
    enum Kind { NUM, STR, BOOL, OBJ, NIL } kind = NIL;
    double num = 0;
    std::string str;
    bool b = false;
    std::shared_ptr<ScriptObj> obj;

    static ScriptValue ofNum(double v)  { ScriptValue s; s.kind = NUM; s.num = v; return s; }
    static ScriptValue ofStr(std::string v) { ScriptValue s; s.kind = STR; s.str = std::move(v); return s; }
    static ScriptValue ofBool(bool v)   { ScriptValue s; s.kind = BOOL; s.b = v; return s; }
    static ScriptValue ofObj(std::shared_ptr<ScriptObj> o) { ScriptValue s; s.kind = OBJ; s.obj = std::move(o); return s; }
    static ScriptValue nil() { return ScriptValue(); }

    std::string render() const {
        switch (kind) {
            case NUM: {
                if (num == (long long)num) return std::to_string((long long)num);
                char buf[32]; snprintf(buf, sizeof buf, "%g", num);
                return buf;
            }
            case STR: return str;
            case BOOL: return b ? "true" : "false";
            case OBJ: return "[object]";
            default: return "nil";
        }
    }
    bool truthy() const {
        switch (kind) {
            case NUM: return num != 0;
            case STR: return !str.empty();
            case BOOL: return b;
            case OBJ: return true;
            default: return false;
        }
    }
};

// Builtin host functions receive/return ScriptValues.
using ScriptBuiltin = std::function<ScriptValue(const std::vector<ScriptValue>&)>;

struct ScriptError {
    bool ok = false;
    std::string message;
    int line = 0;
};

class SakoScript {
public:
    SakoScript();
    void setBuiltin(const std::string& name, ScriptBuiltin fn);
    void setGlobal(const std::string& name, ScriptValue v);
    // Run program text; returns error info.
    ScriptError run(const std::string& source);

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace sako
