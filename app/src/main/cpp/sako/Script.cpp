// NocturneScript interpreter implementation.
// Tokenizer -> recursive-descent parser (AST as closures) -> evaluator.
#include "Script.h"
#include <cctype>
#include <cmath>
#include <sstream>

namespace sako {

struct SakoScript::Impl {
    // ---- token ----
    enum TokType {
        T_EOF, T_NUM, T_STR, T_ID, T_KW,
        T_PLUS, T_MINUS, T_STAR, T_SLASH, T_PERCENT,
        T_EQ, T_EQEQ, T_NEQ, T_LT, T_LE, T_GT, T_GE,
        T_LP, T_RP, T_LBRACE, T_RBRACE, T_LBRACK, T_RBRACK,
        T_COMMA, T_DOT, T_SEMI, T_ARROW, T_ANDAND, T_OROR, T_NOT, T_COLON
    };
    struct Tok {
        TokType t = T_EOF;
        std::string s;
        double n = 0;
        int line = 1;
    };

    std::vector<Tok> toks;
    size_t pos = 0;
    std::map<std::string, ScriptValue> globals;
    std::map<std::string, ScriptBuiltin> builtins;
    std::string err;
    int errLine = 0;
    int callDepth = 0;

    // ---------------- lexer ----------------
    static bool isIdStart(char c) { return isalpha((unsigned char)c) || c == '_'; }
    static bool isIdChar(char c) { return isalnum((unsigned char)c) || c == '_'; }

    bool lex(const std::string& src) {
        toks.clear();
        int line = 1;
        size_t i = 0;
        while (i < src.size()) {
            char c = src[i];
            if (c == '\n') { ++line; ++i; continue; }
            if (isspace((unsigned char)c)) { ++i; continue; }
            if (c == '#' && i + 1 < src.size() && src[i + 1] == '#') {   // ## comment
                while (i < src.size() && src[i] != '\n') ++i;
                continue;
            }
            if (c == '/' && i + 1 < src.size() && src[i + 1] == '/') {
                while (i < src.size() && src[i] != '\n') ++i;
                continue;
            }
            // A leading-dot number (".5") must not swallow the second dot of a
            // range: in "0..3" the first dot is already guarded below, but
            // without this the second would lex as the number 0.3 and the
            // for-range parser would see DOT NUM instead of DOT DOT.
            if (isdigit((unsigned char)c) ||
                (c == '.' && i + 1 < src.size() && isdigit((unsigned char)src[i + 1]) &&
                 !(i > 0 && src[i - 1] == '.'))) {
                size_t s = i;
                int dots = 0;
                bool hex = (c == '0' && i + 1 < src.size() &&
                            (src[i + 1] == 'x' || src[i + 1] == 'X'));
                if (hex) { i += 2; while (i < src.size() && isxdigit((unsigned char)src[i])) ++i; }
                else {
                    while (i < src.size() &&
                           (isdigit((unsigned char)src[i]) ||
                            (src[i] == '.' && dots == 0 &&
                             !(i + 1 < src.size() && src[i + 1] == '.')))) {
                        if (src[i] == '.') ++dots;
                        ++i;
                    }
                }
                std::string num = src.substr(s, i - s);
                Tok t; t.line = line;
                t.n = hex ? (double)strtoull(num.c_str(), nullptr, 16)
                          : strtod(num.c_str(), nullptr);
                t.t = T_NUM;
                toks.push_back(t);
                continue;
            }
            if (c == '"' || c == '\'') {
                char quote = c;
                ++i;
                std::string val;
                while (i < src.size() && src[i] != quote) {
                    if (src[i] == '\\' && i + 1 < src.size()) {
                        ++i;
                        switch (src[i]) {
                            case 'n': val += '\n'; break;
                            case 't': val += '\t'; break;
                            default: val += src[i];
                        }
                    } else val += src[i];
                    ++i;
                }
                if (i >= src.size()) { err = "unterminated string"; errLine = line; return false; }
                ++i;
                Tok t; t.t = T_STR; t.s = val; t.line = line;
                toks.push_back(t);
                continue;
            }
            if (isIdStart(c)) {
                size_t s = i;
                while (i < src.size() && isIdChar(src[i])) ++i;
                std::string id = src.substr(s, i - s);
                Tok t; t.s = id; t.line = line;
                if (id == "if" || id == "else" || id == "while" || id == "for" ||
                    id == "fun" || id == "return" || id == "true" || id == "false" ||
                    id == "nil" || id == "and" || id == "or" || id == "not" ||
                    id == "in" || id == "break" || id == "continue")
                    t.t = T_KW;
                else t.t = T_ID;
                toks.push_back(t);
                continue;
            }
            Tok t; t.line = line;
            char c2 = i + 1 < src.size() ? src[i + 1] : '\0';
            switch (c) {
                case '+': t.t = T_PLUS; break;
                case '-':
                    if (c2 == '>') { t.t = T_ARROW; ++i; } else t.t = T_MINUS;
                    break;
                case '*': t.t = T_STAR; break;
                case '/': t.t = T_SLASH; break;
                case '%': t.t = T_PERCENT; break;
                case '=': t.t = c2 == '=' ? T_EQEQ : T_EQ; if (c2 == '=') ++i; break;
                case '!': t.t = c2 == '=' ? T_NEQ : T_NOT; if (c2 == '=') ++i; break;
                case '<': t.t = c2 == '=' ? T_LE : T_LT; if (c2 == '=') ++i; break;
                case '>': t.t = c2 == '=' ? T_GE : T_GT; if (c2 == '=') ++i; break;
                case '(': t.t = T_LP; break;
                case ')': t.t = T_RP; break;
                case '{': t.t = T_LBRACE; break;
                case '}': t.t = T_RBRACE; break;
                case '[': t.t = T_LBRACK; break;
                case ']': t.t = T_RBRACK; break;
                case ',': t.t = T_COMMA; break;
                case '.': t.t = T_DOT; break;
                case ';': t.t = T_SEMI; break;
                case ':': t.t = T_COLON; break;
                case '&': if (c2 == '&') { t.t = T_ANDAND; ++i; break; } err = "bad &"; errLine = line; return false;
                case '|': if (c2 == '|') { t.t = T_OROR; ++i; break; } err = "bad |"; errLine = line; return false;
                default:
                    err = std::string("unexpected char '") + c + "'";
                    errLine = line;
                    return false;
            }
            ++i;
            toks.push_back(t);
        }
        Tok e; e.t = T_EOF; e.line = line;
        toks.push_back(e);
        return true;
    }

    // ---------------- AST ----------------
    struct Node;
    using NodeP = std::shared_ptr<Node>;
    struct Node {
        enum K {
            N_NUM, N_STR, N_BOOL, N_NIL, N_ID, N_BIN, N_UN, N_ASSIGN, N_CALL,
            N_MEMBER, N_BLOCK, N_IF, N_WHILE, N_FOR, N_FUN, N_RET, N_BREAK, N_CONTINUE
        } k;
        double num = 0;
        std::string s;
        NodeP a, b, c, d;
        std::vector<NodeP> items;      // block / args / params
        int line = 0;
    };

    struct Scope {
        std::map<std::string, ScriptValue> vars;
        Scope* parent = nullptr;
        ScriptValue* find(const std::string& n) {
            for (Scope* s = this; s; s = s->parent) {
                auto it = s->vars.find(n);
                if (it != s->vars.end()) return &it->second;
            }
            return nullptr;
        }
    };

    struct RetEx { ScriptValue v; };
    struct BrkEx {};
    struct ContEx {};

    const Tok& cur() const { return toks[pos]; }
    const Tok& prev() const { return toks[pos > 0 ? pos - 1 : 0]; }
    bool atEnd() const { return cur().t == T_EOF; }
    void advance() { if (!atEnd()) ++pos; }
    bool check(TokType t) const { return cur().t == t; }
    bool match(TokType t) { if (check(t)) { advance(); return true; } return false; }
    bool matchKw(const std::string& kw) {
        if (cur().t == T_KW && cur().s == kw) { advance(); return true; }
        return false;
    }
    // Non-consuming variant. The binary-operator loops advance() themselves,
    // so testing with matchKw() there ate the right-hand operand.
    bool checkKw(const std::string& kw) const {
        return cur().t == T_KW && cur().s == kw;
    }
    bool expect(TokType t, const char* what) {
        if (check(t)) { advance(); return true; }
        err = std::string("expected ") + what;
        errLine = cur().line;
        return false;
    }

    NodeP mk(Node::K k, int line) {
        auto n = std::make_shared<Node>();
        n->k = k; n->line = line;
        return n;
    }

    NodeP parsePrimary() {
        int ln = cur().line;
        switch (cur().t) {
            case T_NUM: {
                auto n = mk(Node::N_NUM, ln);
                n->num = cur().n;
                advance();
                return n;
            }
            case T_STR: {
                auto n = mk(Node::N_STR, ln);
                n->s = cur().s;
                advance();
                return n;
            }
            case T_ID: {
                auto n = mk(Node::N_ID, ln);
                n->s = cur().s;
                advance();
                return n;
            }
            case T_KW: {
                if (cur().s == "true") {
                    advance();
                    auto n = mk(Node::N_BOOL, ln);
                    n->num = 1;
                    return n;
                }
                if (cur().s == "false") {
                    advance();
                    auto n = mk(Node::N_BOOL, ln);
                    n->num = 0;
                    return n;
                }
                if (cur().s == "nil") { advance(); return mk(Node::N_NIL, ln); }
                err = "unexpected keyword '" + cur().s + "'";
                errLine = ln;
                return nullptr;
            }
            case T_LP: {
                advance();
                auto e = parseExpr();
                if (!e) return nullptr;
                if (!expect(T_RP, ")")) return nullptr;
                return e;
            }
            default:
                err = "unexpected token";
                errLine = cur().line;
                return nullptr;
        }
    }

    NodeP parsePostfix() {
        auto e = parsePrimary();
        if (!e) return nullptr;
        for (;;) {
            if (check(T_DOT)) {
                // ".." (range op) is not member access
                if (pos + 1 < toks.size() && toks[pos + 1].t == T_DOT) break;
                advance();
                if (cur().t != T_ID) { err = "member name expected"; errLine = cur().line; return nullptr; }
                auto n = mk(Node::N_MEMBER, cur().line);
                n->a = e; n->s = cur().s;
                advance();
                e = n;
            } else if (check(T_LP)) {
                advance();
                auto n = mk(Node::N_CALL, cur().line);
                n->a = e;
                if (!check(T_RP)) {
                    for (;;) {
                        auto arg = parseExpr();
                        if (!arg) return nullptr;
                        n->items.push_back(arg);
                        if (!match(T_COMMA)) break;
                    }
                }
                if (!expect(T_RP, ")")) return nullptr;
                e = n;
            } else break;
        }
        return e;
    }

    NodeP parseUnary() {
        // `not` is in the keyword list, so it can never be an identifier — but
        // nothing here consumed it, so `not x` was a parse error and the word
        // was simply unusable. `and` and `or` have had their keyword spelling
        // since the start; this is the third one.
        if (check(T_MINUS) || check(T_NOT) || checkKw("not")) {
            std::string op = check(T_MINUS) ? "-" : "!";
            int ln = cur().line;
            advance();
            auto v = parseUnary();
            if (!v) return nullptr;
            auto n = mk(Node::N_UN, ln);
            n->s = op; n->a = v;
            return n;
        }
        return parsePostfix();
    }

    NodeP parseMul() {
        auto l = parseUnary();
        if (!l) return nullptr;
        for (;;) {
            if (check(T_STAR) || check(T_SLASH) || check(T_PERCENT)) {
                std::string op = check(T_STAR) ? "*" : check(T_SLASH) ? "/" : "%";
                advance();
                auto r = parseUnary();
                if (!r) return nullptr;
                auto n = mk(Node::N_BIN, cur().line);
                n->s = op; n->a = l; n->b = r;
                l = n;
            } else break;
        }
        return l;
    }

    NodeP parseAdd() {
        auto l = parseMul();
        if (!l) return nullptr;
        for (;;) {
            if (check(T_PLUS) || check(T_MINUS)) {
                std::string op = check(T_PLUS) ? "+" : "-";
                advance();
                auto r = parseMul();
                if (!r) return nullptr;
                auto n = mk(Node::N_BIN, cur().line);
                n->s = op; n->a = l; n->b = r;
                l = n;
            } else break;
        }
        return l;
    }

    NodeP parseCmp() {
        auto l = parseAdd();
        if (!l) return nullptr;
        for (;;) {
            TokType t = cur().t;
            if (t == T_EQEQ || t == T_NEQ || t == T_LT || t == T_LE || t == T_GT || t == T_GE) {
                std::string op = t == T_EQEQ ? "==" : t == T_NEQ ? "!=" : t == T_LT ? "<" :
                                 t == T_LE ? "<=" : t == T_GT ? ">" : ">=";
                advance();
                auto r = parseAdd();
                if (!r) return nullptr;
                auto n = mk(Node::N_BIN, cur().line);
                n->s = op; n->a = l; n->b = r;
                l = n;
            } else break;
        }
        return l;
    }

    NodeP parseAnd() {
        auto l = parseCmp();
        if (!l) return nullptr;
        while (check(T_ANDAND) || checkKw("and")) {
            advance();
            auto r = parseCmp();
            if (!r) return nullptr;
            auto n = mk(Node::N_BIN, cur().line);
            n->s = "&&"; n->a = l; n->b = r;
            l = n;
        }
        return l;
    }

    NodeP parseOr() {
        auto l = parseAnd();
        if (!l) return nullptr;
        while (check(T_OROR) || checkKw("or")) {
            advance();
            auto r = parseAnd();
            if (!r) return nullptr;
            auto n = mk(Node::N_BIN, cur().line);
            n->s = "||"; n->a = l; n->b = r;
            l = n;
        }
        return l;
    }

    NodeP parseExpr() {
        int ln = cur().line;
        auto target = parseOr();
        if (!target) return nullptr;
        if (check(T_EQ)) {
            advance();
            auto val = parseExpr();
            if (!val) return nullptr;
            if (target->k != Node::N_ID && target->k != Node::N_MEMBER) {
                err = "invalid assignment target"; errLine = ln; return nullptr;
            }
            auto n = mk(Node::N_ASSIGN, ln);
            n->a = target; n->b = val;
            return n;
        }
        return target;
    }

    NodeP parseBlock() {
        int ln = cur().line;
        if (!expect(T_LBRACE, "{")) return nullptr;
        auto n = mk(Node::N_BLOCK, ln);
        while (!check(T_RBRACE) && !atEnd()) {
            auto st = parseStatement();
            if (!st) return nullptr;
            n->items.push_back(st);
        }
        if (!expect(T_RBRACE, "}")) return nullptr;
        return n;
    }

    NodeP parseStatement() {
        int ln = cur().line;
        if (matchKw("if")) {
            auto n = mk(Node::N_IF, ln);
            bool paren = match(T_LP);
            n->a = parseExpr();
            if (!n->a) return nullptr;
            if (paren && !expect(T_RP, ")")) return nullptr;
            n->b = parseStatement();
            if (!n->b) return nullptr;
            if (matchKw("else")) {
                n->c = parseStatement();
                if (!n->c) return nullptr;
            }
            return n;
        }
        if (matchKw("while")) {
            auto n = mk(Node::N_WHILE, ln);
            bool paren = match(T_LP);
            n->a = parseExpr();
            if (!n->a) return nullptr;
            if (paren && !expect(T_RP, ")")) return nullptr;
            n->b = parseStatement();
            if (!n->b) return nullptr;
            return n;
        }
        if (matchKw("for")) {
            // for i in a..b { }
            auto n = mk(Node::N_FOR, ln);
            if (cur().t != T_ID) { err = "for needs variable"; errLine = ln; return nullptr; }
            n->s = cur().s;
            advance();
            if (!matchKw("in")) { err = "expected 'in'"; errLine = ln; return nullptr; }
            n->a = parseExpr();
            if (!n->a) return nullptr;
            if (!match(T_DOT)) { err = "expected .."; errLine = ln; return nullptr; }
            if (!match(T_DOT)) { err = "expected .."; errLine = ln; return nullptr; }
            n->b = parseExpr();
            if (!n->b) return nullptr;
            n->c = parseStatement();
            if (!n->c) return nullptr;
            return n;
        }
        if (matchKw("fun")) {
            if (cur().t != T_ID) { err = "function name expected"; errLine = ln; return nullptr; }
            auto n = mk(Node::N_FUN, ln);
            n->s = cur().s;
            advance();
            if (!expect(T_LP, "(")) return nullptr;
            if (!check(T_RP)) {
                for (;;) {
                    if (cur().t != T_ID) { err = "param name"; errLine = ln; return nullptr; }
                    n->items.push_back(mk(Node::N_ID, ln));
                    n->items.back()->s = cur().s;
                    advance();
                    if (!match(T_COMMA)) break;
                }
            }
            if (!expect(T_RP, ")")) return nullptr;
            n->a = parseBlock();
            if (!n->a) return nullptr;
            return n;
        }
        if (matchKw("return")) {
            auto n = mk(Node::N_RET, ln);
            if (!check(T_SEMI) && !check(T_RBRACE) && cur().t != T_EOF)
                n->a = parseExpr();
            return n;
        }
        if (matchKw("break")) return mk(Node::N_BREAK, ln);
        if (matchKw("continue")) return mk(Node::N_CONTINUE, ln);
        if (check(T_LBRACE)) return parseBlock();
        // expression statement
        auto e = parseExpr();
        if (!e) return nullptr;
        match(T_SEMI);
        return e;
    }

    bool parseProgram(std::vector<NodeP>& out) {
        while (!atEnd()) {
            auto st = parseStatement();
            if (!st) return false;
            out.push_back(st);
        }
        return true;
    }

    // ---------------- evaluator ----------------
    ScriptValue eval(const NodeP& n, Scope& sc, bool& threw) {
        if (threw || !n) return ScriptValue::nil();
        switch (n->k) {
            case Node::N_NUM: return ScriptValue::ofNum(n->num);
            case Node::N_STR: return ScriptValue::ofStr(n->s);
            case Node::N_BOOL: return ScriptValue::ofBool(n->num == 1);
            case Node::N_NIL: return ScriptValue::nil();
            case Node::N_ID: {
                if (ScriptValue* v = sc.find(n->s)) return *v;
                auto b = builtins.find(n->s);
                if (b != builtins.end()) return ScriptValue::ofStr("::builtin::" + n->s);
                err = "undefined variable '" + n->s + "'";
                errLine = n->line;
                threw = true;
                return ScriptValue::nil();
            }
            case Node::N_UN: {
                auto v = eval(n->a, sc, threw);
                if (threw) return v;
                if (n->s == "-") return ScriptValue::ofNum(-toNum(v));
                return ScriptValue::ofBool(!v.truthy());
            }
            case Node::N_BIN: {
                if (n->s == "&&") {
                    auto l = eval(n->a, sc, threw);
                    if (threw) return l;
                    if (!l.truthy()) return ScriptValue::ofBool(false);
                    auto r = eval(n->b, sc, threw);
                    return ScriptValue::ofBool(r.truthy());
                }
                if (n->s == "||") {
                    auto l = eval(n->a, sc, threw);
                    if (threw) return l;
                    if (l.truthy()) return ScriptValue::ofBool(true);
                    auto r = eval(n->b, sc, threw);
                    return ScriptValue::ofBool(r.truthy());
                }
                auto l = eval(n->a, sc, threw);
                if (threw) return l;
                auto r = eval(n->b, sc, threw);
                if (threw) return r;
                if (n->s == "+") {
                    if (l.kind == ScriptValue::STR || r.kind == ScriptValue::STR)
                        return ScriptValue::ofStr(l.render() + r.render());
                    return ScriptValue::ofNum(toNum(l) + toNum(r));
                }
                if (n->s == "==" || n->s == "!=") {
                    // nil and objects both used to fall through to toNum(),
                    // which answers 0 for each of them — so `obj != nil` was
                    // FALSE for every object, and a host API that can return
                    // nothing (func_containing, insn_at, section_at) could not
                    // be tested at all. nil equals only nil; an object equals
                    // only the same object.
                    bool eq;
                    if (l.kind == ScriptValue::NIL || r.kind == ScriptValue::NIL)
                        eq = (l.kind == ScriptValue::NIL && r.kind == ScriptValue::NIL);
                    else if (l.kind == ScriptValue::OBJ || r.kind == ScriptValue::OBJ)
                        eq = (l.kind == ScriptValue::OBJ && r.kind == ScriptValue::OBJ &&
                              l.obj == r.obj);
                    else if (l.kind == ScriptValue::STR || r.kind == ScriptValue::STR)
                        eq = (l.render() == r.render());
                    else
                        eq = (toNum(l) == toNum(r));
                    return ScriptValue::ofBool(n->s == "==" ? eq : !eq);
                }
                double a = toNum(l), b = toNum(r);
                if (n->s == "-") return ScriptValue::ofNum(a - b);
                if (n->s == "*") return ScriptValue::ofNum(a * b);
                if (n->s == "/") return b == 0 ? ScriptValue::nil() : ScriptValue::ofNum(a / b);
                if (n->s == "%") return b == 0 ? ScriptValue::nil() : ScriptValue::ofNum(fmod(a, b));
                if (n->s == "<") return ScriptValue::ofBool(a < b);
                if (n->s == "<=") return ScriptValue::ofBool(a <= b);
                if (n->s == ">") return ScriptValue::ofBool(a > b);
                if (n->s == ">=") return ScriptValue::ofBool(a >= b);
                return ScriptValue::nil();
            }
            case Node::N_ASSIGN: {
                if (n->a->k == Node::N_ID) {
                    auto v = eval(n->b, sc, threw);
                    if (threw) return v;
                    if (ScriptValue* slot = sc.find(n->a->s)) { *slot = v; return v; }
                    sc.vars[n->a->s] = v;
                    return v;
                }
                if (n->a->k == Node::N_MEMBER) {
                    auto baseV = eval(n->a->a, sc, threw);
                    if (threw) return baseV;
                    auto v = eval(n->b, sc, threw);
                    if (threw) return v;
                    if (baseV.kind == ScriptValue::OBJ && baseV.obj) {
                        (*baseV.obj)[n->a->s] = v;
                        return v;
                    }
                    err = "cannot set member on non-object";
                    errLine = n->line;
                    threw = true;
                    return v;
                }
                err = "bad assignment"; errLine = n->line; threw = true;
                return ScriptValue::nil();
            }
            case Node::N_MEMBER: {
                auto baseV = eval(n->a, sc, threw);
                if (threw) return baseV;
                if (baseV.kind == ScriptValue::OBJ && baseV.obj) {
                    auto it = baseV.obj->find(n->s);
                    if (it != baseV.obj->end()) return it->second;
                    return ScriptValue::nil();
                }
                err = "member '" + n->s + "' on non-object";
                errLine = n->line;
                threw = true;
                return ScriptValue::nil();
            }
            case Node::N_CALL: {
                // builtin?
                if (n->a->k == Node::N_ID) {
                    auto b = builtins.find(n->a->s);
                    if (b != builtins.end()) {
                        std::vector<ScriptValue> args;
                        for (auto& a : n->items) {
                            auto v = eval(a, sc, threw);
                            if (threw) return v;
                            args.push_back(v);
                        }
                        if (++callDepth > 64) {
                            err = "call depth exceeded";
                            errLine = n->line;
                            threw = true;
                            --callDepth;
                            return ScriptValue::nil();
                        }
                        auto r = b->second(args);
                        --callDepth;
                        return r;
                    }
                }
                // user function
                ScriptValue fnv;
                if (n->a->k == Node::N_ID) {
                    if (ScriptValue* v = sc.find(n->a->s)) fnv = *v;
                }
                if (fnv.kind == ScriptValue::STR && fnv.str.rfind("::userfun::", 0) == 0) {
                    std::string key = fnv.str.substr(11);
                    auto it = userFuns.find(key);
                    if (it == userFuns.end()) {
                        err = "no function " + key;
                        errLine = n->line; threw = true;
                        return ScriptValue::nil();
                    }
                    if (++callDepth > 64) {
                        err = "recursion too deep";
                        errLine = n->line; threw = true;
                        --callDepth;
                        return ScriptValue::nil();
                    }
                    Scope fscope;
                    fscope.parent = &globals_scope;
                    for (size_t i = 0; i < it->second.params.size() && i < n->items.size(); ++i) {
                        fscope.vars[it->second.params[i]] = eval(n->items[i], sc, threw);
                    }
                    bool threw2 = false;
                    try {
                        std::vector<NodeP> one{ it->second.body };
                        execBlock(one, fscope);
                    } catch (const RetEx& r) {
                        --callDepth;
                        return r.v;
                    }
                    --callDepth;
                    if (threw) return ScriptValue::nil();
                    return ScriptValue::nil();
                }
                err = "not callable: " + n->a->s;
                errLine = n->line;
                threw = true;
                return ScriptValue::nil();
            }
            case Node::N_BLOCK: {
                Scope inner;
                inner.parent = &sc;
                execBlock(n->items, inner);
                return ScriptValue::nil();
            }
            case Node::N_IF: {
                auto c = eval(n->a, sc, threw);
                if (threw) return c;
                if (c.truthy()) eval(n->b, sc, threw);
                else if (n->c) eval(n->c, sc, threw);
                return ScriptValue::nil();
            }
            case Node::N_WHILE: {
                int guard = 0;
                while (!threw) {
                    auto c = eval(n->a, sc, threw);
                    if (threw) break;
                    if (!c.truthy()) break;
                    try {
                        eval(n->b, sc, threw);
                    } catch (const BrkEx&) { break; }
                    catch (const ContEx&) { }
                    if (++guard > 10000000) { err = "loop limit"; errLine = n->line; threw = true; break; }
                }
                return ScriptValue::nil();
            }
            case Node::N_FOR: {
                auto fromV = eval(n->a, sc, threw);
                if (threw) return fromV;
                auto toV = eval(n->b, sc, threw);
                if (threw) return toV;
                long long from = (long long)toNum(fromV), to = (long long)toNum(toV);
                for (long long i = from; i <= to && !threw; ++i) {
                    Scope inner;
                    inner.parent = &sc;
                    inner.vars[n->s] = ScriptValue::ofNum(double(i));
                    try {
                        eval(n->c, inner, threw);
                    } catch (const BrkEx&) { break; }
                    catch (const ContEx&) { }
                }
                return ScriptValue::nil();
            }
            case Node::N_FUN: {
                UserFn f;
                f.body = n->a;
                for (auto& p : n->items) f.params.push_back(p->s);
                userFuns[n->s] = f;
                sc.vars[n->s] = ScriptValue::ofStr("::userfun::" + n->s);
                return ScriptValue::nil();
            }
            case Node::N_RET: {
                ScriptValue v = n->a ? eval(n->a, sc, threw) : ScriptValue::nil();
                throw RetEx{ v };
            }
            case Node::N_BREAK: throw BrkEx{};
            case Node::N_CONTINUE: throw ContEx{};
        }
        return ScriptValue::nil();
    }

    struct UserFn {
        std::vector<std::string> params;
        NodeP body;
    };
    std::map<std::string, UserFn> userFuns;
    Scope globals_scope;

    void execBlock(const std::vector<NodeP>& items, Scope& sc) {
        for (auto& it : items) {
            bool threwLocally = false;
            eval(it, sc, threwLocally);
            if (threwLocally) return;
        }
    }

    static double toNum(const ScriptValue& v) {
        switch (v.kind) {
            case ScriptValue::NUM: return v.num;
            case ScriptValue::BOOL: return v.b ? 1 : 0;
            case ScriptValue::STR: {
                if (v.str.rfind("0x", 0) == 0) return (double)strtoull(v.str.c_str(), nullptr, 16);
                return strtod(v.str.c_str(), nullptr);
            }
            default: return 0;
        }
    }
};

SakoScript::SakoScript() : impl_(std::make_shared<Impl>()) {}

void SakoScript::setBuiltin(const std::string& name, ScriptBuiltin fn) {
    impl_->builtins[name] = std::move(fn);
}

void SakoScript::setGlobal(const std::string& name, ScriptValue v) {
    impl_->globals[name] = std::move(v);
}

ScriptError SakoScript::run(const std::string& source) {
    ScriptError se;
    Impl& I = *impl_;
    I.err.clear();
    I.errLine = 0;
    I.pos = 0;
    I.userFuns.clear();
    I.globals_scope.vars.clear();
    for (auto& kv : I.globals) I.globals_scope.vars[kv.first] = kv.second;
    I.callDepth = 0;

    if (!I.lex(source)) {
        se.ok = false;
        se.message = I.err;
        se.line = I.errLine;
        return se;
    }
    std::vector<std::shared_ptr<Impl::Node>> prog;
    if (!I.parseProgram(prog)) {
        se.ok = false;
        se.message = I.err;
        se.line = I.errLine;
        return se;
    }
    bool threw = false;
    try {
        I.execBlock(prog, I.globals_scope);
    } catch (const Impl::RetEx&) {
        // top-level return: fine
    } catch (const Impl::BrkEx&) {
    } catch (const Impl::ContEx&) {
    } catch (const std::exception& e) {
        se.ok = false;
        se.message = std::string("runtime: ") + e.what();
        return se;
    }
    if (threw) {
        se.ok = false;
        se.message = I.err;
        se.line = I.errLine;
        return se;
    }
    se.ok = true;
    return se;
}

} // namespace sako
