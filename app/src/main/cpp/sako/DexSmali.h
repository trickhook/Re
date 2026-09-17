// DexSmali — a format-driven Dalvik (DEX) bytecode disassembler.
//
// The native disassembler (Capstone / the IR lifter) decodes machine code; it
// cannot touch Dalvik, which is a register VM with its own ~230-opcode
// instruction set. This module is that missing half: it decodes the code_item
// at a method's codeOff into smali-style lines the way baksmali / Android Studio
// would render them — mnemonic, operands, and resolved names for the index
// operands (string@ / type@ / field@ / meth@ / proto@).
//
// It is header-only ON PURPOSE, exactly like the diff matcher (BinDiff.h), the
// library recogniser (LibSig.h) and the detection scanner (Detections.h): it
// compiles into the engine with NO change to the build system — no new source
// in CMakeLists, no JNI of its own. Engine::dexSmali (Engine.cpp) ensures the
// analysis context and calls decodeMethod() with the raw dex bytes and the
// pool offsets the loader already parsed (DexIndex, in Types.h), then serialises
// the result.
//
// It is FORMAT-DRIVEN: every opcode carries its documented instruction format
// (10x, 12x, 21c, 35c, 3rc, 51l, the switch/array payloads, ...) and the decoder
// reads operands per that format. An opcode it does not know renders honestly as
// "<unknown-op 0xNN>" and never a guessed encoding — a wrong decode is worse
// than an admitted one, because it desynchronises every instruction after it.
#pragma once
#include "Types.h"
#include <cstdio>
#include <string>
#include <vector>

namespace sako {
namespace dexsmali {

// ---- one decoded instruction ------------------------------------------------
struct SmaliLine {
    u64 off = 0;             // dex file byte offset of this instruction
    u32 unit = 0;            // code-unit index within insns[] (for label math)
    u32 units = 1;           // instruction width in 16-bit code units
    std::string bytes;       // lowercase hex of the instruction's code units
    std::string mnem;        // "invoke-virtual", "const-string", "if-eqz", ...
    std::string ops;         // rendered operands, resolved names inline
    std::string comment;     // raw pool index (meth@N) or absolute branch target
};

struct MethodCode {
    bool ok = false;
    std::string error;
    u32 registersSize = 0, insSize = 0, outsSize = 0, triesSize = 0;
    u32 insnsUnits = 0;      // insns_size, in 16-bit code units
    u64 insnsOff = 0;        // dex byte offset of insns[]
    bool truncated = false;  // stopped at the line cap or ran off the end
    std::vector<SmaliLine> lines;
};

// ---- instruction formats ----------------------------------------------------
// Widths in code units are fixed per format; only the switch / array-data
// payloads are variable and are handled out of band.
enum Fmt : u8 {
    F10x, F12x, F11n, F11x, F10t, F20t, F22x, F21t, F21s, F21h, F21c,
    F23x, F22b, F22t, F22s, F22c, F30t, F32x, F31i, F31t, F31c,
    F35c, F3rc, F51l, F45cc, F4rcc, FUnknown
};

// Which pool a format's index operand (B in 21c/31c/35c/3rc, C in 22c) names.
enum Ix : u8 { IxNone, IxString, IxType, IxField, IxMethod, IxProto,
               IxCallSite, IxMethodHandle };

struct OpInfo { const char* name; u8 fmt; u8 ix; };

// The full 0x00..0xFF opcode table. Names and formats follow the Dalvik
// bytecode reference. Truly unused opcodes (0x3e-0x43, 0x73, 0x79-0x7a,
// 0xe3-0xf9) are FUnknown so they render as "<unknown-op ...>" rather than
// pretending to a width. Kept in an inline function so the header can be
// included anywhere without an ODR clash.
inline const OpInfo* opTable() {
    static const OpInfo T[256] = {
        /*00*/ {"nop", F10x, IxNone},
        /*01*/ {"move", F12x, IxNone},
        /*02*/ {"move/from16", F22x, IxNone},
        /*03*/ {"move/16", F32x, IxNone},
        /*04*/ {"move-wide", F12x, IxNone},
        /*05*/ {"move-wide/from16", F22x, IxNone},
        /*06*/ {"move-wide/16", F32x, IxNone},
        /*07*/ {"move-object", F12x, IxNone},
        /*08*/ {"move-object/from16", F22x, IxNone},
        /*09*/ {"move-object/16", F32x, IxNone},
        /*0a*/ {"move-result", F11x, IxNone},
        /*0b*/ {"move-result-wide", F11x, IxNone},
        /*0c*/ {"move-result-object", F11x, IxNone},
        /*0d*/ {"move-exception", F11x, IxNone},
        /*0e*/ {"return-void", F10x, IxNone},
        /*0f*/ {"return", F11x, IxNone},
        /*10*/ {"return-wide", F11x, IxNone},
        /*11*/ {"return-object", F11x, IxNone},
        /*12*/ {"const/4", F11n, IxNone},
        /*13*/ {"const/16", F21s, IxNone},
        /*14*/ {"const", F31i, IxNone},
        /*15*/ {"const/high16", F21h, IxNone},
        /*16*/ {"const-wide/16", F21s, IxNone},
        /*17*/ {"const-wide/32", F31i, IxNone},
        /*18*/ {"const-wide", F51l, IxNone},
        /*19*/ {"const-wide/high16", F21h, IxNone},
        /*1a*/ {"const-string", F21c, IxString},
        /*1b*/ {"const-string/jumbo", F31c, IxString},
        /*1c*/ {"const-class", F21c, IxType},
        /*1d*/ {"monitor-enter", F11x, IxNone},
        /*1e*/ {"monitor-exit", F11x, IxNone},
        /*1f*/ {"check-cast", F21c, IxType},
        /*20*/ {"instance-of", F22c, IxType},
        /*21*/ {"array-length", F12x, IxNone},
        /*22*/ {"new-instance", F21c, IxType},
        /*23*/ {"new-array", F22c, IxType},
        /*24*/ {"filled-new-array", F35c, IxType},
        /*25*/ {"filled-new-array/range", F3rc, IxType},
        /*26*/ {"fill-array-data", F31t, IxNone},
        /*27*/ {"throw", F11x, IxNone},
        /*28*/ {"goto", F10t, IxNone},
        /*29*/ {"goto/16", F20t, IxNone},
        /*2a*/ {"goto/32", F30t, IxNone},
        /*2b*/ {"packed-switch", F31t, IxNone},
        /*2c*/ {"sparse-switch", F31t, IxNone},
        /*2d*/ {"cmpl-float", F23x, IxNone},
        /*2e*/ {"cmpg-float", F23x, IxNone},
        /*2f*/ {"cmpl-double", F23x, IxNone},
        /*30*/ {"cmpg-double", F23x, IxNone},
        /*31*/ {"cmp-long", F23x, IxNone},
        /*32*/ {"if-eq", F22t, IxNone},
        /*33*/ {"if-ne", F22t, IxNone},
        /*34*/ {"if-lt", F22t, IxNone},
        /*35*/ {"if-ge", F22t, IxNone},
        /*36*/ {"if-gt", F22t, IxNone},
        /*37*/ {"if-le", F22t, IxNone},
        /*38*/ {"if-eqz", F21t, IxNone},
        /*39*/ {"if-nez", F21t, IxNone},
        /*3a*/ {"if-ltz", F21t, IxNone},
        /*3b*/ {"if-gez", F21t, IxNone},
        /*3c*/ {"if-gtz", F21t, IxNone},
        /*3d*/ {"if-lez", F21t, IxNone},
        /*3e*/ {nullptr, FUnknown, IxNone},
        /*3f*/ {nullptr, FUnknown, IxNone},
        /*40*/ {nullptr, FUnknown, IxNone},
        /*41*/ {nullptr, FUnknown, IxNone},
        /*42*/ {nullptr, FUnknown, IxNone},
        /*43*/ {nullptr, FUnknown, IxNone},
        /*44*/ {"aget", F23x, IxNone},
        /*45*/ {"aget-wide", F23x, IxNone},
        /*46*/ {"aget-object", F23x, IxNone},
        /*47*/ {"aget-boolean", F23x, IxNone},
        /*48*/ {"aget-byte", F23x, IxNone},
        /*49*/ {"aget-char", F23x, IxNone},
        /*4a*/ {"aget-short", F23x, IxNone},
        /*4b*/ {"aput", F23x, IxNone},
        /*4c*/ {"aput-wide", F23x, IxNone},
        /*4d*/ {"aput-object", F23x, IxNone},
        /*4e*/ {"aput-boolean", F23x, IxNone},
        /*4f*/ {"aput-byte", F23x, IxNone},
        /*50*/ {"aput-char", F23x, IxNone},
        /*51*/ {"aput-short", F23x, IxNone},
        /*52*/ {"iget", F22c, IxField},
        /*53*/ {"iget-wide", F22c, IxField},
        /*54*/ {"iget-object", F22c, IxField},
        /*55*/ {"iget-boolean", F22c, IxField},
        /*56*/ {"iget-byte", F22c, IxField},
        /*57*/ {"iget-char", F22c, IxField},
        /*58*/ {"iget-short", F22c, IxField},
        /*59*/ {"iput", F22c, IxField},
        /*5a*/ {"iput-wide", F22c, IxField},
        /*5b*/ {"iput-object", F22c, IxField},
        /*5c*/ {"iput-boolean", F22c, IxField},
        /*5d*/ {"iput-byte", F22c, IxField},
        /*5e*/ {"iput-char", F22c, IxField},
        /*5f*/ {"iput-short", F22c, IxField},
        /*60*/ {"sget", F21c, IxField},
        /*61*/ {"sget-wide", F21c, IxField},
        /*62*/ {"sget-object", F21c, IxField},
        /*63*/ {"sget-boolean", F21c, IxField},
        /*64*/ {"sget-byte", F21c, IxField},
        /*65*/ {"sget-char", F21c, IxField},
        /*66*/ {"sget-short", F21c, IxField},
        /*67*/ {"sput", F21c, IxField},
        /*68*/ {"sput-wide", F21c, IxField},
        /*69*/ {"sput-object", F21c, IxField},
        /*6a*/ {"sput-boolean", F21c, IxField},
        /*6b*/ {"sput-byte", F21c, IxField},
        /*6c*/ {"sput-char", F21c, IxField},
        /*6d*/ {"sput-short", F21c, IxField},
        /*6e*/ {"invoke-virtual", F35c, IxMethod},
        /*6f*/ {"invoke-super", F35c, IxMethod},
        /*70*/ {"invoke-direct", F35c, IxMethod},
        /*71*/ {"invoke-static", F35c, IxMethod},
        /*72*/ {"invoke-interface", F35c, IxMethod},
        /*73*/ {nullptr, FUnknown, IxNone},
        /*74*/ {"invoke-virtual/range", F3rc, IxMethod},
        /*75*/ {"invoke-super/range", F3rc, IxMethod},
        /*76*/ {"invoke-direct/range", F3rc, IxMethod},
        /*77*/ {"invoke-static/range", F3rc, IxMethod},
        /*78*/ {"invoke-interface/range", F3rc, IxMethod},
        /*79*/ {nullptr, FUnknown, IxNone},
        /*7a*/ {nullptr, FUnknown, IxNone},
        /*7b*/ {"neg-int", F12x, IxNone},
        /*7c*/ {"not-int", F12x, IxNone},
        /*7d*/ {"neg-long", F12x, IxNone},
        /*7e*/ {"not-long", F12x, IxNone},
        /*7f*/ {"neg-float", F12x, IxNone},
        /*80*/ {"neg-double", F12x, IxNone},
        /*81*/ {"int-to-long", F12x, IxNone},
        /*82*/ {"int-to-float", F12x, IxNone},
        /*83*/ {"int-to-double", F12x, IxNone},
        /*84*/ {"long-to-int", F12x, IxNone},
        /*85*/ {"long-to-float", F12x, IxNone},
        /*86*/ {"long-to-double", F12x, IxNone},
        /*87*/ {"float-to-int", F12x, IxNone},
        /*88*/ {"float-to-long", F12x, IxNone},
        /*89*/ {"float-to-double", F12x, IxNone},
        /*8a*/ {"double-to-int", F12x, IxNone},
        /*8b*/ {"double-to-long", F12x, IxNone},
        /*8c*/ {"double-to-float", F12x, IxNone},
        /*8d*/ {"int-to-byte", F12x, IxNone},
        /*8e*/ {"int-to-char", F12x, IxNone},
        /*8f*/ {"int-to-short", F12x, IxNone},
        /*90*/ {"add-int", F23x, IxNone},
        /*91*/ {"sub-int", F23x, IxNone},
        /*92*/ {"mul-int", F23x, IxNone},
        /*93*/ {"div-int", F23x, IxNone},
        /*94*/ {"rem-int", F23x, IxNone},
        /*95*/ {"and-int", F23x, IxNone},
        /*96*/ {"or-int", F23x, IxNone},
        /*97*/ {"xor-int", F23x, IxNone},
        /*98*/ {"shl-int", F23x, IxNone},
        /*99*/ {"shr-int", F23x, IxNone},
        /*9a*/ {"ushr-int", F23x, IxNone},
        /*9b*/ {"add-long", F23x, IxNone},
        /*9c*/ {"sub-long", F23x, IxNone},
        /*9d*/ {"mul-long", F23x, IxNone},
        /*9e*/ {"div-long", F23x, IxNone},
        /*9f*/ {"rem-long", F23x, IxNone},
        /*a0*/ {"and-long", F23x, IxNone},
        /*a1*/ {"or-long", F23x, IxNone},
        /*a2*/ {"xor-long", F23x, IxNone},
        /*a3*/ {"shl-long", F23x, IxNone},
        /*a4*/ {"shr-long", F23x, IxNone},
        /*a5*/ {"ushr-long", F23x, IxNone},
        /*a6*/ {"add-float", F23x, IxNone},
        /*a7*/ {"sub-float", F23x, IxNone},
        /*a8*/ {"mul-float", F23x, IxNone},
        /*a9*/ {"div-float", F23x, IxNone},
        /*aa*/ {"rem-float", F23x, IxNone},
        /*ab*/ {"add-double", F23x, IxNone},
        /*ac*/ {"sub-double", F23x, IxNone},
        /*ad*/ {"mul-double", F23x, IxNone},
        /*ae*/ {"div-double", F23x, IxNone},
        /*af*/ {"rem-double", F23x, IxNone},
        /*b0*/ {"add-int/2addr", F12x, IxNone},
        /*b1*/ {"sub-int/2addr", F12x, IxNone},
        /*b2*/ {"mul-int/2addr", F12x, IxNone},
        /*b3*/ {"div-int/2addr", F12x, IxNone},
        /*b4*/ {"rem-int/2addr", F12x, IxNone},
        /*b5*/ {"and-int/2addr", F12x, IxNone},
        /*b6*/ {"or-int/2addr", F12x, IxNone},
        /*b7*/ {"xor-int/2addr", F12x, IxNone},
        /*b8*/ {"shl-int/2addr", F12x, IxNone},
        /*b9*/ {"shr-int/2addr", F12x, IxNone},
        /*ba*/ {"ushr-int/2addr", F12x, IxNone},
        /*bb*/ {"add-long/2addr", F12x, IxNone},
        /*bc*/ {"sub-long/2addr", F12x, IxNone},
        /*bd*/ {"mul-long/2addr", F12x, IxNone},
        /*be*/ {"div-long/2addr", F12x, IxNone},
        /*bf*/ {"rem-long/2addr", F12x, IxNone},
        /*c0*/ {"and-long/2addr", F12x, IxNone},
        /*c1*/ {"or-long/2addr", F12x, IxNone},
        /*c2*/ {"xor-long/2addr", F12x, IxNone},
        /*c3*/ {"shl-long/2addr", F12x, IxNone},
        /*c4*/ {"shr-long/2addr", F12x, IxNone},
        /*c5*/ {"ushr-long/2addr", F12x, IxNone},
        /*c6*/ {"add-float/2addr", F12x, IxNone},
        /*c7*/ {"sub-float/2addr", F12x, IxNone},
        /*c8*/ {"mul-float/2addr", F12x, IxNone},
        /*c9*/ {"div-float/2addr", F12x, IxNone},
        /*ca*/ {"rem-float/2addr", F12x, IxNone},
        /*cb*/ {"add-double/2addr", F12x, IxNone},
        /*cc*/ {"sub-double/2addr", F12x, IxNone},
        /*cd*/ {"mul-double/2addr", F12x, IxNone},
        /*ce*/ {"div-double/2addr", F12x, IxNone},
        /*cf*/ {"rem-double/2addr", F12x, IxNone},
        /*d0*/ {"add-int/lit16", F22s, IxNone},
        /*d1*/ {"rsub-int", F22s, IxNone},
        /*d2*/ {"mul-int/lit16", F22s, IxNone},
        /*d3*/ {"div-int/lit16", F22s, IxNone},
        /*d4*/ {"rem-int/lit16", F22s, IxNone},
        /*d5*/ {"and-int/lit16", F22s, IxNone},
        /*d6*/ {"or-int/lit16", F22s, IxNone},
        /*d7*/ {"xor-int/lit16", F22s, IxNone},
        /*d8*/ {"add-int/lit8", F22b, IxNone},
        /*d9*/ {"rsub-int/lit8", F22b, IxNone},
        /*da*/ {"mul-int/lit8", F22b, IxNone},
        /*db*/ {"div-int/lit8", F22b, IxNone},
        /*dc*/ {"rem-int/lit8", F22b, IxNone},
        /*dd*/ {"and-int/lit8", F22b, IxNone},
        /*de*/ {"or-int/lit8", F22b, IxNone},
        /*df*/ {"xor-int/lit8", F22b, IxNone},
        /*e0*/ {"shl-int/lit8", F22b, IxNone},
        /*e1*/ {"shr-int/lit8", F22b, IxNone},
        /*e2*/ {"ushr-int/lit8", F22b, IxNone},
        /*e3*/ {nullptr, FUnknown, IxNone},
        /*e4*/ {nullptr, FUnknown, IxNone},
        /*e5*/ {nullptr, FUnknown, IxNone},
        /*e6*/ {nullptr, FUnknown, IxNone},
        /*e7*/ {nullptr, FUnknown, IxNone},
        /*e8*/ {nullptr, FUnknown, IxNone},
        /*e9*/ {nullptr, FUnknown, IxNone},
        /*ea*/ {nullptr, FUnknown, IxNone},
        /*eb*/ {nullptr, FUnknown, IxNone},
        /*ec*/ {nullptr, FUnknown, IxNone},
        /*ed*/ {nullptr, FUnknown, IxNone},
        /*ee*/ {nullptr, FUnknown, IxNone},
        /*ef*/ {nullptr, FUnknown, IxNone},
        /*f0*/ {nullptr, FUnknown, IxNone},
        /*f1*/ {nullptr, FUnknown, IxNone},
        /*f2*/ {nullptr, FUnknown, IxNone},
        /*f3*/ {nullptr, FUnknown, IxNone},
        /*f4*/ {nullptr, FUnknown, IxNone},
        /*f5*/ {nullptr, FUnknown, IxNone},
        /*f6*/ {nullptr, FUnknown, IxNone},
        /*f7*/ {nullptr, FUnknown, IxNone},
        /*f8*/ {nullptr, FUnknown, IxNone},
        /*f9*/ {nullptr, FUnknown, IxNone},
        /*fa*/ {"invoke-polymorphic", F45cc, IxMethod},
        /*fb*/ {"invoke-polymorphic/range", F4rcc, IxMethod},
        /*fc*/ {"invoke-custom", F35c, IxCallSite},
        /*fd*/ {"invoke-custom/range", F3rc, IxCallSite},
        /*fe*/ {"const-method-handle", F21c, IxMethodHandle},
        /*ff*/ {"const-method-type", F21c, IxProto},
    };
    return T;
}

// Fixed instruction width, in 16-bit code units, per format.
inline u32 fmtUnits(u8 fmt) {
    switch (fmt) {
        case F10x: case F12x: case F11n: case F11x: case F10t: return 1;
        case F20t: case F22x: case F21t: case F21s: case F21h: case F21c:
        case F23x: case F22b: case F22t: case F22s: case F22c: return 2;
        case F30t: case F32x: case F31i: case F31t: case F31c:
        case F35c: case F3rc: return 3;
        case F45cc: case F4rcc: return 4;
        case F51l: return 5;
        default: return 1;   // FUnknown: advance one unit, best effort
    }
}

// ---- pool resolvers ---------------------------------------------------------
// Every read is bounds-checked against the raw dex bytes; an out-of-range index
// or a table the file did not carry renders as "kind@N" rather than reading
// arbitrary memory. This is the ONLY place operand indices are resolved, so the
// smali the decoder emits can never disagree with itself.
struct Pools {
    const u8* data = nullptr;
    size_t n = 0;
    DexIndex idx;

    std::string rawIx(const char* kind, u32 i) const {
        char b[32];
        std::snprintf(b, sizeof b, "%s@%u", kind, i);
        return b;
    }

    std::string str(u32 i) const {
        if (i >= idx.stringIdsCount) return rawIx("string", i);
        u64 base = u64(idx.stringIdsOff) + u64(i) * 4;
        if (base + 4 > n) return rawIx("string", i);
        u32 dataOff = rd32(data + base);
        if (dataOff >= n) return rawIx("string", i);
        size_t pos = dataOff;
        // skip the uleb128 utf16 length prefix
        while (pos < n && (data[pos] & 0x80)) ++pos;
        if (pos < n) ++pos;
        if (pos >= n) return "";
        return readCString(data + pos, n - pos, 240);
    }

    std::string type(u32 i) const {
        if (i >= idx.typeIdsCount) return rawIx("type", i);
        u64 base = u64(idx.typeIdsOff) + u64(i) * 4;
        if (base + 4 > n) return rawIx("type", i);
        return str(rd32(data + base));
    }

    std::string proto(u32 i) const {
        if (i >= idx.protoIdsCount) return rawIx("proto", i);
        u64 base = u64(idx.protoIdsOff) + u64(i) * 12;
        if (base + 12 > n) return rawIx("proto", i);
        u32 retIdx = rd32(data + base + 4);
        u32 paramsOff = rd32(data + base + 8);
        std::string sig = "(";
        if (paramsOff && paramsOff + 4 <= n) {
            u32 pc = rd32(data + paramsOff);
            if (pc <= 4096 && paramsOff + 4 + u64(pc) * 2 <= n) {
                for (u32 k = 0; k < pc; ++k)
                    sig += type(rd16(data + paramsOff + 4 + u64(k) * 2));
            }
        }
        sig += ")";
        sig += type(retIdx);
        return sig;
    }

    std::string field(u32 i) const {
        if (i >= idx.fieldIdsCount) return rawIx("field", i);
        u64 base = u64(idx.fieldIdsOff) + u64(i) * 8;
        if (base + 8 > n) return rawIx("field", i);
        u16 classIdx = rd16(data + base);
        u16 typeIdx = rd16(data + base + 2);
        u32 nameIdx = rd32(data + base + 4);
        return type(classIdx) + "->" + str(nameIdx) + ":" + type(typeIdx);
    }

    std::string method(u32 i) const {
        if (i >= idx.methodIdsCount) return rawIx("meth", i);
        u64 base = u64(idx.methodIdsOff) + u64(i) * 8;
        if (base + 8 > n) return rawIx("meth", i);
        u16 classIdx = rd16(data + base);
        u16 protoIdx = rd16(data + base + 2);
        u32 nameIdx = rd32(data + base + 4);
        return type(classIdx) + "->" + str(nameIdx) + proto(protoIdx);
    }

    // Resolve one index operand through the pool its opcode names.
    std::string resolve(u8 ix, u32 i) const {
        switch (ix) {
            case IxString: return "\"" + escapeSmali(str(i)) + "\"";
            case IxType:   return type(i);
            case IxField:  return field(i);
            case IxMethod: return method(i);
            case IxProto:  return proto(i);
            case IxCallSite:     return rawIx("call_site", i);
            case IxMethodHandle: return rawIx("method_handle", i);
            default:       return rawIx("index", i);
        }
    }

    // The raw pool tag for the comment column, so a resolved operand can still
    // be correlated back to its index.
    static std::string ixTag(u8 ix, u32 i) {
        const char* k;
        switch (ix) {
            case IxString: k = "string"; break;
            case IxType:   k = "type"; break;
            case IxField:  k = "field"; break;
            case IxMethod: k = "meth"; break;
            case IxProto:  k = "proto"; break;
            case IxCallSite:     k = "call_site"; break;
            case IxMethodHandle: k = "method_handle"; break;
            default: return std::string();
        }
        char b[40];
        std::snprintf(b, sizeof b, "%s@%u", k, i);
        return b;
    }

    // Minimal smali string escaping for the operand column. The result is a
    // DISPLAY string; the engine JSON-escapes it again when it serialises.
    static std::string escapeSmali(const std::string& s) {
        std::string r;
        r.reserve(s.size() + 4);
        for (unsigned char c : s) {
            switch (c) {
                case '\\': r += "\\\\"; break;
                case '"':  r += "\\\""; break;
                case '\n': r += "\\n"; break;
                case '\r': r += "\\r"; break;
                case '\t': r += "\\t"; break;
                default:
                    if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\x%02x", c); r += b; }
                    else r += char(c);
            }
        }
        return r;
    }
};

// ---- small formatters -------------------------------------------------------
namespace detail {

inline std::string reg(u32 r, u32 registersSize, u32 insSize) {
    // The last `insSize` registers are the incoming parameters, shown pN; the
    // rest are locals, shown vN — the baksmali convention.
    char b[16];
    if (insSize && registersSize >= insSize && r >= registersSize - insSize)
        std::snprintf(b, sizeof b, "p%u", r - (registersSize - insSize));
    else
        std::snprintf(b, sizeof b, "v%u", r);
    return b;
}

// A signed literal as hex: 0x0, 0x1a, -0x1. The magnitude is taken in unsigned
// arithmetic so INT64_MIN (whose negation overflows a signed 64) is safe.
inline std::string lit(i64 v) {
    char b[32];
    if (v < 0) {
        u64 mag = ~u64(v) + 1;
        std::snprintf(b, sizeof b, "-0x%llx", (unsigned long long)mag);
    } else {
        std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
    }
    return b;
}

// A relative branch offset in code units, signed: +0x5, -0x3.
inline std::string rel(i64 off) {
    char b[32];
    if (off < 0) std::snprintf(b, sizeof b, "-0x%llx", (unsigned long long)(-off));
    else std::snprintf(b, sizeof b, "+0x%llx", (unsigned long long)off);
    return b;
}

inline std::string hexUnits(const u8* p, size_t avail, u32 units, u32 cap = 16) {
    std::string r;
    u32 show = units < cap ? units : cap;
    for (u32 k = 0; k < show; ++k) {
        if (u64(k) * 2 + 2 > avail) break;
        char b[8];
        std::snprintf(b, sizeof b, "%04x", rd16(p + k * 2));
        r += b;
    }
    if (units > cap) r += "..";
    return r;
}

} // namespace detail

// ---- payload pseudo-ops -----------------------------------------------------
// A packed-switch / sparse-switch / fill-array-data payload is not a normal
// instruction: its first code unit is 0x0100 / 0x0200 / 0x0300 and its length
// is data-driven. It has to be measured exactly so linear decoding of the rest
// of the method stays in step, and it is rendered as one honest summary line
// rather than a decode of bytes that are data, not code.
inline u32 payloadUnits(const u8* data, size_t n, u64 off, u16 hi, bool& ok) {
    ok = true;
    if (hi == 0x01) {                 // packed-switch-payload
        if (off + 4 > n) { ok = false; return 1; }
        u16 size = rd16(data + off + 2);
        return 4 + u32(size) * 2;
    }
    if (hi == 0x02) {                 // sparse-switch-payload
        if (off + 4 > n) { ok = false; return 1; }
        u16 size = rd16(data + off + 2);
        return 2 + u32(size) * 4;
    }
    if (hi == 0x03) {                 // fill-array-data-payload
        if (off + 8 > n) { ok = false; return 1; }
        u16 width = rd16(data + off + 2);
        u32 size = rd32(data + off + 4);
        u64 dataUnits = (u64(size) * width + 1) / 2;
        return u32(4 + dataUnits);
    }
    ok = false;
    return 1;
}

// ---- the decoder ------------------------------------------------------------
inline MethodCode decodeMethod(const u8* data, size_t n, u64 codeOff,
                               const DexIndex& index, size_t maxLines = 20000) {
    using namespace detail;
    MethodCode mc;
    if (!data || codeOff == 0 || codeOff + 16 > n) {
        mc.error = "no code item at this offset";
        return mc;
    }
    mc.registersSize = rd16(data + codeOff);
    mc.insSize = rd16(data + codeOff + 2);
    mc.outsSize = rd16(data + codeOff + 4);
    mc.triesSize = rd16(data + codeOff + 6);
    mc.insnsUnits = rd32(data + codeOff + 12);
    mc.insnsOff = codeOff + 16;
    if (mc.insnsUnits == 0) { mc.ok = true; return mc; }
    if (mc.insnsOff + u64(mc.insnsUnits) * 2 > n) {
        // The header claims more code than the file holds. Decode what is there
        // and say it is short rather than reading past the end.
        mc.truncated = true;
        u64 avail = n > mc.insnsOff ? (n - mc.insnsOff) / 2 : 0;
        mc.insnsUnits = u32(avail);
        if (mc.insnsUnits == 0) { mc.ok = true; return mc; }
    }

    Pools pools; pools.data = data; pools.n = n; pools.idx = index;
    const OpInfo* T = opTable();
    const u32 rs = mc.registersSize, ins = mc.insSize;
    auto R = [&](u32 r) { return reg(r, rs, ins); };

    u32 pos = 0;
    while (pos < mc.insnsUnits) {
        if (mc.lines.size() >= maxLines) { mc.truncated = true; break; }
        u64 boff = mc.insnsOff + u64(pos) * 2;
        if (boff + 2 > n) { mc.truncated = true; break; }
        u16 u0 = rd16(data + boff);
        u8 op = u0 & 0xFF;
        u8 hib = u8(u0 >> 8);

        // read code unit k of this instruction, or 0 if out of range
        auto U = [&](u32 k) -> u16 {
            u64 o = boff + u64(k) * 2;
            return (o + 2 <= n && (pos + k) < mc.insnsUnits) ? rd16(data + o) : 0;
        };

        SmaliLine ln;
        ln.off = boff;
        ln.unit = pos;

        // A 0x00 with a non-zero high byte is a switch / array-data payload,
        // not a nop.
        if (op == 0x00 && hib != 0x00) {
            bool ok = false;
            u32 units = payloadUnits(data, n, boff, hib, ok);
            if (units == 0) units = 1;
            if (!ok) mc.truncated = true;
            // Never let a data-driven length run past the insns array.
            if (pos + units > mc.insnsUnits) { units = mc.insnsUnits - pos; mc.truncated = true; }
            ln.units = units ? units : 1;
            ln.bytes = hexUnits(data + boff, n - boff, ln.units);
            if (hib == 0x01) {
                ln.mnem = "packed-switch-payload";
                u16 size = (boff + 4 <= n) ? rd16(data + boff + 2) : 0;
                ln.ops = std::to_string(size) + " targets";
            } else if (hib == 0x02) {
                ln.mnem = "sparse-switch-payload";
                u16 size = (boff + 4 <= n) ? rd16(data + boff + 2) : 0;
                ln.ops = std::to_string(size) + " keys";
            } else if (hib == 0x03) {
                ln.mnem = "fill-array-data-payload";
                u16 width = (boff + 4 <= n) ? rd16(data + boff + 2) : 0;
                u32 size = (boff + 8 <= n) ? rd32(data + boff + 4) : 0;
                ln.ops = std::to_string(size) + " x " + std::to_string(width) + " bytes";
            } else {
                ln.mnem = "nop-payload";
            }
            mc.lines.push_back(ln);
            if (ln.units == 0) { mc.truncated = true; break; }
            pos += ln.units;
            continue;
        }

        const OpInfo& oi = T[op];
        if (oi.name == nullptr || oi.fmt == FUnknown) {
            char b[32];
            std::snprintf(b, sizeof b, "<unknown-op 0x%02x>", op);
            ln.mnem = b;
            ln.units = 1;
            ln.bytes = hexUnits(data + boff, n - boff, 1);
            mc.lines.push_back(ln);
            pos += 1;
            continue;
        }

        u32 units = fmtUnits(oi.fmt);
        // An instruction that would read past the end of insns[] is truncated:
        // render the mnemonic honestly, mark short, and stop.
        if (pos + units > mc.insnsUnits) {
            ln.mnem = oi.name;
            ln.units = mc.insnsUnits - pos;
            ln.ops = "<truncated>";
            ln.bytes = hexUnits(data + boff, n - boff, ln.units ? ln.units : 1);
            mc.lines.push_back(ln);
            mc.truncated = true;
            break;
        }
        ln.units = units;
        ln.bytes = hexUnits(data + boff, n - boff, units);
        ln.mnem = oi.name;

        // Decode operands per the documented format.
        switch (oi.fmt) {
            case F10x:
                break;
            case F12x: {                       // op B|A  -> vA, vB
                u32 a = (u0 >> 8) & 0xF, b = (u0 >> 12) & 0xF;
                ln.ops = R(a) + ", " + R(b);
                break;
            }
            case F11n: {                       // op B|A  -> vA, #+B (signed 4)
                u32 a = (u0 >> 8) & 0xF; i64 b = sext((u0 >> 12) & 0xF, 4);
                ln.ops = R(a) + ", " + lit(b);
                break;
            }
            case F11x: {                       // op AA   -> vAA
                ln.ops = R((u0 >> 8) & 0xFF);
                break;
            }
            case F10t: {                       // op AA   -> +AA (signed 8)
                i64 t = sext((u0 >> 8) & 0xFF, 8);
                ln.ops = rel(t);
                ln.comment = hexAddr(mc.insnsOff + u64(i64(pos) + t) * 2);
                break;
            }
            case F20t: {                       // ØØ|op AAAA -> +AAAA (signed 16)
                i64 t = sext(U(1), 16);
                ln.ops = rel(t);
                ln.comment = hexAddr(mc.insnsOff + u64(i64(pos) + t) * 2);
                break;
            }
            case F22x: {                       // op AA BBBB -> vAA, vBBBB
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + R(U(1));
                break;
            }
            case F21t: {                       // op AA BBBB -> vAA, +BBBB
                i64 t = sext(U(1), 16);
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + rel(t);
                ln.comment = hexAddr(mc.insnsOff + u64(i64(pos) + t) * 2);
                break;
            }
            case F21s: {                       // op AA BBBB -> vAA, #+BBBB (s16)
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + lit(sext(U(1), 16));
                break;
            }
            case F21h: {                       // op AA BBBB -> vAA, #+BBBB shifted
                // const/high16 puts B in the high 16 bits of a 32-bit value;
                // const-wide/high16 puts it in the high 16 bits of a 64-bit one.
                u16 b = U(1);
                i64 val = (op == 0x19) ? i64(u64(b) << 48) : i64(i32(u32(b) << 16));
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + lit(val);
                break;
            }
            case F21c: {                       // op AA BBBB -> vAA, <index>
                u32 i = U(1);
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + pools.resolve(oi.ix, i);
                ln.comment = Pools::ixTag(oi.ix, i);
                break;
            }
            case F23x: {                       // op AA BB CC -> vAA, vBB, vCC
                u16 u1 = U(1);
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + R(u1 & 0xFF) + ", " + R(u1 >> 8);
                break;
            }
            case F22b: {                       // op AA BB CC -> vAA, vBB, #+CC (s8)
                u16 u1 = U(1);
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + R(u1 & 0xFF) + ", " +
                         lit(sext((u1 >> 8) & 0xFF, 8));
                break;
            }
            case F22t: {                       // op B|A CCCC -> vA, vB, +CCCC
                u32 a = (u0 >> 8) & 0xF, b = (u0 >> 12) & 0xF;
                i64 t = sext(U(1), 16);
                ln.ops = R(a) + ", " + R(b) + ", " + rel(t);
                ln.comment = hexAddr(mc.insnsOff + u64(i64(pos) + t) * 2);
                break;
            }
            case F22s: {                       // op B|A CCCC -> vA, vB, #+CCCC
                u32 a = (u0 >> 8) & 0xF, b = (u0 >> 12) & 0xF;
                ln.ops = R(a) + ", " + R(b) + ", " + lit(sext(U(1), 16));
                break;
            }
            case F22c: {                       // op B|A CCCC -> vA, vB, <index>
                u32 a = (u0 >> 8) & 0xF, b = (u0 >> 12) & 0xF;
                u32 i = U(1);
                ln.ops = R(a) + ", " + R(b) + ", " + pools.resolve(oi.ix, i);
                ln.comment = Pools::ixTag(oi.ix, i);
                break;
            }
            case F30t: {                       // ØØ|op AAAAlo AAAAhi -> +AAAAAAAA
                i64 t = i32(u32(U(1)) | (u32(U(2)) << 16));
                ln.ops = rel(t);
                ln.comment = hexAddr(mc.insnsOff + u64(i64(pos) + t) * 2);
                break;
            }
            case F32x: {                       // ØØ|op AAAA BBBB -> vAAAA, vBBBB
                ln.ops = R(U(1)) + ", " + R(U(2));
                break;
            }
            case F31i: {                       // op AA BBBBlo hi -> vAA, #+B32
                i64 v = i32(u32(U(1)) | (u32(U(2)) << 16));
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + lit(v);
                break;
            }
            case F31t: {                       // op AA BBBBlo hi -> vAA, +B32 (payload)
                i64 t = i32(u32(U(1)) | (u32(U(2)) << 16));
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + rel(t);
                ln.comment = hexAddr(mc.insnsOff + u64(i64(pos) + t) * 2);
                break;
            }
            case F31c: {                       // op AA BBBBlo hi -> vAA, <string>
                u32 i = u32(U(1)) | (u32(U(2)) << 16);
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + pools.resolve(oi.ix, i);
                ln.comment = Pools::ixTag(oi.ix, i);
                break;
            }
            case F35c: {                       // {vC..vG}, <index>
                u32 A = (u0 >> 12) & 0xF, G = (u0 >> 8) & 0xF;
                u32 i = U(1);
                u16 u2 = U(2);
                u32 rC = u2 & 0xF, rD = (u2 >> 4) & 0xF, rE = (u2 >> 8) & 0xF, rF = (u2 >> 12) & 0xF;
                std::string regs = "{";
                u32 arr[5] = { rC, rD, rE, rF, G };
                for (u32 k = 0; k < A && k < 5; ++k) { if (k) regs += ", "; regs += R(arr[k]); }
                regs += "}";
                ln.ops = regs + ", " + pools.resolve(oi.ix, i);
                ln.comment = Pools::ixTag(oi.ix, i);
                break;
            }
            case F3rc: {                       // {vCCCC..vNNNN}, <index>
                u32 A = (u0 >> 8) & 0xFF;
                u32 i = U(1);
                u32 c = U(2);
                std::string regs = "{";
                if (A == 0) regs += "";
                else if (A == 1) regs += R(c);
                else regs += R(c) + " .. " + R(c + A - 1);
                regs += "}";
                ln.ops = regs + ", " + pools.resolve(oi.ix, i);
                ln.comment = Pools::ixTag(oi.ix, i);
                break;
            }
            case F45cc: {                      // {vC..vG}, meth, proto
                u32 A = (u0 >> 12) & 0xF, G = (u0 >> 8) & 0xF;
                u32 mi = U(1);
                u16 u2 = U(2);
                u32 pi = U(3);
                u32 rC = u2 & 0xF, rD = (u2 >> 4) & 0xF, rE = (u2 >> 8) & 0xF, rF = (u2 >> 12) & 0xF;
                std::string regs = "{";
                u32 arr[5] = { rC, rD, rE, rF, G };
                for (u32 k = 0; k < A && k < 5; ++k) { if (k) regs += ", "; regs += R(arr[k]); }
                regs += "}";
                ln.ops = regs + ", " + pools.method(mi) + ", " + pools.proto(pi);
                ln.comment = Pools::ixTag(IxMethod, mi) + " " + Pools::ixTag(IxProto, pi);
                break;
            }
            case F4rcc: {                      // {vCCCC..vNNNN}, meth, proto
                u32 A = (u0 >> 8) & 0xFF;
                u32 mi = U(1);
                u32 c = U(2);
                u32 pi = U(3);
                std::string regs = "{";
                if (A == 1) regs += R(c);
                else if (A > 1) regs += R(c) + " .. " + R(c + A - 1);
                regs += "}";
                ln.ops = regs + ", " + pools.method(mi) + ", " + pools.proto(pi);
                ln.comment = Pools::ixTag(IxMethod, mi) + " " + Pools::ixTag(IxProto, pi);
                break;
            }
            case F51l: {                       // op AA B(x4) -> vAA, #+B64
                u64 v = u64(U(1)) | (u64(U(2)) << 16) | (u64(U(3)) << 32) | (u64(U(4)) << 48);
                char b[32];
                std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
                ln.ops = R((u0 >> 8) & 0xFF) + ", " + b + "L";
                break;
            }
            default: {
                char b[32];
                std::snprintf(b, sizeof b, "<unknown-op 0x%02x>", op);
                ln.mnem = b;
                break;
            }
        }

        mc.lines.push_back(ln);
        pos += units;
    }

    mc.ok = true;
    return mc;
}

} // namespace dexsmali
} // namespace sako
