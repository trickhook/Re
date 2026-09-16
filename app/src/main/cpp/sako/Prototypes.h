// Signatures for functions a stripped binary imports by name.
//
// Knowing that strlen takes a const char* is what lets the decompiler print
// a string literal instead of the address of one: it only reads through a
// constant pointer when the pointer's type says it points at characters.
// Return types matter almost as much — without them every call result is an
// undefined8 and nothing downstream can be typed from it.
#pragma once

namespace sako {
namespace proto {

// Compact encoding, one character per type:
//   v void        i int (4)       u unsigned (4)   l long (8)      z size_t (8)
//   p void *      s const char *  w wchar/short     c char (1)     f float  d double
//   . varargs from here on
struct KnownProto {
    const char* name;
    const char* ret;     // one character
    const char* args;    // one character per parameter, "" for none
};

extern const KnownProto kKnownProtos[];
extern const int kKnownProtoCount;

} // namespace proto
} // namespace sako
