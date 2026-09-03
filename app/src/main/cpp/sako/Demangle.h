// Symbol demangler — Itanium C++ ABI (GCC/Clang) + MSVC-lite decorations.
// Self-contained; returns the input unchanged when it cannot demangle.
#pragma once
#include "Types.h"
#include <string>

namespace sako {

// Returns demangled name for _Z... / ?... symbols, or the original name.
std::string demangle(const std::string& mangled);

// true when the name looks like an Itanium or MSVC mangled symbol.
bool looksMangled(const std::string& name);

} // namespace sako
