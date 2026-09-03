// Binary loader engines: ELF / PE / DEX
#pragma once
#include "Types.h"

namespace sako {

ElfInfo parseElf(const Binary& b);
PeInfo  parsePe(const Binary& b);
DexInfo parseDex(const Binary& b);

// Map a virtual address to a raw file offset (uses section/segment tables).
// Returns u64(-1) when unmapped.
u64 elfVaToOff(const ElfInfo& e, u64 va);
u64 peVaToOff(const PeInfo& e, u64 va);   // va = imageBase + rva

// --- ELF helpers ---
const Section* elfSectionAt(const ElfInfo& e, u64 va);
// Largest executable PROGBITS section (code range)
bool elfExecRange(const ElfInfo& e, u64& va, u64& size);

// --- PE helpers ---
bool peExecRange(const PeInfo& e, u64& va, u64& size);

} // namespace sako
