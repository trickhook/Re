// sigmatch — host test harness for the library-function matcher.
//
// It loads a (typically stripped) ELF exactly as the engine does
// (loadBinaryFile -> parseElf -> discoverFunctionsElf), applies a signature
// database with the ENGINE's own matcher (LibSig.h / LibSigFormat.h — the same
// code that runs on device), and prints one line per function it named plus the
// summary counts. This is what turns "it compiles" into a measured round trip:
// pair it with score_roundtrip.py to get present / named / correct / wrong /
// missed on a real library. It is host-only and lives in tools/ by design; the
// on-device path is Engine::setLibSigDb + Engine::analyze.
//
// Build (host, no capstone/ghidra needed — discovery and matching are byte-level):
//   g++ -std=c++17 -O2 -I ../app/src/main/cpp/sako sigmatch.cpp \
//       ../app/src/main/cpp/sako/{Types,Binary,ElfLoader,PeLoader,Analyzer}.cpp -o sigmatch
//
// Usage:  sigmatch <elf> <db.nsig> [--all]
//   default prints only functions the matcher named (from==lib);
//   --all prints every discovered function.
#include "Analysis.h"
#include "Loaders.h"
#include "Binary.h"
#include "LibSig.h"
#include <cstdio>
#include <string>
using namespace sako;

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: sigmatch <elf> <db.nsig> [--all]\n"); return 2; }
    bool all = (argc > 3 && std::string(argv[3]) == "--all");
    Binary b = loadBinaryFile(argv[1]);
    if (b.data.empty()) { fprintf(stderr, "cannot read %s\n", argv[1]); return 1; }
    ElfInfo e = parseElf(b);
    size_t found = 0;
    std::vector<FuncInfo> funcs = discoverFunctionsElf(b, e, &found);

    libsig::Db db;
    std::string err;
    if (!loadLibSigDb(argv[2], db, &err)) { fprintf(stderr, "db load failed: %s\n", err.c_str()); return 1; }

    LibMatchStats st;
    applyLibSignaturesElf(b, e, funcs, db, &st);

    for (auto& f : funcs)
        if (f.from == "lib" || all)
            printf("%llx %llu %s %s\n", (unsigned long long)f.addr,
                   (unsigned long long)f.size, f.from.c_str(), f.name.c_str());

    fprintf(stderr,
        "arch=%s dbRecords=%zu dbForArch=%zu funcs=%zu\n"
        "unknownBefore=%zu attempted=%zu NAMED=%zu collisions=%zu matchMs=%.2f\n",
        e.archEnum.c_str(), db.size(), db.countForArch(libsig::archIdFromEnum(e.archEnum)),
        funcs.size(), st.unknownBefore, st.attempted, st.named, st.collisions, st.ms);
    return 0;
}
