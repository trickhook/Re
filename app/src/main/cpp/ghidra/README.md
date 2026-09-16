# Ghidra decompiler (vendored)

The p-code decompiler from Ghidra, used as Nocturne's high-fidelity
decompilation backend alongside the built-in IR lifter.

- **Upstream:** https://github.com/NationalSecurityAgency/ghidra
- **Commit:** `263160cf57db21a9e25f1e0a8bc42fde5b8824eb`
- **Path:** `Ghidra/Features/Decompiler/src/decompile/cpp`
- **Licence:** Apache-2.0 — see `LICENSE`

## What is here and what is not

`cpp/` holds 78 of the 115 translation units upstream ships, plus every
header. The decompiler proper has no Java or JNI dependency: in a Ghidra
installation the Java side drives this code over a pipe, so it links directly.

Left out, and why:

| left out | reason |
|---|---|
| `bfd_arch`, `loadimage_bfd`, `codedata`, `analyzesigs` | need binutils BFD to read a file from disk. Nocturne has its own loaders and feeds bytes from memory. |
| `*_ghidra` (`loadimage_ghidra`, `database_ghidra`, …), `ghidra_arch`, `ghidra_process`, `ghidra_translate`, `ghidra_context` | the pipe protocol back to a running Ghidra. There is no Ghidra here to talk to. |
| `ifacedecomp`, `ifaceterm`, `interface`, `consolemain`, `ruleparse`, `rulecompile`, `unify` | the interactive console front end and its dynamic rule compiler. |
| `slgh_compile`, `slghparse`, `slghscan` | the SLEIGH compiler. Specs are compiled ahead of time in CI, not on a phone. |
| `raw_arch`, `xml_arch`, `loadimage_xml` | alternative Architecture entry points. `GhidraArch` in `sako/` is our own. |
| `printjava`, `signature`, `paramid`, `grammar` | other output languages, signature hashing, and the C type-declaration parser. |
| `test`, `testfunction`, `sleighexample` | upstream's own tests and example. |

`pcodeparse` and `pcodecompile` are kept: the AARCH64 compiler spec defines
p-code injections, and parsing those needs the snippet parser.

## Updating

Re-run the sparse checkout in `.github/workflows/ghidra-decompiler-poc.yml`,
copy the files named in `CMakeLists.txt`'s `GHIDRA_SOURCES`, and rebuild. The
SLEIGH specs under `app/src/main/assets/sleigh/` must be regenerated with the
matching `sleigh` compiler — the `.sla` format is versioned against the
decompiler that reads it.
