Nocturne 2.1.0-rc1

First signed release, and a release candidate on purpose: R8 has never run on
this project before, so this build exists to be installed by hand and
exercised once before 2.1.0 goes out to anyone's updater.

Decompiles eight architectures, not four. MIPS, PowerPC, SPARC and m68k now
go through Ghidra's decompiler instead of rendering a correctly-named
function with an empty body. SystemZ still only disassembles, and the app now
says so rather than listing all nine as equals — Ghidra ships no
z/Architecture processor module.

A p-code emulator. Run a function with your own arguments and read back what
it wrote: the plaintext a decrypt routine produces, a computed jump resolved,
a string assembled at runtime that is nowhere in the file. On the obfuscated
sample this project is tested against it recovers eleven such strings,
including an MD5 of the empty string that identifies its own function.

An MCP server, so an assistant can drive the engine over your network with no
cable: fourteen tools, read-only by default, a 256-bit token, and a QR to
pair. Not an AI feature in the app — there is no model client in here.

IDA Pro interoperability. Renames, comments and bookmarks export as an
IDAPython or IDC script that measures the right rebase instead of guessing,
and never overwrites a name you typed in IDA. Annotations come back from an
IDA IDC dump.

Five new plugins and eighteen new script builtins, including access to the
emulator. Three previously shipped plugins were annotating nothing at all on
ARM64 and now work.

An in-app updater, which is why this release exists at all.

The engine's call graph meant three different things on three screens and now
means one, cross-checked against llvm-objdump. The UI has a motion system
that honours the system's reduce-animation setting. And the Ghidra backend
had never once run on a device, because an escaped dollar sign made the
SLEIGH specifications fail to install, silently, since the day it landed.

Known: the debugger needs a rooted or debuggable device. An emulator result
marked approximate is plausible, not certain. MCP traffic is unencrypted on
your network — use the loopback mode and adb forward if that matters.

