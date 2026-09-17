Nocturne 2.2.0

Runs and debugs a sample on an ordinary unrooted phone. Until now the debugger
could only trace something already running, because since Android 10 an app may
not execute a file from its own storage — so a sample you imported could not be
launched at all. A Shizuku user service at shell uid stages the sample into
/data/local/tmp, makes it executable, and forks it under ptrace: the gdbserver
workflow, with breakpoints, registers, memory, stack and threads. This is the
"needs a rooted or debuggable device" limitation from 2.1.0, lifted. It needs
Shizuku running; the tab walks the setup and, when the engine cannot start in
the service process, prints the exact reason instead of failing blankly.

Four debugger backends, and Attach picks a process instead of a pid. In-process
is unchanged. Shizuku shell runs your sample. Shizuku root and a new direct-su
root backend — for devices with Magisk but no Shizuku — attach to any running
process; the su backend is the same engine as the app, spoken over a pipe, and
it accepts nothing but the debugger protocol, never a shell. Attach no longer
asks you to know a pid: it lists the running processes of your installed apps by
name and you tap one. Where a backend can enumerate but not attach, the control
stays honestly disabled rather than failing when pressed.

Analysis reaches the end of the binary. The function list was silently capped
at 4000; the cap is gone, and on a stripped shared object the engine now runs a
prologue scan that actually finds the functions the symbol table omits —
libcrypto goes from 5,363 to 10,908 — at a measured false-positive rate under
0.1% where a .dynsym is present. The list pages rather than truncating, and
every count that used to be a floor now says so: cross-reference totals, string
totals, DEX method and class totals, and a disassembly that tells you when it is
showing part of a function rather than the whole. The C++ demangler was
rewritten; against c++filt over 106,385 real symbols it went from 8.78% to
99.23% exact, and the placeholder "subst_" text that used to litter 40,000 names
is gone.

Produce a C file for the whole binary, the way IDA does. It decompiles every
function to one .c streamed to disk, with progress and cancel, and a function
the decompiler refuses is marked in the file and the run continues, rather than
one failure ending the export.

An online plugin hub, entirely on GitHub, no server. Browse community plugins
and install them — each is verified by its SHA-256 and an ECDSA signature before
a byte is written. Write your own in an in-app editor, test-run it, and publish:
your device holds an EC P-256 key that signs the plugin to prove it is yours and
untampered, and publishing opens a GitHub issue that an automated check
validates and merges. The signature is authorship and integrity, not a GitHub
credential and not a safety proof of anyone's script — which is safe here
because a plugin is sandboxed NocturneScript, loop-guarded, with no file,
network or exec. The end-to-end path is proven: a real device-signed submission
verifies against the registry's own validator.

A bundled test target to learn the tools on. A small crackme ships inside the
app and as its own downloadable artifact — load it, find the check, breakpoint
it, and defeat it by flipping one branch. docs/TEST-TARGET.md walks it.

Smaller than it was on the way here. The su-root daemon had briefly linked the
whole decompiler it never calls; it does not any more, which is tens of
megabytes off the APK, per architecture. The app engine keeps Ghidra in full —
the Pseudo-C tab and the MCP decompiler are exactly that.

Known: attaching to a process you did not start still needs root — the shell
backend runs samples but cannot ptrace a foreign process, and says so. Running
a sample at all needs Shizuku or root; a stock app still cannot. The plugin
hub's automated merge needs two repository settings enabled and the registry
index live on the default branch; installing and browsing need neither. An
emulator result marked approximate is plausible, not certain. MCP traffic is
plain HTTP in the Wi-Fi mode and encrypted only in the default loopback-plus-adb
mode. The ARM32 function-discovery rules are reasoned, not yet measured against
a non-stripped ARM32 binary.
