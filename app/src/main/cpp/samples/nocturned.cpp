// Nocturne debugger daemon — the engine's JSON debugger, over a pipe.
//
// This is the whole privileged half of the ROOT backend. It is the SAME engine
// the app runs in-process (sako_jni.cpp) and the SAME engine the Shizuku user
// service runs across a Binder (NocturneUserService); the only thing that
// changes here is the transport. There it is a JNI call or a Binder
// transaction; here it is a pipe, and the process is a standalone executable
// the app launches with `su`.
//
// The loop below is the entire program: read one line of JSON from stdin, hand
// it verbatim to sako::Engine::instance().dbgCmd(), write the one-line JSON
// answer to stdout, flush. Every debugger op the engine already understands —
// spawn, attach, cont, step, bp_add, regs, read, stack, threads, ps, poll and
// the rest — works here with no code of its own, because the protocol is the
// engine's, not the daemon's. There is deliberately no argv parsing and no
// configuration: everything the session needs arrives as JSON on stdin.
//
// SECURITY SURFACE. This process accepts NOTHING but that debugger protocol.
// There is no shell op, no file-copy op, no "run this command" — a line that is
// not one of the engine's debugger ops is answered by the engine with
// {"ok":false,"error":"unknown op: ..."} and changes nothing on the device. The
// only writer of its stdin is the app that launched it (the pipe is private to
// that parent/child pair), so "root debugger" never widens into "root shell for
// anything on the device". The engine can spawn a program the caller names, or
// ptrace-attach to a pid the caller names, because that is what a debugger is;
// it cannot be asked to do anything else.
//
// LIFETIME. When the app that holds the write end of the pipe goes away — a
// clean disconnect, a backend switch, or the app process being killed — the
// next std::getline() sees end-of-file, the loop ends, and this process exits.
// The engine sets PTRACE_O_EXITKILL on every tracee, so a spawned child dies
// with the daemon and an attached process is released. That EOF-triggered exit
// is the backstop that stops a leaked root daemon from outliving the app even
// when the app never got to kill it explicitly.

#include <iostream>
#include <string>

#include "sako/Engine.h"

int main() {
    // A request/response pipe: decouple from C stdio and flush after each
    // answer, so the app is never left waiting on a reply that is sitting in a
    // buffer this side of the pipe.
    std::ios_base::sync_with_stdio(false);

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        const std::string answer = sako::Engine::instance().dbgCmd(line);
        std::cout << answer << '\n';
        std::cout.flush();
    }
    return 0;
}
