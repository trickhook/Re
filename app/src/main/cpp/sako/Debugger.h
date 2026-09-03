// Experimental ptrace-based syscall tracer.
// Forks a child process (from Android's own app process), attaches via
// PTRACE_TRACEME and records syscalls + register snapshots.
//
// NOTE: on unrooted devices SELinux may deny exec/ptrace for system binaries.
// In that case a clear error is returned instead of crashing.
#pragma once
#include "Types.h"
#include <atomic>
#include <string>
#include <vector>

namespace sako {

struct DebugResult {
    bool ok = false;
    std::string error;
    std::vector<std::string> eventJson; // each line: one syscall event JSON object
};

// argv[0] = program path (fallback: /system/bin/<base>), rest = args.
// maxEvents capped internally to 1000.
DebugResult debugRunSyscalls(const std::vector<std::string>& argv, int maxEvents,
                             std::atomic<bool>& stopFlag);

// Kills the currently traced child (if any).
void debugStopChild();

} // namespace sako
