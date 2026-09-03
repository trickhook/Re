#include "Debugger.h"
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/uio.h>
#include <linux/elf.h>

#if defined(__aarch64__)
#include <asm/ptrace.h>
#define SAKO_ARCH_ARM64 1
#elif defined(__x86_64__)
#include <sys/user.h>
#define SAKO_ARCH_X86 1
#endif

namespace sako {

static std::atomic<pid_t> g_childPid{0};

void debugStopChild() {
    pid_t pid = g_childPid.load();
    if (pid > 0) kill(pid, SIGKILL);
}

#if defined(SAKO_ARCH_ARM64)
static const char* arm64SysName(long nr) {
    switch (nr) {
        case 17: return "getcwd"; case 19: return "eventfd2"; case 23: return "dup";
        case 24: return "dup3"; case 25: return "fcntl"; case 26: return "inotify_init1";
        case 29: return "ioctl"; case 32: return "flock"; case 33: return "mknodat";
        case 34: return "mkdirat"; case 35: return "unlinkat"; case 36: return "symlinkat";
        case 37: return "linkat"; case 38: return "renameat"; case 40: return "mount";
        case 43: return "statfs"; case 44: return "fstatfs"; case 45: return "truncate";
        case 46: return "ftruncate"; case 47: return "fallocate"; case 48: return "faccessat";
        case 49: return "chdir"; case 50: return "fchdir"; case 51: return "chroot";
        case 52: return "fchmod"; case 54: return "setxattr";
        case 56: return "openat"; case 57: return "close";
        case 61: return "getdents64"; case 62: return "lseek";
        case 63: return "read"; case 64: return "write"; case 65: return "readv";
        case 66: return "writev"; case 67: return "pread64"; case 68: return "pwrite64";
        case 71: return "sendmsg"; case 73: return "recvmsg"; case 78: return "readlinkat";
        case 79: return "newfstatat"; case 80: return "fstat";
        case 82: return "fsync"; case 83: return "fdatasync"; case 93: return "exit";
        case 94: return "exit_group"; case 96: return "set_tid_address";
        case 98: return "futex"; case 99: return "set_robust_list";
        case 113: return "clock_gettime"; case 115: return "clock_nanosleep";
        case 116: return "syslog"; case 117: return "ptrace"; case 118: return "sched_setparam";
        case 122: return "sched_setaffinity"; case 123: return "sched_getaffinity";
        case 124: return "sched_yield"; case 129: return "kill";
        case 130: return "tkill"; case 131: return "tgkill";
        case 134: return "rt_sigaction"; case 135: return "rt_sigprocmask";
        case 139: return "rt_sigreturn"; case 160: return "uname";
        case 169: return "gettimeofday"; case 172: return "getpid";
        case 174: return "getuid"; case 175: return "geteuid";
        case 176: return "getgid"; case 177: return "getegid";
        case 178: return "gettid"; case 198: return "socket";
        case 203: return "connect"; case 212: return "shutdown";
        case 214: return "brk"; case 215: return "munmap";
        case 216: return "mremap"; case 220: return "clone";
        case 221: return "execve"; case 222: return "mmap";
        case 226: return "mprotect"; case 227: return "msync";
        case 233: return "madvise"; case 262: return "newstat";
        case 263: return "newlstat"; case 278: return "getrandom";
        case 281: return "execveat"; case 283: return "membarrier";
        default: return nullptr;
    }
}
#endif // SAKO_ARCH_ARM64

#if defined(SAKO_ARCH_X86)
static const char* x86SysName(long nr) {
    switch (nr) {
        case 0: return "read"; case 1: return "write"; case 2: return "open";
        case 3: return "close"; case 4: return "stat"; case 5: return "fstat";
        case 6: return "lstat"; case 7: return "poll"; case 8: return "lseek";
        case 9: return "mmap"; case 10: return "mprotect"; case 11: return "munmap";
        case 12: return "brk"; case 13: return "rt_sigaction"; case 14: return "rt_sigprocmask";
        case 16: return "ioctl"; case 17: return "pread64"; case 18: return "pwrite64";
        case 19: return "readv"; case 20: return "writev"; case 21: return "access";
        case 23: return "select"; case 25: return "mremap"; case 33: return "dup2";
        case 39: return "getpid"; case 41: return "socket"; case 42: return "connect";
        case 43: return "accept"; case 45: return "recvfrom"; case 46: return "sendto";
        case 47: return "recvmsg"; case 48: return "sendmsg"; case 56: return "clone";
        case 57: return "fork"; case 58: return "vfork"; case 59: return "execve";
        case 60: return "exit"; case 61: return "wait4"; case 62: return "kill";
        case 63: return "uname"; case 72: return "fcntl"; case 79: return "getcwd";
        case 80: return "chdir"; case 87: return "unlink"; case 89: return "readlink";
        case 96: return "gettimeofday"; case 102: return "getuid";
        case 107: return "geteuid"; case 110: return "getppid";
        case 157: return "prctl"; case 158: return "arch_prctl";
        case 186: return "gettid"; case 202: return "futex";
        case 218: return "set_tid_address"; case 231: return "exit_group";
        case 232: return "epoll_wait"; case 257: return "openat";
        case 262: return "newfstatat"; case 273: return "set_robust_list";
        case 288: return "accept4"; case 291: return "execveat";
        case 302: return "prlimit64"; case 318: return "getrandom";
        case 334: return "rseq"; case 435: return "clone3";
        default: return nullptr;
    }
}
#endif // SAKO_ARCH_X86

DebugResult debugRunSyscalls(const std::vector<std::string>& argv, int maxEvents,
                             std::atomic<bool>& stopFlag) {
    DebugResult res;
    if (argv.empty() || argv[0].empty()) { res.error = "No program specified"; return res; }
    if (maxEvents <= 0) maxEvents = 200;
    if (maxEvents > 1000) maxEvents = 1000;

    std::vector<char*> cargv;
    for (auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);
    std::vector<char*> cenv;
    cenv.push_back(const_cast<char*>("SAKO_TRACE=1"));
    cenv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) { res.error = std::string("fork failed: ") + strerror(errno); return res; }

    if (pid == 0) {
        // child
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) _exit(126);
        raise(SIGSTOP);
        execv(argv[0].c_str(), cargv.data());
        // fallback: /system/bin/<base>
        std::string base = argv[0];
        size_t slash = base.find_last_of('/');
        if (slash != std::string::npos) base = base.substr(slash + 1);
        std::string alt = "/system/bin/" + base;
        execv(alt.c_str(), cargv.data());
        _exit(127);
    }

    g_childPid = pid;
    int status = 0;

    // wait for initial stop
    if (waitpid(pid, &status, 0) < 0) {
        res.error = "waitpid failed";
        g_childPid = 0;
        return res;
    }
    if (!WIFSTOPPED(status)) {
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        res.error = code == 126 ? "ptrace denied (SELinux/root required?)"
                                : code == 127 ? "exec failed: program not found"
                                              : "child exited immediately";
        g_childPid = 0;
        return res;
    }

    ptrace(PTRACE_SETOPTIONS, pid, nullptr,
           (void*)(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD));

    std::ostringstream out;
    bool inSyscall = false;
    long pendingNr = -1;
    u64 pendingIp = 0;
    std::string pendingRegs;
    int events = 0;
    bool entered = false;
    u64 args[6] = {0, 0, 0, 0, 0, 0};

    auto snapshot = [&](std::ostringstream& regsJson) -> bool {
#ifdef SAKO_ARCH_ARM64
        struct user_pt_regs regs{};
        struct iovec iov{ &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) return false;
        regsJson << "\"pc\":\"" << hexAddr(regs.pc) << "\",\"sp\":\"" << hexAddr(regs.sp) << "\"";
        for (int i = 0; i < 31; ++i)
            regsJson << ",\"x" << i << "\":\"" << hexAddr(u64(regs.regs[i])) << "\"";
        return true;
#elif defined(SAKO_ARCH_X86)
        struct user_regs_struct regs{};
        struct iovec iov{ &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) return false;
        regsJson << "\"rip\":\"" << hexAddr(u64(regs.rip)) << "\",\"rsp\":\"" << hexAddr(u64(regs.rsp)) << "\"";
        regsJson << ",\"rax\":\"" << hexAddr(u64(regs.rax)) << "\",\"rdi\":\"" << hexAddr(u64(regs.rdi)) << "\"";
        regsJson << ",\"rsi\":\"" << hexAddr(u64(regs.rsi)) << "\",\"rdx\":\"" << hexAddr(u64(regs.rdx)) << "\"";
        return true;
#else
        (void)regsJson;
        return false;
#endif
    };

    while (events < maxEvents && !stopFlag.load()) {
        if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) < 0) break;
        if (waitpid(pid, &status, 0) < 0) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }
        if (!WIFSTOPPED(status)) break;

        int sig = WSTOPSIG(status);
        if (sig != (SIGTRAP | 0x80)) {
            // deliver other signals to child
            ptrace(PTRACE_SYSCALL, pid, nullptr, (void*)(long)sig);
            continue;
        }

        std::ostringstream regsJson;
        bool haveRegs = snapshot(regsJson);

#ifdef SAKO_ARCH_ARM64
        struct user_pt_regs regs{};
        struct iovec iov{ &regs, sizeof(regs) };
        long nr = -1; u64 a[6] = {0}; u64 retv = 0; u64 ip = 0;
        if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) >= 0) {
            nr = long(regs.regs[8]);
            for (int i = 0; i < 6; ++i) a[i] = u64(regs.regs[i]);
            retv = u64(regs.regs[0]);
            ip = u64(regs.pc);
        }
#elif defined(SAKO_ARCH_X86)
        struct user_regs_struct regs{};
        struct iovec iov{ &regs, sizeof(regs) };
        long nr = -1; u64 a[6] = {0}; u64 retv = 0; u64 ip = 0;
        if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) >= 0) {
            nr = long(regs.orig_rax);
            a[0] = u64(regs.rdi); a[1] = u64(regs.rsi); a[2] = u64(regs.rdx);
            a[3] = u64(regs.r10); a[4] = u64(regs.r8);  a[5] = u64(regs.r9);
            retv = u64(regs.rax); ip = u64(regs.rip);
        }
#else
        long nr = -1; u64 a[6] = {0}; u64 retv = 0; u64 ip = 0;
#endif

        if (!inSyscall) {
            inSyscall = true;
            pendingNr = nr;
            pendingIp = ip;
            args[0] = a[0]; args[1] = a[1]; args[2] = a[2];
            args[3] = a[3]; args[4] = a[4]; args[5] = a[5];
            entered = true;
        } else {
            inSyscall = false;
            if (!entered) continue;
            // emit event
            std::ostringstream ev;
            ev << "{\"n\":" << events << ",\"nr\":" << pendingNr
               << ",\"syscall\":\"";
            const char* nm =
#if defined(SAKO_ARCH_ARM64)
                arm64SysName(pendingNr);
#elif defined(SAKO_ARCH_X86)
                x86SysName(pendingNr);
#else
                nullptr;
#endif
            if (nm) ev << nm; else ev << "sys_" << pendingNr;
            ev << "\",\"ip\":\"" << hexAddr(pendingIp) << "\",\"args\":[";
            for (int i = 0; i < 6; ++i) {
                if (i) ev << ",";
                ev << "\"" << hexAddr(args[i]) << "\"";
            }
            ev << "],\"ret\":\"" << hexAddr(retv) << "\"";
            if (haveRegs) ev << "," << regsJson.str();
            ev << "}";
            res.eventJson.push_back(ev.str());
            ++events;
        }
    }

    if (WIFSTOPPED(status) || kill(pid, 0) == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
    g_childPid = 0;

    if (res.eventJson.empty() && res.error.empty()) {
        res.error = stopFlag.load() ? "Stopped by user" : "No syscalls captured (trace ended)";
    }
    res.ok = !res.eventJson.empty();
    return res;
}

} // namespace sako
