// Interactive debugger session implementation (single worker-thread design).
#include "DebugSession.h"
#include <cerrno>
#include <csignal>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <dirent.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/elf.h>

#if defined(__aarch64__)
#include <asm/ptrace.h>
#define SAKO_D_ARCH_ARM64 1
#elif defined(__x86_64__)
#include <sys/user.h>
#define SAKO_D_ARCH_X86 1
#endif

namespace sako {

DebugSession& DebugSession::instance() {
    static DebugSession s;
    return s;
}

DebugSession::~DebugSession() { cleanup(); }

// ------------------------------------------------------------ MiniJson --
MiniJson MiniJson::parse(const std::string& s) {
    MiniJson out;
    size_t i = 0;
    auto skipWs = [&]() { while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t' || s[i] == '\r')) ++i; };
    skipWs();
    if (i >= s.size() || s[i] != '{') return out;
    ++i;
    while (i < s.size()) {
        skipWs();
        if (s[i] == '}') break;
        if (s[i] != '"') break;
        size_t k0 = ++i;
        while (i < s.size() && s[i] != '"') ++i;
        std::string key = s.substr(k0, i - k0);
        ++i;
        skipWs();
        if (i >= s.size() || s[i] != ':') break;
        ++i;
        skipWs();
        std::string val;
        if (i < s.size() && s[i] == '"') {
            size_t v0 = ++i;
            std::string unesc;
            while (i < s.size() && s[i] != '"') {
                if (s[i] == '\\' && i + 1 < s.size()) {
                    ++i;
                    char c = s[i];
                    switch (c) {
                        case 'n': unesc += '\n'; break;
                        case 't': unesc += '\t'; break;
                        case 'r': unesc += '\r'; break;
                        case '"': unesc += '"'; break;
                        case '\\': unesc += '\\'; break;
                        default: unesc += c;
                    }
                } else unesc += s[i];
                ++i;
            }
            ++i;
            val = unesc;
        } else {
            size_t v0 = i;
            while (i < s.size() && s[i] != ',' && s[i] != '}') ++i;
            val = s.substr(v0, i - v0);
            while (!val.empty() && val.back() == ' ') val.pop_back();
        }
        out.kv[key] = val;
        skipWs();
        if (i < s.size() && s[i] == ',') ++i;
    }
    return out;
}

std::string MiniJson::str(const std::string& k, const std::string& dflt) const {
    auto it = kv.find(k);
    return it == kv.end() ? dflt : it->second;
}

u64 MiniJson::num(const std::string& k, u64 dflt) const {
    auto it = kv.find(k);
    if (it == kv.end()) return dflt;
    const std::string& v = it->second;
    if (v.rfind("0x", 0) == 0 || v.rfind("0X", 0) == 0)
        return strtoull(v.c_str() + 2, nullptr, 16);
    return strtoull(v.c_str(), nullptr, 0);
}

// ------------------------------------------------------------ mem I/O --
bool DebugSession::readMemProc(pid_t pid, u64 addr, void* buf, size_t len) {
    struct iovec local{ buf, len };
    struct iovec remote{ (void*)(uintptr_t)addr, len };
    ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (r == ssize_t(len)) return true;
    u8* dst = (u8*)buf;
    size_t done = 0;
    errno = 0;
    while (done < len) {
        u64 aligned = (addr + done) & ~u64(sizeof(long) - 1);
        long word = ptrace(PTRACE_PEEKDATA, pid, (void*)(uintptr_t)aligned, nullptr);
        if (word == -1 && errno != 0) return false;
        u8* wp = (u8*)&word;
        size_t inOff = (addr + done) - aligned;
        size_t take = std::min(sizeof(long) - inOff, len - done);
        memcpy(dst + done, wp + inOff, take);
        done += take;
    }
    return true;
}

bool DebugSession::writeMemProc(pid_t pid, u64 addr, const void* buf, size_t len) {
    const u8* src = (const u8*)buf;
    size_t done = 0;
    while (done < len) {
        u64 a = addr + done;
        size_t chunk = std::min(sizeof(long) - (a % sizeof(long)), len - done);
        long word = 0;
        if (chunk < sizeof(long)) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, (void*)(uintptr_t)(a & ~u64(sizeof(long) - 1)), nullptr);
            if (word == -1 && errno != 0) return false;
        }
        memcpy((u8*)&word + (a % sizeof(long)), src + done, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, (void*)(uintptr_t)(a & ~u64(sizeof(long) - 1)), (void*)word) < 0)
            return false;
        done += chunk;
    }
    return true;
}

bool DebugSession::readMemRaw(u64 addr, void* buf, size_t len) {
    return readMemProc(pid_, addr, buf, len);
}

bool DebugSession::writeMemRaw(u64 addr, const void* buf, size_t len) {
    return writeMemProc(pid_, addr, buf, len);
}

// ------------------------------------------------------------ bp patch --
bool DebugSession::installBp(Bp& bp) {
    if (bp.installed || !pid_) return false;
#if defined(SAKO_D_ARCH_ARM64)
    u32 brk = 0xD4200020;   // brk #0x20
    u64 word = 0;
    if (!readMemRaw(bp.addr, &word, sizeof(word))) return false;
    bp.origWord = word;
    u64 patched = (word & ~u64(0xFFFFFFFF)) | u64(brk);
    if (!writeMemRaw(bp.addr, &patched, sizeof(patched))) return false;
    bp.installed = true;
    return true;
#elif defined(SAKO_D_ARCH_X86)
    long word = 0;
    if (!readMemRaw(bp.addr, &word, sizeof(word))) return false;
    memcpy(&bp.origWord, &word, sizeof(u64));
    long patched = (word & ~0xFFL) | 0xCC;
    if (!writeMemRaw(bp.addr, &patched, sizeof(patched))) return false;
    bp.installed = true;
    return true;
#else
    return false;
#endif
}

bool DebugSession::removeBp(Bp& bp) {
    if (!bp.installed) return true;
    if (!writeMemRaw(bp.addr, &bp.origWord, sizeof(bp.origWord))) return false;
    bp.installed = false;
    return true;
}

// ------------------------------------------------------------ registers --
std::string DebugSession::regsJsonLocked(pid_t tid) {
    pid_t t = tid ? tid : pid_;
    std::ostringstream o;
    o << "{\"ok\":true";
#if defined(SAKO_D_ARCH_ARM64)
    struct user_pt_regs regs{};
    struct iovec iov{ &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, t, (void*)NT_PRSTATUS, &iov) < 0) {
        return "{\"ok\":false,\"error\":\"GETREGSET failed: " + std::string(strerror(errno)) + "\"}";
    }
    o << ",\"arch\":\"arm64\",\"pc\":\"" << hexAddr(regs.pc) << "\",\"sp\":\"" << hexAddr(regs.sp) << "\"";
    for (int i = 0; i < 31; ++i)
        o << ",\"x" << i << "\":\"" << hexAddr(u64(regs.regs[i])) << "\"";
    o << ",\"pstate\":\"" << hexAddr(u64(regs.pstate)) << "\"";
    archName_ = "arm64";
#elif defined(SAKO_D_ARCH_X86)
    struct user_regs_struct regs{};
    struct iovec iov{ &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, t, (void*)NT_PRSTATUS, &iov) < 0) {
        return "{\"ok\":false,\"error\":\"GETREGSET failed: " + std::string(strerror(errno)) + "\"}";
    }
    o << ",\"arch\":\"x86_64\",\"pc\":\"" << hexAddr(u64(regs.rip)) << "\",\"sp\":\"" << hexAddr(u64(regs.rsp)) << "\"";
    o << ",\"rax\":\"" << hexAddr(u64(regs.rax)) << "\",\"rbx\":\"" << hexAddr(u64(regs.rbx)) << "\"";
    o << ",\"rcx\":\"" << hexAddr(u64(regs.rcx)) << "\",\"rdx\":\"" << hexAddr(u64(regs.rdx)) << "\"";
    o << ",\"rsi\":\"" << hexAddr(u64(regs.rsi)) << "\",\"rdi\":\"" << hexAddr(u64(regs.rdi)) << "\"";
    o << ",\"rbp\":\"" << hexAddr(u64(regs.rbp)) << "\",\"r8\":\"" << hexAddr(u64(regs.r8)) << "\"";
    o << ",\"r9\":\"" << hexAddr(u64(regs.r9)) << "\",\"r10\":\"" << hexAddr(u64(regs.r10)) << "\"";
    o << ",\"r11\":\"" << hexAddr(u64(regs.r11)) << "\",\"r12\":\"" << hexAddr(u64(regs.r12)) << "\"";
    o << ",\"r13\":\"" << hexAddr(u64(regs.r13)) << "\",\"r14\":\"" << hexAddr(u64(regs.r14)) << "\"";
    o << ",\"r15\":\"" << hexAddr(u64(regs.r15)) << "\",\"eflags\":\"" << hexAddr(u64(regs.eflags)) << "\"";
    o << ",\"orig_rax\":\"" << hexAddr(u64(regs.orig_rax)) << "\",\"cs\":\"" << hexAddr(u64(regs.cs)) << "\"";
    archName_ = "x86_64";
#else
    return "{\"ok\":false,\"error\":\"unsupported host arch\"}";
#endif
    o << "}";
    return o.str();
}

// set PC helper (x86 breakpoint rewind)
static void dbgSetPc(pid_t pid, u64 pc) {
#if defined(SAKO_D_ARCH_ARM64)
    struct user_pt_regs regs{};
    struct iovec iov{ &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) return;
    regs.pc = pc;
    ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
#elif defined(SAKO_D_ARCH_X86)
    struct user_regs_struct regs{};
    struct iovec iov{ &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) return;
    regs.rip = pc;
    ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
#endif
}

// ------------------------------------------------------------ events --
void DebugSession::pushEvent(const std::string& ev) {
    std::lock_guard<std::mutex> lk(mu_);
    events_.push_back(ev);
    if (events_.size() > 2000) events_.erase(events_.begin(), events_.begin() + 500);
}

// worker thread: identify a SIGTRAP/signal stop
void DebugSession::classifyStop(int sig) {
    std::string rj = regsJsonLocked();
    u64 pc = 0;
    {
        size_t p = rj.find("\"pc\":\"0x");
        if (p != std::string::npos) pc = strtoull(rj.c_str() + p + 6, nullptr, 16);
    }

    if (sig == SIGTRAP) {
        u64 bpAddr = pc;
#if defined(SAKO_D_ARCH_ARM64)
        // pc points AT the brk instruction
#else
        if (bpAddr) bpAddr -= 1;   // x86: pc is after the 0xCC
#endif
        Bp* hit = nullptr;
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = bps_.find(bpAddr);
            if (it != bps_.end()) hit = &it->second;
            if (hit) {
                hit->hits++;
                removeBp(*hit);
            }
        }
        if (hit) {
#if !defined(SAKO_D_ARCH_ARM64)
            dbgSetPc(pid_, bpAddr);   // rewind pc onto the breakpoint
#endif
            std::ostringstream ev;
            ev << "{\"type\":\"breakpoint\",\"addr\":\"" << hexAddr(bpAddr)
               << "\",\"pc\":\"" << hexAddr(pc) << "\",\"hits\":" << hit->hits << "}";
            pushEvent(ev.str());
            std::lock_guard<std::mutex> lk(mu_);
            state_ = ST_STOPPED;
            lastStopRegs_ = rj;
            return;
        }
        // exec completion or other trap
        std::ostringstream ev;
        ev << "{\"type\":\"stopped\",\"sig\":" << sig << ",\"pc\":\"" << hexAddr(pc) << "\"}";
        pushEvent(ev.str());
        {
            std::lock_guard<std::mutex> lk(mu_);
            state_ = ST_STOPPED;
            lastStopRegs_ = rj;
            // (re)install pending breakpoints now that we're stopped
            for (auto& kv : bps_) installBp(kv.second);
        }
        return;
    }

    // other signals: report and deliver
    {
        std::ostringstream ev;
        ev << "{\"type\":\"signal\",\"sig\":" << sig << "}";
        pushEvent(ev.str());
    }
    ptrace(PTRACE_CONT, pid_, nullptr, (void*)(long)sig);
}

// ------------------------------------------------------------ monitor --
void DebugSession::monitorLoop() {
    while (monitorRun_.load()) {
        int status = 0;
        pid_t r = waitpid(pid_, &status, WNOHANG);
        if (r == 0) { usleep(15000); continue; }
        if (r < 0) break;

        if (WIFEXITED(status)) {
            std::ostringstream ev;
            ev << "{\"type\":\"exit\",\"code\":" << WEXITSTATUS(status) << "}";
            pushEvent(ev.str());
            std::lock_guard<std::mutex> lk(mu_);
            state_ = ST_EXITED;
            break;
        }
        if (WIFSIGNALED(status)) {
            std::ostringstream ev;
            ev << "{\"type\":\"killed\",\"sig\":" << WTERMSIG(status) << "}";
            pushEvent(ev.str());
            std::lock_guard<std::mutex> lk(mu_);
            state_ = ST_EXITED;
            break;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        // classification requires ptrace -> must run on the worker thread
        postJob("__classify:" + std::to_string(sig), true);
    }
    monitorRun_ = false;
}

// ------------------------------------------------------------ worker --
void DebugSession::startWorker() {
    if (workerRun_.load()) return;
    workerRun_ = true;
    worker_ = std::thread(&DebugSession::workerLoop, this);
}

void DebugSession::postJob(const std::string& json, bool fireAndForget) {
    Job j;
    j.json = json;
    j.internal_ = fireAndForget;
    auto pr = std::make_shared<std::promise<std::string>>();
    j.pr = pr;
    {
        std::lock_guard<std::mutex> lk(jqMu_);
        jobs_.push(std::move(j));
    }
    jqCv_.notify_one();
}

void DebugSession::workerLoop() {
    while (workerRun_.load()) {
        Job job;
        {
            std::unique_lock<std::mutex> lk(jqMu_);
            jqCv_.wait_for(lk, std::chrono::milliseconds(100), [this] { return !jobs_.empty(); });
            if (jobs_.empty()) continue;
            job = std::move(jobs_.front());
            jobs_.pop();
        }
        std::string out;
        if (job.json.rfind("__classify:", 0) == 0) {
            int sig = atoi(job.json.c_str() + 11);
            classifyStop(sig);
            continue;
        }
        out = handleCmd(job.json);
        if (job.pr && !job.internal_) job.pr->set_value(out);
    }
}

std::string DebugSession::cmd(const std::string& json) {
    startWorker();
    auto pr = std::make_shared<std::promise<std::string>>();
    auto fut = pr->get_future();
    {
        std::lock_guard<std::mutex> lk(jqMu_);
        Job j;
        j.json = json;
        j.pr = pr;
        jobs_.push(std::move(j));
    }
    jqCv_.notify_one();
    return fut.get();
}

bool DebugSession::active() const {
    return workerRun_.load();
}

void DebugSession::cleanup() {
    monitorRun_ = false;
    if (monitor_.joinable()) monitor_.join();
    {
        std::lock_guard<std::mutex> lk(mu_);
        pid_t p = pid_;
        if (p > 0) {
            kill(p, SIGKILL);
            int status;
            waitpid(p, &status, 0);
        }
        pid_ = 0;
        state_ = ST_NONE;
        bps_.clear();
        events_.clear();
    }
}

// ------------------------------------------------------------ dispatch --
std::string DebugSession::handleCmd(const std::string& json) {
    // internal classify marker never reaches here
    MiniJson j = MiniJson::parse(json);
    std::string op = j.str("op");
    std::ostringstream o;

    if (op == "status") {
        const char* st;
        {
            std::lock_guard<std::mutex> lk(mu_);
            st = state_ == ST_NONE ? "none" : state_ == ST_STOPPED ? "stopped" :
                 state_ == ST_RUNNING ? "running" : "exited";
        }
        o << "{\"ok\":true,\"state\":\"" << st << "\",\"pid\":" << pid_ << "}";
        return o.str();
    }

    if (op == "spawn") {
        cleanup();
        std::string prog = j.str("prog");
        std::string argsStr = j.str("args");
        if (prog.empty()) return "{\"ok\":false,\"error\":\"no program\"}";
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(prog.c_str()));
        size_t start = 0;
        while (start < argsStr.size()) {
            size_t nl = argsStr.find('\n', start);
            std::string tok = nl == std::string::npos ? argsStr.substr(start)
                                                      : argsStr.substr(start, nl - start);
            if (!tok.empty()) argv.push_back(strdup(tok.c_str()));
            if (nl == std::string::npos) break;
            start = nl + 1;
        }
        argv.push_back(nullptr);

        pid_t pid = fork();
        if (pid < 0) return std::string("{\"ok\":false,\"error\":\"fork failed: ") + strerror(errno) + "\"}";
        if (pid == 0) {
            ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            raise(SIGSTOP);
            execv(prog.c_str(), argv.data());
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, nullptr, (void*)(long)PTRACE_O_EXITKILL);
        {
            std::lock_guard<std::mutex> lk(mu_);
            pid_ = pid;
            mode_ = "spawn";
            state_ = ST_STOPPED;
            bps_.clear();
            events_.clear();
        }
        // monitor thread: waitpid loop only
        monitorRun_ = true;
        monitor_ = std::thread(&DebugSession::monitorLoop, this);
        o << "{\"ok\":true,\"pid\":" << pid << ",\"state\":\"stopped\"}";
        return o.str();
    }

    if (op == "attach") {
        cleanup();
        pid_t pid = (pid_t)j.num("pid");
        if (pid <= 0) return "{\"ok\":false,\"error\":\"invalid pid\"}";
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
            return std::string("{\"ok\":false,\"error\":\"attach failed: ") + strerror(errno) + "\"}";
        int status = 0;
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, nullptr, (void*)(long)PTRACE_O_EXITKILL);
        {
            std::lock_guard<std::mutex> lk(mu_);
            pid_ = pid;
            mode_ = "attach";
            state_ = ST_STOPPED;
            bps_.clear();
            events_.clear();
        }
        monitorRun_ = true;
        monitor_ = std::thread(&DebugSession::monitorLoop, this);
        o << "{\"ok\":true,\"pid\":" << pid << ",\"state\":\"stopped\"}";
        return o.str();
    }

    if (op == "detach") {
        if (pid_ > 0) {
            for (auto& kv : bps_) removeBp(kv.second);
            ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        }
        monitorRun_ = false;
        if (monitor_.joinable()) monitor_.detach();
        {
            std::lock_guard<std::mutex> lk(mu_);
            pid_ = 0;
            state_ = ST_NONE;
            bps_.clear();
        }
        return "{\"ok\":true}";
    }

    if (op == "kill") {
        if (pid_ > 0) kill(pid_, SIGKILL);
        monitorRun_ = false;
        if (monitor_.joinable()) monitor_.join();
        {
            std::lock_guard<std::mutex> lk(mu_);
            pid_ = 0;
            state_ = ST_NONE;
            bps_.clear();
        }
        return "{\"ok\":true}";
    }

    if (pid_ == 0 && op != "poll") return "{\"ok\":false,\"error\":\"no active session\"}";

    if (op == "bp_add") {
        u64 addr = j.num("addr");
        if (!addr) return "{\"ok\":false,\"error\":\"addr required\"}";
        std::lock_guard<std::mutex> lk(mu_);
        if (bps_.count(addr)) return "{\"ok\":true,\"note\":\"exists\"}";
        Bp bp;
        bp.addr = addr;
        if (state_ == ST_STOPPED) installBp(bp);
        bps_[addr] = bp;
        o << "{\"ok\":true,\"addr\":\"" << hexAddr(addr)
          << "\",\"installed\":" << (bp.installed ? "true" : "false") << "}";
        return o.str();
    }
    if (op == "bp_del") {
        u64 addr = j.num("addr");
        std::lock_guard<std::mutex> lk(mu_);
        auto it = bps_.find(addr);
        if (it == bps_.end()) return "{\"ok\":false,\"error\":\"not found\"}";
        removeBp(it->second);
        bps_.erase(it);
        return "{\"ok\":true}";
    }
    if (op == "bp_list") {
        std::lock_guard<std::mutex> lk(mu_);
        o << "{\"ok\":true,\"bps\":[";
        bool first = true;
        for (auto& kv : bps_) {
            if (!first) o << ",";
            first = false;
            o << "{\"addr\":\"" << hexAddr(kv.first) << "\",\"hits\":" << kv.second.hits
              << ",\"enabled\":" << (kv.second.enabled ? "true" : "false") << "}";
        }
        o << "]}";
        return o.str();
    }
    if (op == "cont") {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (state_ == ST_RUNNING) return "{\"ok\":false,\"error\":\"already running\"}";
        }
        // gdb-style continue: if pc sits on a breakpoint, step over it first
        {
            std::string rj = regsJsonLocked();
            size_t p = rj.find("\"pc\":\"0x");
            u64 pc = p != std::string::npos ? strtoull(rj.c_str() + p + 6, nullptr, 16) : 0;
            bool onBp = false;
            {
                std::lock_guard<std::mutex> lk(mu_);
                onBp = pc && bps_.count(pc) != 0;
            }
            if (onBp) {
                ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
                int st = 0;
                waitpid(pid_, &st, 0);
            }
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            for (auto& kv : bps_) installBp(kv.second);
            state_ = ST_RUNNING;
        }
        if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0) {
            std::lock_guard<std::mutex> lk(mu_);
            state_ = ST_STOPPED;
            return std::string("{\"ok\":false,\"error\":\"cont failed: ") + strerror(errno) + "\"}";
        }
        return "{\"ok\":true,\"state\":\"running\"}";
    }
    if (op == "step") {
        if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) < 0)
            return std::string("{\"ok\":false,\"error\":\"step failed: ") + strerror(errno) + "\"}";
        int status = 0;
        waitpid(pid_, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            std::lock_guard<std::mutex> lk(mu_);
            state_ = ST_EXITED;
            return "{\"ok\":false,\"error\":\"exited during step\"}";
        }
        std::string rj = regsJsonLocked();
        {
            std::lock_guard<std::mutex> lk(mu_);
            state_ = ST_STOPPED;
            lastStopRegs_ = rj;
        }
        return "{\"ok\":true,\"state\":\"stopped\"}";
    }
    if (op == "regs") {
        return regsJsonLocked((pid_t)j.num("tid"));
    }
    if (op == "setreg") {
        std::string name = j.str("reg");
        u64 val = j.num("value");
#if defined(SAKO_D_ARCH_ARM64)
        struct user_pt_regs regs{};
        struct iovec iov{ &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid_, (void*)NT_PRSTATUS, &iov) < 0)
            return "{\"ok\":false,\"error\":\"getregset failed\"}";
        bool applied = false;
        if (name == "pc") { regs.pc = val; applied = true; }
        else if (name == "sp") { regs.sp = val; applied = true; }
        else if (name.rfind("x", 0) == 0) {
            int n = atoi(name.c_str() + 1);
            if (n >= 0 && n < 31) { regs.regs[n] = val; applied = true; }
        }
        if (!applied) return "{\"ok\":false,\"error\":\"unknown reg\"}";
        if (ptrace(PTRACE_SETREGSET, pid_, (void*)NT_PRSTATUS, &iov) < 0)
            return "{\"ok\":false,\"error\":\"setregset failed\"}";
        return "{\"ok\":true}";
#elif defined(SAKO_D_ARCH_X86)
        struct user_regs_struct regs{};
        struct iovec iov{ &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid_, (void*)NT_PRSTATUS, &iov) < 0)
            return "{\"ok\":false,\"error\":\"getregset failed\"}";
        u64* slots[] = { (u64*)&regs.rax, (u64*)&regs.rbx, (u64*)&regs.rcx, (u64*)&regs.rdx,
                         (u64*)&regs.rsi, (u64*)&regs.rdi, (u64*)&regs.rbp, (u64*)&regs.rsp,
                         (u64*)&regs.r8, (u64*)&regs.r9, (u64*)&regs.r10, (u64*)&regs.r11,
                         (u64*)&regs.r12, (u64*)&regs.r13, (u64*)&regs.r14, (u64*)&regs.r15,
                         (u64*)&regs.rip };
        const char* names[] = { "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                                "r8","r9","r10","r11","r12","r13","r14","r15","pc" };
        for (size_t i = 0; i < sizeof(slots)/sizeof(slots[0]); ++i) {
            if (name == names[i]) {
                *slots[i] = val;
                if (ptrace(PTRACE_SETREGSET, pid_, (void*)NT_PRSTATUS, &iov) < 0)
                    return "{\"ok\":false,\"error\":\"setregset failed\"}";
                return "{\"ok\":true}";
            }
        }
        return "{\"ok\":false,\"error\":\"unknown reg\"}";
#else
        return "{\"ok\":false,\"error\":\"unsupported arch\"}";
#endif
    }
    if (op == "read") {
        u64 addr = j.num("addr");
        u64 len = j.num("len", 64);
        if (len > 4096) len = 4096;
        std::vector<u8> buf(size_t(len), 0);
        bool okd = readMemRaw(addr, buf.data(), size_t(len));
        o << "{\"ok\":" << (okd ? "true" : "false") << ",\"addr\":\"" << hexAddr(addr)
          << "\",\"len\":" << len << ",\"data\":\"";
        char hexs[3];
        for (u64 i = 0; i < len; ++i) {
            snprintf(hexs, sizeof hexs, "%02x", buf[size_t(i)]);
            o << hexs;
        }
        o << "\"}";
        return o.str();
    }
    if (op == "write") {
        u64 addr = j.num("addr");
        std::string hexData = j.str("data");
        if (hexData.size() % 2) return "{\"ok\":false,\"error\":\"odd hex length\"}";
        std::vector<u8> buf(hexData.size() / 2);
        for (size_t i = 0; i < buf.size(); ++i)
            buf[i] = u8(strtoul(hexData.substr(i * 2, 2).c_str(), nullptr, 16));
        bool okd = writeMemRaw(addr, buf.data(), buf.size());
        o << "{\"ok\":" << (okd ? "true" : "false") << ",\"written\":" << buf.size() << "}";
        return o.str();
    }
    if (op == "stack") {
        std::string rj = regsJsonLocked();
        size_t p = rj.find("\"sp\":\"0x");
        u64 sp = p != std::string::npos ? strtoull(rj.c_str() + p + 6, nullptr, 16) : 0;
        if (!sp) return "{\"ok\":false,\"error\":\"no sp\"}";
        u64 len = j.num("len", 128);
        if (len > 1024) len = 1024;
        std::vector<u8> buf(size_t(len), 0);
        bool okd = readMemRaw(sp, buf.data(), size_t(len));
        o << "{\"ok\":" << (okd ? "true" : "false") << ",\"sp\":\"" << hexAddr(sp)
          << "\",\"len\":" << len << ",\"data\":\"";
        char hexs[3];
        for (u64 i = 0; i < len; ++i) {
            snprintf(hexs, sizeof hexs, "%02x", buf[size_t(i)]);
            o << hexs;
        }
        o << "\"}";
        return o.str();
    }
    if (op == "threads") {
        std::string dirPath = "/proc/" + std::to_string(pid_) + "/task";
        DIR* d = opendir(dirPath.c_str());
        o << "{\"ok\":true,\"threads\":[";
        bool first = true;
        if (d) {
            struct dirent* e;
            while ((e = readdir(d)) != nullptr) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                pid_t tid = (pid_t)atoi(e->d_name);
                if (!first) o << ",";
                first = false;
                o << "{\"tid\":" << tid;
                std::string commPath = dirPath + "/" + e->d_name + "/comm";
                FILE* f = fopen(commPath.c_str(), "r");
                if (f) {
                    char name[64] = {0};
                    if (fgets(name, sizeof name, f)) {
                        std::string nm(name);
                        while (!nm.empty() && (nm.back() == '\n' || nm.back() == '\r')) nm.pop_back();
                        o << ",\"name\":\"" << jsonEscape(nm) << "\"";
                    }
                    fclose(f);
                }
                o << "}";
            }
            closedir(d);
        }
        o << "]}";
        return o.str();
    }
    if (op == "poll") {
        std::lock_guard<std::mutex> lk(mu_);
        o << "{\"ok\":true,\"state\":\""
          << (state_ == ST_NONE ? "none" : state_ == ST_STOPPED ? "stopped" :
              state_ == ST_RUNNING ? "running" : "exited")
          << "\",\"pid\":" << pid_ << ",\"events\":[";
        for (size_t i = 0; i < events_.size(); ++i) {
            if (i) o << ",";
            o << events_[i];
        }
        o << "]}";
        events_.clear();
        return o.str();
    }

    return "{\"ok\":false,\"error\":\"unknown op: " + jsonEscape(op) + "\"}";
}

} // namespace sako
