// Interactive ptrace debugger session.
//
// ARCHITECTURE NOTE (Linux ptrace constraint):
// PTRACE_ATTACH/TRACEME records the *calling thread* as the tracer, and only
// that thread may issue ptrace() calls for the tracee. Because commands can
// arrive from arbitrary Kotlin coroutine threads, ALL ptrace work is routed
// through one dedicated worker thread. A monitor thread only does waitpid()
// and posts "classify stop" jobs back to the worker.
#pragma once
#include "Types.h"
#include <atomic>
#include <condition_variable>
#include <future>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>
#include <map>

namespace sako {

class DebugSession {
public:
    static DebugSession& instance();

    // One JSON command in -> one JSON response out.
    // ops: spawn, attach, detach, kill, cont, step, bp_add, bp_del, bp_list,
    //      regs, setreg, read, write, stack, threads, status, poll
    std::string cmd(const std::string& json);

    bool active() const;

private:
    DebugSession() = default;
    ~DebugSession();

    enum State { ST_NONE, ST_STOPPED, ST_RUNNING, ST_EXITED };

    struct Bp {
        u64 addr = 0;
        u64 origWord = 0;
        bool enabled = true;
        bool installed = false;
        int hits = 0;
    };

    // worker-thread job plumbing
    struct Job {
        std::string json;
        std::shared_ptr<std::promise<std::string>> pr;
        bool internal_ = false;   // monitor-originated, no future wait
    };
    void startWorker();
    void workerLoop();
    std::string handleCmd(const std::string& json);
    void postJob(const std::string& json, bool fireAndForget);

    // ptrace helpers (worker thread only)
    bool installBp(Bp& bp);
    bool removeBp(Bp& bp);
    bool readMemRaw(u64 addr, void* buf, size_t len);
    bool writeMemRaw(u64 addr, const void* buf, size_t len);
    static bool readMemProc(pid_t pid, u64 addr, void* buf, size_t len);
    static bool writeMemProc(pid_t pid, u64 addr, const void* buf, size_t len);
    std::string regsJsonLocked(pid_t tid = 0);
    void classifyStop(int status);   // worker: identify exec/bp/signal stops

    // monitor thread (waitpid only)
    void monitorLoop();

    void cleanup();
    void pushEvent(const std::string& ev);

    std::mutex mu_;                  // guards state_, bps_, events_, pid_
    State state_ = ST_NONE;
    pid_t pid_ = 0;
    std::string mode_;
    std::map<u64, Bp> bps_;
    std::vector<std::string> events_;
    // Events the ring dropped since the last poll drained it. A debugger that
    // quietly eats 500 stops shows one that never happened next to one it ate,
    // so the count goes out with the window that replaced them.
    size_t eventsDropped_ = 0;
    std::string lastStopRegs_;

    // worker
    std::thread worker_;
    std::atomic<bool> workerRun_{false};
    std::mutex jqMu_;
    std::condition_variable jqCv_;
    std::queue<Job> jobs_;

    // monitor
    std::thread monitor_;
    std::atomic<bool> monitorRun_{false};

    std::string archName_ = "-";
};

// Minimal JSON value parse (flat objects: strings/numbers/bools).
struct MiniJson {
    std::map<std::string, std::string> kv;
    static MiniJson parse(const std::string& s);
    std::string str(const std::string& k, const std::string& dflt = "") const;
    u64 num(const std::string& k, u64 dflt = 0) const;
    bool has(const std::string& k) const { return kv.count(k) != 0; }
};

} // namespace sako
