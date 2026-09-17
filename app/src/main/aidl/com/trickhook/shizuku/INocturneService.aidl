package com.trickhook.shizuku;

/**
 * The privileged half of the debugger, as seen from the app.
 *
 * There is deliberately no second protocol here. The whole ptrace debugger is
 * already one JSON-string-in / JSON-string-out call --
 * Java_com_trickhook_engine_NativeBridge_nativeDbgCmd -- so the service is that
 * same call, forwarded across a Binder into a process running as uid 2000
 * (shell) or uid 0 (root). Every op the in-process debugger understands
 * (spawn, attach, cont, step, bp_add, regs, read, stack, threads, poll, ...)
 * works here verbatim, and a new engine op needs no change on this side.
 *
 * Ops whose name starts with "svc." are the service's own and never reach the
 * engine: svc.hello, svc.stageBegin, svc.stageEnd, svc.unstage, svc.sweep.
 *
 * Transaction ids are explicit because AIDL requires all-or-nothing, and
 * destroy() must land on 16777115 -- Shizuku's server calls that code directly
 * when it tears a user service down. AIDL adds FIRST_CALL_TRANSACTION, so the
 * number written here is one less. See Shizuku-API's
 * ShizukuApiConstants.USER_SERVICE_TRANSACTION_destroy.
 */
interface INocturneService {

    /**
     * Called by the Shizuku/Sui server when the user service is removed. The
     * process is NOT killed for us: this is where staged files are deleted and
     * System.exit is called.
     */
    void destroy() = 16777114;

    /** One command in, one JSON answer out. Never throws across the Binder. */
    String dbgCmd(String json) = 1;

    /**
     * One chunk of a file being staged into /data/local/tmp.
     *
     * A shell-uid process cannot read /data/user/0/com.trickhook -- Shizuku's
     * own README says so -- so the bytes cannot be handed over as a path. They
     * come across the Binder instead, in pieces small enough for the 1 MiB
     * transaction buffer. [json] carries the token from svc.stageBegin.
     */
    String stageChunk(String json, in byte[] chunk) = 2;
}
