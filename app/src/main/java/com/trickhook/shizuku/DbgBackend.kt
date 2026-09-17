package com.trickhook.shizuku

/**
 * Which process the ptrace session actually runs in.
 *
 * One debugger, three backends. The protocol is identical in all three — one
 * JSON command in, one JSON answer out — so nothing above this knows or cares
 * which one is live. What differs is the uid the tracer runs as, and that is
 * the whole story:
 *
 *  - [LOCAL] is the app's own process, uid 10xxx, SELinux domain
 *    untrusted_app. From Android 10 on, app_data_file carries no execute
 *    permission, so the only things it can spawn are /system/bin/* and files
 *    in its own nativeLibraryDir. A sample imported through the file picker
 *    lands in app storage and therefore cannot be run at all. This is exactly
 *    today's behaviour and it is not changed by anything in this package.
 *
 *  - [SHIZUKU_SHELL] is a Shizuku user service on the adb backend: uid 2000,
 *    domain shell. It may write to /data/local/tmp, chmod +x there, and
 *    fork / PTRACE_TRACEME / exec its own child — the gdbserver workflow. So a
 *    user's ARM64 sample becomes runnable on a stock unrooted phone. It may
 *    NOT PTRACE_ATTACH to a process it did not start: shell cannot ptrace an
 *    app domain without run-as, and run-as only covers debuggable packages.
 *
 *  - [SHIZUKU_ROOT] is the same user service when Shizuku was started by root,
 *    or when the backend is Sui: uid 0. Everything above, plus attach to any
 *    pid on the device.
 *
 * The ordinal order is deliberately "least privilege first", so a UI that walks
 * the entries reads as an escalation.
 */
enum class DbgBackend(
    /** Name for the chip and the status line. */
    val label: String,
    /** What this backend can do, in one line, for the capability strip. */
    val summary: String,
    /** The one thing it cannot do, or null when nothing is missing. */
    val limit: String?
) {
    LOCAL(
        label = "In-process",
        summary = "/system/bin and this app's own libraries. Breakpoints, registers, memory, stack.",
        limit = "An imported sample cannot be executed: app storage carries no execute permission. " +
            "Attach needs the target to be root-owned-by-you or a debuggable process."
    ),
    SHIZUKU_SHELL(
        label = "Shizuku shell",
        summary = "uid 2000. Stages the open sample into /data/local/tmp, makes it executable, " +
            "and traces it as its own child.",
        limit = "Attach to a running process is root-only. shell cannot ptrace an app or a system " +
            "process without run-as, and run-as only covers debuggable packages."
    ),
    SHIZUKU_ROOT(
        label = "Shizuku root",
        summary = "uid 0. Stages and runs any sample, and attaches to any pid on the device.",
        limit = null
    );

    /** True for the two backends that talk to a Shizuku user service. */
    val privileged: Boolean get() = this != LOCAL

    /**
     * Whether the Attach control is offered at all.
     *
     * False on [SHIZUKU_SHELL] on purpose: PTRACE_ATTACH to a foreign pid is
     * refused by the kernel and by SELinux there, and an action that is always
     * going to fail should be visibly unavailable rather than fail when it is
     * pressed. [LOCAL] keeps it, because that is what it has always done and a
     * rooted or debuggable device still uses it.
     */
    val offersAttach: Boolean get() = this != SHIZUKU_SHELL

    /**
     * Whether a file from app storage can be copied somewhere executable and
     * run. This is the capability the whole feature exists for.
     */
    val canStage: Boolean get() = privileged

    companion object {
        /** The backend for a live Shizuku service, given the uid it runs as. */
        fun forUid(uid: Int): DbgBackend = if (uid == 0) SHIZUKU_ROOT else SHIZUKU_SHELL
    }
}
