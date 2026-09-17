package com.trickhook.shizuku

/**
 * Which process the ptrace session actually runs in.
 *
 * One debugger, four backends. The protocol is identical in all four — one
 * JSON command in, one JSON answer out — so nothing above this knows or cares
 * which one is live. What differs is the uid the tracer runs as and the
 * transport that carries the JSON to it, and that is the whole story:
 *
 *  - [LOCAL] is the app's own process, uid 10xxx, SELinux domain
 *    untrusted_app. From Android 10 on, app_data_file carries no execute
 *    permission, so the only things it can spawn are those under /system/bin and files
 *    in its own nativeLibraryDir. A sample imported through the file picker
 *    lands in app storage and therefore cannot be run at all. This is exactly
 *    today's behaviour and it is not changed by anything in this package.
 *    Transport: an in-process JNI call.
 *
 *  - [SHIZUKU_SHELL] is a Shizuku user service on the adb backend: uid 2000,
 *    domain shell. It may write to /data/local/tmp, chmod +x there, and
 *    fork / PTRACE_TRACEME / exec its own child — the gdbserver workflow. So a
 *    user's ARM64 sample becomes runnable on a stock unrooted phone. It may
 *    NOT PTRACE_ATTACH to a process it did not start: shell cannot ptrace an
 *    app domain without run-as, and run-as only covers debuggable packages.
 *    Transport: a Binder into the Shizuku user service.
 *
 *  - [SHIZUKU_ROOT] is the same user service when Shizuku was started by root,
 *    or when the backend is Sui: uid 0. Everything above, plus attach to any
 *    pid on the device. Transport: the same Binder.
 *
 *  - [ROOT] is uid 0 reached through `su` directly, with no Shizuku at all —
 *    for the many devices that have Magisk su but run Shizuku over adb, or run
 *    no Shizuku. The app launches a private debugger daemon with `su` and talks
 *    to it over that process's stdin/stdout. Same engine, same protocol; the
 *    transport is a pipe instead of a Binder. Everything [SHIZUKU_ROOT] can do.
 *    It is an ADDITIONAL path to uid 0, not a replacement — [SHIZUKU_ROOT]
 *    stays for the devices where Shizuku already runs as root.
 *
 * The ordinal order is deliberately "least privilege first", so a UI that walks
 * the entries reads as an escalation. [ROOT] sits last: it is uid 0 like
 * [SHIZUKU_ROOT], reached by the most direct route.
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
    ),
    ROOT(
        label = "Root (su)",
        summary = "uid 0 through su, no Shizuku. Launches a private debugger daemon that stages " +
            "and runs any sample, and attaches to any pid on the device.",
        limit = null
    );

    /**
     * True for every backend whose tracer runs as a more-privileged uid than
     * the app itself — [SHIZUKU_SHELL], [SHIZUKU_ROOT] and [ROOT]. This is the
     * escalation flag: it gates staging (see [canStage]) and tells the UI a
     * process behind the backend has to exist and be connected before a command
     * can be sent. It is NOT "talks to Shizuku" — that is [usesShizuku], and the
     * two diverge for [ROOT], which is privileged but reaches uid 0 through su.
     */
    val privileged: Boolean get() = this != LOCAL

    /**
     * True for the two backends that talk to a Shizuku user service across a
     * Binder. Everything Shizuku-specific keys off this — the Shizuku state
     * strip, the readiness gate on [com.trickhook.shizuku.ShizukuGate], the
     * shell/root relabel from the server's uid, the staging transport. [ROOT]
     * is deliberately excluded: it is privileged but its transport is a pipe to
     * a su-launched daemon, not the Shizuku Binder, so none of that applies.
     */
    val usesShizuku: Boolean get() = this == SHIZUKU_SHELL || this == SHIZUKU_ROOT

    /**
     * Whether the Attach control is offered at all.
     *
     * False on [SHIZUKU_SHELL] on purpose: PTRACE_ATTACH to a foreign pid is
     * refused by the kernel and by SELinux there, and an action that is always
     * going to fail should be visibly unavailable rather than fail when it is
     * pressed. [LOCAL] keeps it, because that is what it has always done and a
     * rooted or debuggable device still uses it. [ROOT] and [SHIZUKU_ROOT]
     * offer it because uid 0 can attach to any pid.
     */
    val offersAttach: Boolean get() = this != SHIZUKU_SHELL

    /**
     * Whether a file from app storage can be copied somewhere executable and
     * run. This is the capability the whole feature exists for. True for every
     * privileged backend: the Shizuku ones stage into /data/local/tmp across
     * the Binder, [ROOT] stages into the app's own files and has its
     * su-launched daemon exec it there.
     */
    val canStage: Boolean get() = privileged

    companion object {
        /**
         * The backend for a live Shizuku service, given the uid it runs as.
         * Only ever a Shizuku backend — [ROOT] is not reached this way, since it
         * does not go through a Shizuku service.
         */
        fun forUid(uid: Int): DbgBackend = if (uid == 0) SHIZUKU_ROOT else SHIZUKU_SHELL
    }
}
