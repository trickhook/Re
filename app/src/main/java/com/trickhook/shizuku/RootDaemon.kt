package com.trickhook.shizuku

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Where the su-launched debugger daemon is, in one enum, the same way
 * [ShizukuStage] is for Shizuku. "Is root available" is not a boolean, and the
 * debugger tab has a sentence and an action for each of these.
 */
enum class RootStage {
    /** Not looked for yet: nothing has been run, no `su` has been invoked. */
    UNKNOWN,

    /** A probe or a launch is in flight. */
    CHECKING,

    /** `su` is not on the device, was denied, or did not return uid 0. */
    NO_ROOT,

    /** The daemon is up and answered a debugger command. */
    RUNNING,

    /** `su` granted root but the daemon could not be started or did not answer. */
    FAILED,

    /** It was running and then the pipe broke mid-session. */
    DIED
}

/**
 * The fourth debugger backend's privileged half: uid 0 through `su`, with no
 * Shizuku at all.
 *
 * This is the exact counterpart of [ShizukuGate] for [DbgBackend.ROOT]. Where
 * ShizukuGate binds a Shizuku user service and forwards debugger JSON across a
 * Binder, this launches a native daemon ([app/src/main/cpp/samples/nocturned.cpp],
 * shipped in assets as `bin/<abi>/nocturned`) with `su` and forwards the same
 * debugger JSON over that process's stdin/stdout. The daemon is the SAME engine
 * the app runs in-process; only the transport differs — a pipe instead of a
 * Binder.
 *
 * A singleton with Compose snapshot state, so the debugger tab redraws as the
 * daemon comes up and goes down; state writes are marshalled to the main thread
 * by [onMain] because [connect] and the pipe I/O run on worker threads.
 *
 * NOTHING HERE STARTS BY ITSELF, exactly as with ShizukuGate. The daemon is
 * started only when someone picks the Root backend and presses Connect.
 *
 * ANTI-INJECTION. `su` is only ever invoked with a FIXED argv:
 * `["su", "-c", <a path this app chose>]`. The path is [Context.getFilesDir]
 * plus a constant file name — no part of it comes from a file's contents, a
 * pid, a process name, or anything a user typed. Untrusted data (the sample
 * bytes, the pid to attach, the addresses) travels as JSON on the daemon's
 * stdin, never on a command line, so there is nothing to inject into the root
 * shell. See [connectBlocking] and [stageSample].
 *
 * NO LEAK. The daemon must die with the app. Three things guarantee it: [cmd]
 * marks it dead the moment the pipe breaks; [disconnect] (called on Disconnect,
 * on a backend switch away from Root, and from the ViewModel's onCleared) closes
 * stdin and kills the process; and — the backstop for an abrupt app kill that
 * reaches none of those — closing our end of the pipe gives the daemon EOF on
 * its next read, so it exits on its own and PTRACE_O_EXITKILL takes any tracee
 * with it.
 */
object RootDaemon {

    /** Mirror of the abiFilters in build.gradle.kts and the assets we ship. */
    private val DAEMON_ABIS = listOf("arm64-v8a", "x86_64")

    /** Asset and on-disk name of the daemon executable. */
    private const val DAEMON_NAME = "nocturned"

    /**
     * Fixed on-disk name for a staged sample. Constant so the path handed to
     * the daemon is entirely app-controlled and free of shell metacharacters.
     */
    private const val STAGED_NAME = "root-staged-sample"

    /**
     * How long to wait for `su` to answer the availability probe. Generous
     * because the first invocation can raise a Magisk/SuperSU prompt the user
     * has to tap through.
     */
    private const val PROBE_TIMEOUT_MS = 20_000L

    private val main = Handler(Looper.getMainLooper())

    // ------------------------------------------------------------- state --

    var stage by mutableStateOf(RootStage.UNKNOWN); private set

    /** One sentence saying what [stage] means right now. Never empty. */
    var detail by mutableStateOf("Root has not been looked for yet."); private set

    /** "uid=0(root) ... context=..." from the su probe, while running. */
    var daemonLine by mutableStateOf(""); private set

    /** The staged sample's absolute path while one is staged, else "". */
    var stagedPath by mutableStateOf(""); private set

    @Volatile
    private var process: Process? = null

    @Volatile
    private var writer: BufferedWriter? = null

    @Volatile
    private var reader: BufferedReader? = null

    private var app: Context? = null

    /** True only when a command can actually be sent. */
    val ready: Boolean get() = stage == RootStage.RUNNING && process != null

    // --------------------------------------------------------- lifecycle --

    /**
     * Remember the application context. Safe to call on every entry to the
     * debugger tab; it starts nothing. Needed so [stageSample]/[unstage] have a
     * files dir even before Connect.
     */
    fun attach(context: Context) {
        app = context.applicationContext
    }

    /**
     * Probe `su`, extract the daemon, launch it, and confirm it answers — all on
     * a worker thread, because every step can block (a root prompt, a copy, a
     * pipe read). Safe to call from any state.
     */
    fun connect(context: Context) {
        val ctx = context.applicationContext
        app = ctx
        if (stage == RootStage.CHECKING || stage == RootStage.RUNNING) return
        onMain {
            stage = RootStage.CHECKING
            detail = "Checking for root and starting the debugger daemon."
        }
        Thread({ connectBlocking(ctx) }, "nocturne-root-connect").start()
    }

    private fun connectBlocking(ctx: Context) {
        // 1. Is there root at all? Run `su -c id` and read uid=0 back. This is
        //    the honest availability check: a device without root fails here
        //    with a reason, instead of the backend failing on first use.
        val probe = probeSu()
        if (!probe.ok) {
            onMain { stage = RootStage.NO_ROOT; detail = probe.text }
            return
        }

        // 2. Get the right-ABI daemon out of assets and onto disk somewhere su
        //    can exec it (app files — su is not bound by the untrusted_app W^X
        //    limit).
        val exe: File
        try {
            val extracted = extractDaemon(ctx)
            if (extracted == null) {
                onMain {
                    stage = RootStage.FAILED
                    detail = "No debugger daemon is bundled for this device's ABI " +
                        "(${Build.SUPPORTED_ABIS.joinToString()}). Shipped: " +
                        DAEMON_ABIS.joinToString() + "."
                }
                return
            }
            exe = extracted
        } catch (t: Throwable) {
            onMain {
                stage = RootStage.FAILED
                detail = "The debugger daemon is missing from the app (bin/<abi>/$DAEMON_NAME). " +
                    "It is built into the APK by CI. (${describe(t)})"
            }
            return
        }

        // 3. Launch it under su with a FIXED argv — exe.absolutePath is app
        //    files plus a constant name, no untrusted text. stdin/stdout are the
        //    pipe we talk the debugger protocol over; stderr is drained and
        //    discarded so it can never fill and block the daemon.
        val proc: Process
        try {
            proc = ProcessBuilder("su", "-c", exe.absolutePath).start()
        } catch (t: Throwable) {
            onMain {
                stage = RootStage.FAILED
                detail = "su would not start the daemon: ${describe(t)}"
            }
            return
        }
        drainAndDiscard(proc)
        process = proc
        writer = proc.outputStream.bufferedWriter()
        reader = proc.inputStream.bufferedReader()

        // 4. Confirm the engine is actually answering. `status` is a real engine
        //    op with no side effects; ok:true means the daemon started, the
        //    engine loaded, and the pipe round-trips.
        val ans = cmd("""{"op":"status"}""")
        val ok = try {
            JSONObject(ans).optBoolean("ok")
        } catch (t: Throwable) {
            false
        }
        if (!ok) {
            val why = try {
                JSONObject(ans).optString("error")
            } catch (t: Throwable) {
                ans.take(120)
            }
            teardownProcess()
            onMain {
                stage = RootStage.FAILED
                detail = "The root daemon did not answer. su may have been denied, or SELinux " +
                    "refused to exec it." + (if (why.isNotBlank()) " ($why)" else "")
            }
            return
        }
        onMain {
            stage = RootStage.RUNNING
            daemonLine = probe.text
            detail = "Root debugger daemon running."
        }
    }

    /**
     * Stop the daemon: close stdin (so its next read hits EOF and it exits,
     * releasing any tracee) and kill the su process. Called from the Disconnect
     * button, on a backend switch away from Root, and from the ViewModel's
     * onCleared.
     */
    fun disconnect() {
        teardownProcess()
        onMain {
            daemonLine = ""
            stagedPath = ""
            if (stage == RootStage.RUNNING || stage == RootStage.CHECKING) {
                stage = RootStage.UNKNOWN
                detail = "Root debugger daemon stopped."
            }
        }
    }

    // --------------------------------------------------------- transport --

    /**
     * Send one debugger command and read one answer.
     *
     * Blocking; call it off the main thread. Synchronized because the daemon is
     * a single request/response pipe — unlike a Binder it does not serialize
     * concurrent callers itself, and the 400 ms session poll issues several
     * commands in a row. Never throws: a broken pipe comes back as
     * `{"ok":false,"error":...}` and is reported like any other failed command.
     */
    @Synchronized
    fun cmd(json: String): String {
        val w = writer
        val r = reader
        if (w == null || r == null || process == null) {
            return errJson("no root daemon is connected — pick the Root backend and press Connect")
        }
        return try {
            w.write(json)
            w.write("\n")
            w.flush()
            val line = r.readLine()
            if (line == null) {
                daemonDied()
                errJson("the root daemon closed its output — the process is gone")
            } else {
                line
            }
        } catch (t: Throwable) {
            daemonDied()
            errJson(describe(t))
        }
    }

    // ----------------------------------------------------------- staging --

    /** What [stageSample] found out. [path] is empty unless [ok]. */
    class StageResult(
        val ok: Boolean,
        val path: String,
        val note: String,
        val machine: String
    )

    /**
     * Copy [file] into the app's own files directory, make it executable, and
     * return the path for the daemon to spawn.
     *
     * No bytes cross any IPC: the daemon runs as root, so it reads the copied
     * file by path directly — the app can always write its own files, and root
     * can read and exec them (root is not bound by the untrusted_app SELinux
     * exec rule the way the app is). A previous staged file is removed first.
     *
     * Blocking; call it off the main thread.
     */
    fun stageSample(file: File): StageResult {
        if (process == null) return StageResult(false, "", "no root daemon is connected", "")
        if (!file.isFile) return StageResult(false, "", file.absolutePath + " is not a file any more", "")
        val ctx = app ?: return StageResult(false, "", "no app context", "")
        unstage()
        val dst = File(ctx.filesDir, STAGED_NAME)
        val machine: String
        try {
            file.inputStream().use { ins -> dst.outputStream().use { ins.copyTo(it) } }
            machine = readElfMachine(dst)
        } catch (t: Throwable) {
            return StageResult(false, "", "could not copy the sample: " + describe(t), "")
        }
        // The chmod succeeds as a syscall; that THIS app cannot exec app storage
        // is irrelevant, the root daemon will.
        dst.setReadable(true)
        dst.setExecutable(true)
        val path = dst.absolutePath
        onMain { stagedPath = path }
        val device = deviceMachine()
        val runnable = machine.isEmpty() || device.isEmpty() || machine == device
        val note = if (runnable) "" else "sample is $machine; this device runs $device"
        return StageResult(true, path, note, machine)
    }

    /** Delete the staged sample. Called when a session ends and when another is staged. */
    fun unstage() {
        val ctx = app ?: return
        val f = File(ctx.filesDir, STAGED_NAME)
        if (f.exists()) {
            try {
                f.delete()
            } catch (t: Throwable) {
                // Best effort; it lives in the app's own dir, nobody else sees it.
            }
        }
        onMain { stagedPath = "" }
    }

    // -------------------------------------------------------------- misc --

    /** Result of the su probe: [ok] plus a human line (the id output, or why not). */
    private class Probe(val ok: Boolean, val text: String)

    private fun probeSu(): Probe {
        val p = try {
            ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
        } catch (t: Throwable) {
            return Probe(
                false,
                "su is not available on this device (${describe(t)}). It is not rooted, or root " +
                    "is not exposed to apps."
            )
        }
        val finished = try {
            p.waitFor(PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (t: Throwable) {
            false
        }
        if (!finished) {
            try {
                p.destroyForcibly()
            } catch (t: Throwable) {
                // already gone
            }
            return Probe(
                false,
                "su did not answer within ${PROBE_TIMEOUT_MS / 1000}s — the root prompt may have " +
                    "been dismissed."
            )
        }
        val out = try {
            p.inputStream.bufferedReader().use { it.readText() }.trim()
        } catch (t: Throwable) {
            ""
        }
        return if (out.contains("uid=0")) {
            Probe(true, out.lineSequence().firstOrNull()?.take(160) ?: "uid=0")
        } else {
            Probe(
                false,
                "su ran but did not grant root (no uid=0)." +
                    (if (out.isNotEmpty()) " " + out.take(120) else "")
            )
        }
    }

    private fun extractDaemon(ctx: Context): File? {
        val abi = Build.SUPPORTED_ABIS.firstOrNull { it in DAEMON_ABIS } ?: return null
        val dst = File(ctx.filesDir, DAEMON_NAME)
        ctx.assets.open("bin/$abi/$DAEMON_NAME").use { ins ->
            dst.outputStream().use { ins.copyTo(it) }
        }
        dst.setReadable(true)
        dst.setExecutable(true)
        return dst
    }

    /** The ELF e_machine as an ABI name, or "" when the file is not a readable ELF. */
    private fun readElfMachine(f: File): String {
        return try {
            val h = ByteArray(20)
            val n = f.inputStream().use { it.read(h) }
            if (n < 20) return ""
            val elf = h[0].toInt() and 0xFF == 0x7F &&
                h[1].toInt() == 'E'.code && h[2].toInt() == 'L'.code && h[3].toInt() == 'F'.code
            if (!elf) return ""
            val m = (h[18].toInt() and 0xFF) or ((h[19].toInt() and 0xFF) shl 8)
            when (m) {
                0xB7 -> "arm64-v8a"
                0x3E -> "x86_64"
                0x28 -> "armeabi-v7a"
                0x03 -> "x86"
                else -> "machine 0x%X".format(m)
            }
        } catch (t: Throwable) {
            ""
        }
    }

    private fun deviceMachine(): String = Build.SUPPORTED_ABIS.firstOrNull() ?: ""

    /**
     * Read the daemon's stderr to /dev/null on a thread of its own. The daemon
     * writes nothing there (engine logs go to logcat), but su can, and an
     * undrained stderr pipe that filled would block the process. It ends at EOF
     * when the process dies.
     */
    private fun drainAndDiscard(proc: Process) {
        Thread({
            try {
                proc.errorStream.use { es ->
                    val buf = ByteArray(4096)
                    while (es.read(buf) >= 0) {
                        // discard
                    }
                }
            } catch (t: Throwable) {
                // process gone
            }
        }, "nocturne-root-stderr").start()
    }

    private fun teardownProcess() {
        val p = process
        val w = writer
        process = null
        writer = null
        reader = null
        // Closing stdin gives the daemon EOF -> it exits cleanly, releasing any
        // tracee (PTRACE_O_EXITKILL). destroy() then kills the su process too.
        try {
            w?.close()
        } catch (t: Throwable) {
            // already closed
        }
        try {
            p?.outputStream?.close()
        } catch (t: Throwable) {
            // already closed
        }
        try {
            p?.destroy()
        } catch (t: Throwable) {
            // already gone
        }
        try {
            p?.destroyForcibly()
        } catch (t: Throwable) {
            // already gone
        }
    }

    private fun daemonDied() {
        val p = process
        process = null
        writer = null
        reader = null
        try {
            p?.destroyForcibly()
        } catch (t: Throwable) {
            // already gone
        }
        onMain {
            daemonLine = ""
            stagedPath = ""
            stage = RootStage.DIED
            detail = "The root debugger daemon died. Reconnect to start a new one."
        }
    }

    private fun errJson(why: String): String =
        JSONObject().put("ok", false).put("error", "root: " + why).toString()

    private fun describe(t: Throwable): String {
        val m = t.message
        return if (m.isNullOrBlank()) t.javaClass.simpleName else t.javaClass.simpleName + ": " + m
    }

    private fun onMain(block: () -> Unit) {
        if (Looper.myLooper() === Looper.getMainLooper()) block() else main.post(block)
    }
}
