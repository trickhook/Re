package com.trickhook.shizuku

import android.content.Context
import android.os.Binder
import android.system.Os
import android.system.OsConstants
import androidx.annotation.Keep
import com.trickhook.engine.NativeBridge
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.security.SecureRandom

/**
 * THIS CLASS DOES NOT RUN IN THE APP.
 *
 * Shizuku's server starts a separate process for it — literally
 *
 *   (CLASSPATH='<shizuku.apk>' /system/bin/app_process /system/bin
 *      --nice-name='com.trickhook:dbg' moe.shizuku.starter.ServiceStarter
 *      --token=... --package=com.trickhook --class=<this class> --uid=<ours>)&
 *
 * and that process runs as **uid 2000 (shell)** with the adb backend, or uid 0
 * with a root/Sui backend, with no non-SDK-API restrictions. The starter builds
 * our Application through createPackageContextAsUser(CONTEXT_INCLUDE_CODE) and
 * instantiates this class by name off `application.getClassLoader()`, so the
 * code is ours and the class loader is the app's — which is the whole reason
 * System.loadLibrary can find libnocturne.so at all. See
 * NativeBridge.ensureEngine and docs/SHIZUKU.md.
 *
 * What that buys, and it is the entire point of this file: a shell-uid process
 * may write to /data/local/tmp, chmod +x there, and fork / PTRACE_TRACEME /
 * exec its own child. That is the gdbserver workflow, and it makes "run and
 * debug an arbitrary ARM64 sample" possible on a stock, unrooted phone — where
 * the app itself cannot execve anything out of its own data directory at all,
 * because app_data_file carries no execute permission from Android 10 on.
 *
 * What it does NOT buy: PTRACE_ATTACH to a process this backend did not start.
 * `shell` cannot ptrace an app domain without `run-as`, and `run-as` only
 * covers debuggable packages. That stays a root feature, and the UI says so
 * rather than letting someone find out by pressing a button.
 *
 * Constraints this file works under, all of them load-bearing:
 *
 *  - It is NOT a real Android application process. Context#registerReceiver,
 *    Context#getContentResolver and friends do not work. Nothing here uses
 *    them; the only thing the Context is read for is ApplicationInfo.
 *  - It cannot read the app's data directory. Samples arrive over the Binder
 *    in chunks, never as a path.
 *  - Its lifetime is tied to the app process (daemon(false)), so the app going
 *    away takes the privileged process with it — the same stance McpService
 *    takes with stopWithTask. A SIGKILL still skips [destroy], so staged files
 *    are also swept on every fresh connect.
 */
class NocturneUserService : INocturneService.Stub {

    companion object {
        /**
         * Everything this service stages lives under here and nowhere else.
         * /data/local/tmp is shell_data_file: the one directory a shell-uid
         * process may both write to and execute from.
         */
        private const val ROOT_DIR = "/data/local/tmp/nocturne"

        /**
         * 0700. Kotlin has no octal literals — `0700` is seven hundred — and
         * that is exactly the kind of typo that silently leaves a staged sample
         * readable by everything on the device, so the bits are spelled out.
         */
        private const val MODE_0700 = 0b111_000_000

        /**
         * A sample bigger than this is refused rather than pushed through the
         * Binder 256 KiB at a time for minutes with no way to cancel.
         */
        private const val MAX_STAGE = 128L * 1024 * 1024
    }

    /**
     * The app's uid, when Shizuku used the Context constructor (v13+). Every
     * command is checked against it: this Binder is only ever handed to our own
     * package, but a privileged surface should not rely on that staying true
     * forever. -1 means "unknown", which is the pre-v13 path, and the check is
     * skipped rather than guessed at.
     */
    private val appUid: Int

    /**
     * The app's nativeLibraryDir, for [NativeBridge.ensureEngine]'s second
     * attempt. Null on the pre-v13 path, where only the class loader's own
     * search path is available.
     */
    private val nativeLibDir: String?

    /** Staging in flight, keyed by token. */
    private val inFlight = HashMap<String, Staging>()

    /** Staging finished and on disk, keyed by token. */
    private val staged = HashMap<String, File>()

    private val rng = SecureRandom()

    private class Staging(val dir: File, val file: File, val out: FileOutputStream) {
        var written: Long = 0
    }

    /** Shizuku pre-v13 and the Sui-only path. */
    constructor() : super() {
        appUid = -1
        nativeLibDir = null
    }

    /**
     * Shizuku v13+ tries this one first. The Context is created with
     * createPackageContextAsUser and is NOT a working application Context; it
     * is read here for ApplicationInfo and nothing else.
     *
     * Kept explicitly because the class is reached by name from another
     * process: R8 has no call site to see.
     */
    @Keep
    constructor(context: Context) : super() {
        var uid = -1
        var dir: String? = null
        try {
            val ai = context.applicationInfo
            uid = ai.uid
            dir = ai.nativeLibraryDir
        } catch (t: Throwable) {
            // A Context that cannot answer for its own package is not fatal:
            // the uid check turns itself off and the engine load falls back to
            // the class loader's own search path.
        }
        appUid = uid
        nativeLibDir = dir
    }

    // ------------------------------------------------------------ lifecycle --

    override fun destroy() {
        try {
            if (NativeBridge.loadError == null) NativeBridge.nativeDbgCmd("""{"op":"kill"}""")
        } catch (t: Throwable) {
            // The tracee is about to lose its tracer either way.
        }
        sweep()
        System.exit(0)
    }

    // ------------------------------------------------------------- commands --

    override fun dbgCmd(json: String?): String {
        val body = json
        if (body.isNullOrBlank()) return fail("request", "empty command")
        val denied = callerDenied()
        if (denied != null) return denied
        val op = try {
            JSONObject(body).optString("op")
        } catch (t: Throwable) {
            return fail("request", "not JSON: " + describe(t))
        }
        return try {
            when {
                op == "svc.hello" -> hello()
                op == "svc.stageBegin" -> stageBegin(JSONObject(body))
                op == "svc.stageEnd" -> stageEnd(JSONObject(body))
                op == "svc.unstage" -> unstage(JSONObject(body))
                op == "svc.sweep" -> JSONObject().put("ok", true).put("removed", sweep()).toString()
                op.startsWith("svc.") -> fail("request", "unknown service op '" + op + "'")
                else -> forward(body)
            }
        } catch (t: Throwable) {
            // Never let anything out of here as an exception: across a Binder
            // that arrives as a bare RemoteException carrying no message at
            // all, and the debugger tab would say "command failed" and stop.
            fail("service", describe(t))
        }
    }

    override fun stageChunk(json: String?, chunk: ByteArray?): String {
        val denied = callerDenied()
        if (denied != null) return denied
        return try {
            val o = JSONObject(json ?: "{}")
            val token = o.optString("token")
            val st = inFlight[token] ?: return fail("stage", "no staging in progress for that token")
            val bytes = chunk ?: return fail("stage", "chunk was null")
            if (st.written + bytes.size > MAX_STAGE) {
                abort(token)
                return fail(
                    "stage",
                    "the sample is larger than the " + (MAX_STAGE / 1024 / 1024) + " MiB staging limit"
                )
            }
            st.out.write(bytes)
            st.written += bytes.size
            """{"ok":true}"""
        } catch (t: Throwable) {
            fail("stage", describe(t))
        }
    }

    /**
     * Forward to the engine, having first made sure there is one.
     *
     * This is the single most likely thing in the whole feature not to work:
     * the class loader here is the app's, built by LoadedApk inside a process
     * that is not an app, and libnocturne.so has to be found through it.
     * [NativeBridge.ensureEngine] tries the class loader first and an explicit
     * path second, and returns a sentence rather than throwing, so a failure
     * arrives in the event log as a reason instead of as silence.
     */
    private fun forward(body: String): String {
        val why = NativeBridge.ensureEngine(nativeLibDir)
        if (why != null) return fail("engine", why)
        return NativeBridge.nativeDbgCmd(body)
    }

    private fun hello(): String {
        val why = NativeBridge.ensureEngine(nativeLibDir)
        val uid = Os.getuid()
        val o = JSONObject()
        o.put("ok", true)
        o.put("uid", uid)
        o.put("pid", Os.getpid())
        o.put("root", uid == 0)
        o.put("machine", machine())
        o.put("has32", has32Bit())
        o.put("engine", if (why == null) "loaded" else "unavailable")
        o.put("engineError", why ?: "")
        o.put("selinux", selinuxContext())
        o.put("tmp", ROOT_DIR)
        o.put("swept", sweep())
        return o.toString()
    }

    // -------------------------------------------------------------- staging --

    private fun stageBegin(o: JSONObject): String {
        val size = o.optLong("size")
        if (size <= 0L) return fail("stage", "the file is empty, so there is nothing to run")
        if (size > MAX_STAGE) {
            return fail(
                "stage",
                "the sample is " + (size / 1024 / 1024) + " MiB; the staging limit is " +
                    (MAX_STAGE / 1024 / 1024) + " MiB"
            )
        }
        val root = File(ROOT_DIR)
        val guard = guardRoot(root)
        if (guard != null) return guard
        val token = newToken()
        val dir = File(root, token)
        if (!dir.mkdirs() && !dir.isDirectory) {
            return fail(
                "stage",
                "cannot create " + dir.absolutePath + " — uid " + Os.getuid() +
                    " may not write to " + ROOT_DIR
            )
        }
        chmod(dir, MODE_0700)
        val dst = File(dir, safeName(o.optString("name")))
        val out = try {
            FileOutputStream(dst)
        } catch (t: Throwable) {
            purge(dir)
            return fail("stage", "cannot open " + dst.absolutePath + ": " + describe(t))
        }
        inFlight[token] = Staging(dir, dst, out)
        return JSONObject()
            .put("ok", true)
            .put("token", token)
            .put("path", dst.absolutePath)
            .toString()
    }

    private fun stageEnd(o: JSONObject): String {
        val token = o.optString("token")
        val st = inFlight[token] ?: return fail("stage", "no staging in progress for that token")
        inFlight.remove(token)
        try {
            st.out.flush()
            st.out.close()
        } catch (t: Throwable) {
            purge(st.dir)
            return fail("stage", "could not finish writing " + st.file.name + ": " + describe(t))
        }
        val declared = o.optLong("size", -1L)
        if (declared >= 0L && declared != st.written) {
            purge(st.dir)
            return fail("stage", "transfer was short: " + st.written + " of " + declared + " bytes arrived")
        }
        // Executable, and reachable by nobody else. The child that execs it
        // runs as this same uid, so owner-only is enough — and /data/local/tmp
        // is shared with every other shell-uid process on the device, which is
        // exactly why the default 0644 would be the wrong answer.
        val modeErr = chmod(st.file, MODE_0700)
        if (modeErr != null) {
            purge(st.dir)
            return fail("stage", "chmod 0700 on " + st.file.absolutePath + " failed: " + modeErr)
        }
        staged[token] = st.file
        val probe = probeElf(st.file)
        return JSONObject()
            .put("ok", true)
            .put("token", token)
            .put("path", st.file.absolutePath)
            .put("size", st.written)
            .put("runnable", probe.runnable)
            .put("machine", probe.machine)
            .put("bits", probe.bits)
            .put("kind", probe.kind)
            .put("note", probe.note)
            .toString()
    }

    private fun unstage(o: JSONObject): String {
        val token = o.optString("token")
        if (token.isEmpty()) return JSONObject().put("ok", true).put("removed", sweep()).toString()
        var removed = 0
        inFlight[token]?.let { st ->
            try {
                st.out.close()
            } catch (t: Throwable) {
                // Closing a stream we are about to delete under.
            }
            removed += purge(st.dir)
            inFlight.remove(token)
        }
        staged.remove(token)?.let { f -> removed += purge(f.parentFile ?: f) }
        return JSONObject().put("ok", true).put("removed", removed).toString()
    }

    /**
     * Delete everything under [ROOT_DIR] and nothing above it.
     *
     * Called on connect as well as on teardown, because the tidy paths are not
     * the only paths: a SIGKILL, a crash or a phone that ran out of battery
     * mid-session each leave an executable behind in a directory shared with
     * every other shell process on the device. Returns how many entries went.
     */
    private fun sweep(): Int {
        for (st in inFlight.values) {
            try {
                st.out.close()
            } catch (t: Throwable) {
                // Same as above.
            }
        }
        inFlight.clear()
        staged.clear()
        val root = File(ROOT_DIR)
        if (guardRoot(root) != null) return 0
        var n = 0
        val kids = root.list() ?: return 0
        for (k in kids) n += purge(File(root, k))
        return n
    }

    /**
     * Refuse to touch [ROOT_DIR] if it is a symbolic link.
     *
     * With a root backend [purge] runs as uid 0, and a symlink planted at
     * /data/local/tmp/nocturne by anything else with shell access would turn a
     * recursive delete of our own scratch directory into a recursive delete of
     * whatever it points at. Returns an error JSON, or null when the path is
     * safe — including when it does not exist yet.
     */
    private fun guardRoot(root: File): String? {
        val st = try {
            Os.lstat(root.absolutePath)
        } catch (t: Throwable) {
            return null   // not there yet; mkdirs will make a real directory
        }
        if (OsConstants.S_ISLNK(st.st_mode)) {
            return fail(
                "stage",
                ROOT_DIR + " is a symbolic link. Refusing to stage or delete through it — " +
                    "remove it by hand and try again."
            )
        }
        if (!OsConstants.S_ISDIR(st.st_mode)) {
            return fail("stage", ROOT_DIR + " exists and is not a directory. Remove it and try again.")
        }
        return null
    }

    /**
     * Recursive delete that cannot escape through a symlink: lstat does not
     * follow one, so a link child is removed as a link and its target is left
     * alone. Depth is whatever we created, which is one level.
     */
    private fun purge(f: File): Int {
        val st = try {
            Os.lstat(f.absolutePath)
        } catch (t: Throwable) {
            return 0
        }
        var n = 0
        if (OsConstants.S_ISDIR(st.st_mode)) {
            f.list()?.forEach { k -> n += purge(File(f, k)) }
        }
        if (f.delete()) n++
        return n
    }

    private fun abort(token: String) {
        inFlight.remove(token)?.let { st ->
            try {
                st.out.close()
            } catch (t: Throwable) {
                // Nothing left to salvage.
            }
            purge(st.dir)
        }
    }

    // ------------------------------------------------------------ elf probe --

    /**
     * Just enough of the ELF header to turn "the child exited with 127" into a
     * sentence. Two things actually matter: whether the machine matches this
     * process, and whether there is a program interpreter — a .so has none, and
     * execve on one fails in a way indistinguishable from a missing file.
     */
    private class Probe(
        val runnable: Boolean,
        val machine: String,
        val bits: Int,
        val kind: String,
        val note: String
    )

    private fun probeElf(f: File): Probe = try {
        RandomAccessFile(f, "r").use { raf -> probeOpen(raf) }
    } catch (t: Throwable) {
        Probe(false, "", 0, "", "could not read the ELF header: " + describe(t))
    }

    private fun probeOpen(raf: RandomAccessFile): Probe {
        if (raf.length() < 64L) {
            return Probe(
                false, "", 0, "",
                "only " + raf.length() + " bytes long: too short to be an ELF image"
            )
        }
        val h = ByteArray(64)
        raf.seek(0L)
        raf.readFully(h)
        if (h[0] != 0x7F.toByte() || h[1] != 'E'.code.toByte() ||
            h[2] != 'L'.code.toByte() || h[3] != 'F'.code.toByte()
        ) {
            return Probe(
                false, "", 0, "",
                "no ELF magic. The ptrace backend runs native ELF binaries only — " +
                    "a .dex, a .jar or a script cannot be spawned."
            )
        }
        val cls = h[4].toInt() and 0xFF
        if ((h[5].toInt() and 0xFF) != 1) {
            return Probe(false, "", 0, "", "big-endian ELF: no Android device runs one")
        }
        val bits = if (cls == 2) 64 else 32
        val type = u16(h, 16)
        val mach = u16(h, 18)
        val name = machineName(mach)
        val kind = when (type) {
            1 -> "REL"
            2 -> "EXEC"
            3 -> "DYN"
            4 -> "CORE"
            else -> "type " + type
        }
        if (type != 2 && type != 3) {
            return Probe(false, name, bits, kind, "ELF type " + kind + " is not an executable image")
        }
        if (type == 3 && !hasInterp(raf, h, bits)) {
            return Probe(
                false, name, bits, kind,
                "shared object with no PT_INTERP: this is a library, not a program. " +
                    "Analyse it, or spawn the executable that loads it."
            )
        }
        val self = machine()
        if (!compatible(name, self)) {
            val extra = if (isSibling(name, self) && !has32Bit()) {
                " and this device has no 32-bit runtime"
            } else {
                ""
            }
            return Probe(
                false, name, bits, kind,
                "built for " + name + "; the privileged process is " + self + extra +
                    ". Nothing here can execve it."
            )
        }
        return Probe(true, name, bits, kind, "")
    }

    /** PT_INTERP is type 3 in the program header table. */
    private fun hasInterp(raf: RandomAccessFile, h: ByteArray, bits: Int): Boolean {
        return try {
            val phoff = if (bits == 64) u64(h, 32) else u32(h, 28)
            val phentsize = if (bits == 64) u16(h, 54) else u16(h, 42)
            val phnum = if (bits == 64) u16(h, 56) else u16(h, 44)
            if (phoff <= 0L || phentsize < 4 || phnum <= 0 || phnum > 512) return false
            if (phoff + phentsize.toLong() * phnum > raf.length()) return false
            val table = ByteArray(phentsize * phnum)
            raf.seek(phoff)
            raf.readFully(table)
            var i = 0
            while (i < phnum) {
                if (u32(table, i * phentsize) == 3L) return true
                i++
            }
            false
        } catch (t: Throwable) {
            false
        }
    }

    private fun u16(b: ByteArray, at: Int): Int =
        (b[at].toInt() and 0xFF) or ((b[at + 1].toInt() and 0xFF) shl 8)

    private fun u32(b: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = v or ((b[at + i].toLong() and 0xFF) shl (8 * i))
        return v
    }

    private fun u64(b: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[at + i].toLong() and 0xFF) shl (8 * i))
        return v
    }

    private fun machineName(mach: Int): String = when (mach) {
        3 -> "x86"
        40 -> "arm"
        62 -> "x86_64"
        183 -> "aarch64"
        243 -> "riscv64"
        else -> "machine 0x" + Integer.toHexString(mach)
    }

    /** uname().machine — what THIS process is, not what the device supports. */
    private fun machine(): String = try {
        val m = Os.uname().machine ?: ""
        when {
            m.startsWith("aarch64") -> "aarch64"
            m.startsWith("armv") || m == "arm" -> "arm"
            m == "x86_64" -> "x86_64"
            m.length == 4 && m[0] == 'i' && m.endsWith("86") -> "x86"
            else -> m
        }
    } catch (t: Throwable) {
        ""
    }

    private fun has32Bit(): Boolean {
        val abis = android.os.Build.SUPPORTED_32_BIT_ABIS
        return abis != null && abis.isNotEmpty()
    }

    /** True when [sample] is the 32-bit sibling of [self]'s architecture. */
    private fun isSibling(sample: String, self: String): Boolean =
        (self == "aarch64" && sample == "arm") || (self == "x86_64" && sample == "x86")

    private fun compatible(sample: String, self: String): Boolean = when {
        sample.isEmpty() || self.isEmpty() -> true       // never block on a guess
        sample == self -> true
        isSibling(sample, self) -> has32Bit()
        else -> false
    }

    // ---------------------------------------------------------------- misc --

    private fun callerDenied(): String? {
        if (appUid < 0) return null
        val caller = Binder.getCallingUid()
        if (caller == appUid) return null
        return fail("caller", "uid " + caller + " is not Nocturne (uid " + appUid + ")")
    }

    private fun newToken(): String {
        val b = ByteArray(8)
        rng.nextBytes(b)
        val sb = StringBuilder(16)
        for (x in b) sb.append(String.format("%02x", x.toInt() and 0xFF))
        return sb.toString()
    }

    /**
     * A file name that cannot leave the staging directory. The name comes from
     * a file the user picked, so it can hold anything at all: `..`, a slash, a
     * newline. In a process running as shell that is a directory traversal with
     * teeth, so it is reduced to a conservative ASCII set rather than escaped.
     */
    private fun safeName(raw: String?): String {
        val base = (raw ?: "").substringAfterLast('/').substringAfterLast('\\')
        val cleaned = base.filter { c ->
            c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' ||
                c == '.' || c == '_' || c == '-' || c == '+'
        }.trimStart('.')
        return if (cleaned.isEmpty()) "sample" else cleaned.take(96)
    }

    private fun chmod(f: File, mode: Int): String? = try {
        Os.chmod(f.absolutePath, mode)
        null
    } catch (t: Throwable) {
        describe(t)
    }

    private fun selinuxContext(): String = try {
        File("/proc/self/attr/current").inputStream().bufferedReader().use { r ->
            // The file is NUL-terminated as well as newline-terminated, so trim on
            // "anything at or below a space" rather than on whitespace alone.
            r.readText().trim { c -> c <= ' ' }
        }
    } catch (t: Throwable) {
        ""
    }

    private fun describe(t: Throwable): String {
        val m = t.message
        return if (m.isNullOrBlank()) t.javaClass.simpleName else t.javaClass.simpleName + ": " + m
    }

    private fun fail(kind: String, why: String): String =
        JSONObject().put("ok", false).put("error", kind + ": " + why).toString()
}
