package com.trickhook.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.DeadObjectException
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.trickhook.BuildConfig
import org.json.JSONObject
import rikka.shizuku.Shizuku
import rikka.sui.Sui
import java.io.File

/**
 * Where Shizuku is, in one enum, because "is Shizuku available" is not a
 * boolean and pretending it is produced most of the bad UX in apps that use it.
 *
 * Every value here has a UI of its own in the debugger tab: a sentence that
 * says what the state means and one action that moves out of it. None of them
 * dead-ends — not even [NOT_INSTALLED], which links to where Shizuku comes
 * from rather than telling the user to go and find it.
 */
enum class ShizukuStage {
    /** Neither Shizuku nor Sui is on the device. */
    NOT_INSTALLED,

    /** Installed, but the service is not running: nobody has paired it this boot. */
    NOT_RUNNING,

    /**
     * A binder arrived from a server too old to be worth supporting. Shizuku
     * API dropped pre-v11 in 12.1.0 and user services need v10 at minimum, so
     * this is "upgrade Shizuku", not "this device cannot do it".
     */
    UNSUPPORTED,

    /** Running, and has never been asked for permission. */
    ASK,

    /** Running, and the user said no. */
    DENIED,

    /** Permission granted, privileged service not started yet. */
    GRANTED,

    /** bindUserService is in flight. */
    BINDING,

    /** The privileged service answered and the engine is loaded in it. */
    BOUND,

    /**
     * The service was started but is not usable: no binder inside the timeout,
     * the process died on the way up, or libnocturne.so would not load in it.
     */
    BIND_FAILED,

    /** It was working and then the binder went away mid-session. */
    BINDER_DEAD
}

/**
 * The Shizuku side of the debugger: availability, permission, the lifetime of
 * the privileged service, and the transport that carries debugger commands to
 * it.
 *
 * A singleton because the privileged process outlives any one composition and
 * survives tab switches, while the screen that shows it does not. Every field
 * is Compose snapshot state so the debugger tab redraws itself, and every write
 * is marshalled onto the main thread by [onMain]: the Shizuku listeners and
 * the ServiceConnection callbacks already arrive there, but [handshake],
 * [stageSample] and [cmd] run on worker threads.
 *
 * [refresh], [connect] and [disconnect] are main-thread calls and do talk to
 * Shizuku synchronously. Every one of those is a single Binder transaction to a
 * resident process — pingBinder, getVersion, getUid, checkSelfPermission — and
 * the two that could genuinely block, starting the process and loading the
 * engine inside it, are both asynchronous already.
 *
 * NOTHING HERE STARTS BY ITSELF. Listeners are registered the first time the
 * debugger tab is opened; the privileged process is started only when someone
 * picks the Shizuku backend and presses Connect. `daemon(false)` ties it to the
 * app process, so swiping Nocturne away takes it down — the same stance
 * McpService takes with `stopWithTask`.
 */
object ShizukuGate {

    /** Shizuku's own package. Sui is a Magisk module and has none. */
    const val MANAGER_PACKAGE = "moe.shizuku.privileged.api"

    /** Where a user who has not got Shizuku is sent. */
    const val DOWNLOAD_URL = "https://shizuku.rikka.app/download/"

    /**
     * Any int; it comes straight back through
     * OnRequestPermissionResultListener and is only used to tell our own
     * request apart from somebody else's.
     */
    private const val PERMISSION_REQUEST = 0x4E4F43

    /**
     * How long to wait for bindUserService to produce a binder. Shizuku's
     * server gives the starting process 30 s before it drops the record; this
     * is shorter so the screen stops claiming to be busy first, and it is
     * advisory — a binder that turns up at 25 s is still accepted.
     */
    private const val BIND_TIMEOUT_MS = 20_000L

    /**
     * Bytes per stageChunk transaction. The Binder transaction buffer is about
     * 1 MiB and it is shared across everything in flight in the process, so a
     * quarter of it is the usual safe ceiling for one payload.
     */
    private const val CHUNK = 256 * 1024

    private val main = Handler(Looper.getMainLooper())

    // ------------------------------------------------------------- state --

    var stage by mutableStateOf(ShizukuStage.NOT_INSTALLED); private set

    /** One sentence saying what [stage] means right now. Never empty. */
    var detail by mutableStateOf("Shizuku has not been looked for yet."); private set

    /** uid the Shizuku server runs as: 0 for root, 2000 for adb, -1 unknown. */
    var serverUid by mutableIntStateOf(-1); private set

    /** Shizuku API version of the server, or -1. */
    var serverApi by mutableIntStateOf(-1); private set

    /** True when the backend is Sui rather than the Shizuku app. */
    var sui by mutableStateOf(false); private set

    /** "uid 2000 (shell) - aarch64 - u:r:shell:s0", from the service itself. */
    var serviceLine by mutableStateOf(""); private set

    /** The staged sample's absolute path while one is staged, else "". */
    var stagedPath by mutableStateOf(""); private set

    @Volatile
    private var service: INocturneService? = null

    @Volatile
    private var stagedToken: String = ""

    private var app: Context? = null
    private var listening = false
    private var binding = false
    private var everBound = false

    /** True only when a command can actually be sent. */
    val ready: Boolean get() = stage == ShizukuStage.BOUND && service != null

    // --------------------------------------------------------- lifecycle --

    /**
     * Register the listeners once and re-read the world. Safe to call on every
     * entry to the debugger tab, and that is how it is called: a permission
     * granted in Shizuku's own UI while we were on another tab is picked up
     * here rather than needing the app restarted.
     *
     * The received-listener is the *sticky* variant, so a binder that arrived
     * before the tab was ever opened still reaches us.
     */
    fun attach(context: Context) {
        app = context.applicationContext
        if (!listening) {
            listening = true
            // Registered for the life of the process and never removed:
            // Shizuku keeps listeners in a plain ArrayList with no dedup, so a
            // register/unregister pair on every tab switch is how an app ends
            // up with forty copies of one callback.
            try {
                Shizuku.addBinderReceivedListenerSticky(binderReceived)
                Shizuku.addBinderDeadListener(binderDead)
                Shizuku.addRequestPermissionResultListener(permissionResult)
            } catch (t: Throwable) {
                listening = false
            }
        }
        refresh()
    }

    private val binderReceived = Shizuku.OnBinderReceivedListener { refresh() }

    private val binderDead = Shizuku.OnBinderDeadListener {
        onMain {
            service = null
            binding = false
            serviceLine = ""
            stagedPath = ""
            stagedToken = ""
            stage = ShizukuStage.BINDER_DEAD
            detail = "The Shizuku service went away. Anything it was tracing died with it; " +
                "pair Shizuku again and reconnect."
        }
    }

    private val permissionResult = Shizuku.OnRequestPermissionResultListener { code, grant ->
        if (code != PERMISSION_REQUEST) return@OnRequestPermissionResultListener
        if (grant == PackageManager.PERMISSION_GRANTED) {
            refresh()
            connect()
        } else {
            onMain {
                stage = ShizukuStage.DENIED
                detail = "Nocturne was refused. Shizuku remembers that, so the next request is " +
                    "silent — grant it from Shizuku's own app screen instead."
            }
        }
    }

    /**
     * Re-derive [stage] from what Shizuku says right now.
     *
     * The order matters. Everything on the Shizuku class throws once the binder
     * is gone, so the binder is checked first and nothing else is asked until
     * it answers.
     */
    fun refresh() {
        val alive = try {
            Shizuku.pingBinder()
        } catch (t: Throwable) {
            false
        }
        val isSui = try {
            Sui.isSui()
        } catch (t: Throwable) {
            false
        }

        if (!alive) {
            val installed = installed()
            onMain {
                sui = isSui
                serverUid = -1
                serverApi = -1
                service = null
                if (installed || isSui) {
                    stage = ShizukuStage.NOT_RUNNING
                    detail = "Shizuku is installed but not running. Open Shizuku and start it — " +
                        "over wireless debugging on Android 11 and up, or with the one adb command " +
                        "it shows you. It has to be started again after every reboot."
                } else {
                    stage = ShizukuStage.NOT_INSTALLED
                    detail = "Shizuku is not installed. It is a separate free app that holds the adb " +
                        "privilege for other apps; Nocturne never needs it to analyse a file, only " +
                        "to run one."
                }
            }
            return
        }

        if (isPreV11()) {
            onMain {
                sui = isSui
                stage = ShizukuStage.UNSUPPORTED
                detail = "This Shizuku server predates API v11. User services need v10 and the " +
                    "permission model needs v11 — update Shizuku."
            }
            return
        }

        val api = intOf { Shizuku.getVersion() }
        val uid = intOf { Shizuku.getUid() }
        if (api in 0..9) {
            onMain {
                sui = isSui
                serverApi = api
                serverUid = uid
                stage = ShizukuStage.UNSUPPORTED
                detail = "Shizuku API $api cannot run a user service; v10 is the minimum. Update Shizuku."
            }
            return
        }

        val granted = try {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        } catch (t: Throwable) {
            false
        }
        if (!granted) {
            val refused = try {
                Shizuku.shouldShowRequestPermissionRationale()
            } catch (t: Throwable) {
                false
            }
            onMain {
                sui = isSui
                serverApi = api
                serverUid = uid
                service = null
                if (refused) {
                    stage = ShizukuStage.DENIED
                    detail = "Nocturne was refused. Shizuku will not ask again — open Shizuku and " +
                        "grant it there."
                } else {
                    stage = ShizukuStage.ASK
                    detail = "Shizuku API $api is running. It has not been asked whether Nocturne " +
                        "may use it."
                }
            }
            return
        }

        val svc = service
        val live = svc != null && try {
            svc.asBinder().pingBinder()
        } catch (t: Throwable) {
            false
        }
        onMain {
            sui = isSui
            serverApi = api
            serverUid = uid
            when {
                live -> {
                    // [handshake] owns the move to BOUND, and only it can: a
                    // binder that answers is not the same thing as an engine
                    // that loaded, and BOUND is what the UI reads as "you can
                    // press Spawn now".
                    if (stage != ShizukuStage.BOUND && stage != ShizukuStage.BIND_FAILED) {
                        stage = ShizukuStage.BINDING
                        detail = "Waiting for the privileged debugger to report in."
                    }
                }

                binding -> {
                    stage = ShizukuStage.BINDING
                    detail = "Starting the privileged debugger process."
                }

                else -> {
                    service = null
                    if (stage != ShizukuStage.BIND_FAILED && stage != ShizukuStage.BINDER_DEAD) {
                        stage = ShizukuStage.GRANTED
                        detail = "Permission granted (Shizuku API $api, uid $uid). The privileged " +
                            "debugger has not been started."
                    }
                }
            }
        }
    }

    /** Ask Shizuku for permission. The answer arrives on [permissionResult]. */
    fun requestPermission() {
        try {
            Shizuku.requestPermission(PERMISSION_REQUEST)
        } catch (t: Throwable) {
            onMain {
                stage = ShizukuStage.NOT_RUNNING
                detail = "Shizuku refused the permission request: " + describe(t)
            }
        }
    }

    /**
     * An intent that opens Shizuku, or the download page when it is not
     * installed. Null only when there is no browser and no Shizuku, which is a
     * state the caller should just not offer a button for.
     */
    fun openIntent(): Intent? {
        val ctx = app ?: return null
        if (installed()) {
            val launch = try {
                ctx.packageManager.getLaunchIntentForPackage(MANAGER_PACKAGE)
            } catch (t: Throwable) {
                null
            }
            if (launch != null) return launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return Intent(Intent.ACTION_VIEW, Uri.parse(DOWNLOAD_URL))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    // --------------------------------------------------- privileged service --

    /**
     * The identity of the user service. `tag` is stable so an obfuscated build
     * cannot silently start a second one; `version` is the app's version code
     * so an update recreates the process rather than talking to yesterday's
     * code, which is a genuinely confusing failure to debug; `daemon(false)`
     * ties its life to ours.
     *
     * `debuggable` is deliberately false even in debug builds. This process
     * owns a ptrace session, and attaching a second debugger to the debugger is
     * not a thing anyone wants by default.
     */
    private val args: Shizuku.UserServiceArgs by lazy {
        Shizuku.UserServiceArgs(
            ComponentName(BuildConfig.APPLICATION_ID, NocturneUserService::class.java.name)
        )
            .daemon(false)
            .processNameSuffix("dbg")
            .debuggable(false)
            .version(BuildConfig.VERSION_CODE)
            .tag("nocturne-dbg")
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            binding = false
            if (binder == null || !binder.pingBinder()) {
                onMain {
                    service = null
                    stage = ShizukuStage.BIND_FAILED
                    detail = "Shizuku started the privileged process but its binder was already " +
                        "dead. Check Shizuku's own log."
                }
                return
            }
            val svc = INocturneService.Stub.asInterface(binder)
            service = svc
            everBound = true
            // The handshake loads libnocturne.so in the other process, which is
            // real work, and this callback is on the main thread.
            Thread({ handshake(svc) }, "nocturne-shizuku-hello").start()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            binding = false
            val had = service != null
            service = null
            onMain {
                serviceLine = ""
                stagedPath = ""
                stagedToken = ""
                if (had || everBound) {
                    stage = ShizukuStage.BINDER_DEAD
                    detail = "The privileged debugger process exited. Anything it was tracing is " +
                        "gone; reconnect to start a new one."
                } else {
                    stage = ShizukuStage.BIND_FAILED
                    detail = "The privileged debugger process exited before it answered."
                }
            }
        }
    }

    /**
     * Start the privileged process, or walk one step towards being able to.
     * Safe to call from any state: it does the next useful thing rather than
     * requiring the caller to know the state machine.
     */
    fun connect() {
        refresh()
        when (stage) {
            ShizukuStage.ASK, ShizukuStage.DENIED -> {
                requestPermission()
                return
            }

            ShizukuStage.NOT_INSTALLED, ShizukuStage.NOT_RUNNING, ShizukuStage.UNSUPPORTED -> return
            ShizukuStage.BOUND, ShizukuStage.BINDING -> return
            else -> Unit
        }
        binding = true
        onMain {
            stage = ShizukuStage.BINDING
            detail = "Starting the privileged debugger process."
        }
        try {
            Shizuku.bindUserService(args, connection)
        } catch (t: Throwable) {
            binding = false
            onMain {
                stage = ShizukuStage.BIND_FAILED
                detail = "Shizuku would not start the service: " + describe(t)
            }
            return
        }
        main.postDelayed({
            if (binding && service == null) {
                binding = false
                stage = ShizukuStage.BIND_FAILED
                detail = "No binder after " + (BIND_TIMEOUT_MS / 1000) + " s. Shizuku could not " +
                    "start the process, or R8 stripped NocturneUserService out of the release " +
                    "build — check Shizuku's log."
            }
        }, BIND_TIMEOUT_MS)
    }

    /**
     * Stop the privileged process. `remove = true` makes Shizuku call
     * destroy() on the service, which is where the staged file is deleted and
     * System.exit is called — without it the process would simply be forgotten
     * about and keep running.
     */
    fun disconnect() {
        // Deliberately no unstage call here. This runs from a button on the
        // main thread, and dbgCmd is a synchronous Binder call into a process
        // that may be sitting in waitpid — blocking the UI to delete a file
        // that destroy() is about to delete anyway would be a bad trade.
        try {
            Shizuku.unbindUserService(args, connection, true)
        } catch (t: Throwable) {
            // Already gone.
        }
        service = null
        binding = false
        everBound = false
        onMain {
            serviceLine = ""
            stagedPath = ""
            stagedToken = ""
            if (stage == ShizukuStage.BOUND) {
                stage = ShizukuStage.GRANTED
                detail = "Privileged debugger stopped."
            }
        }
    }

    /**
     * First contact with the privileged process: report its identity, sweep
     * anything a previous run left in /data/local/tmp, and — the part that
     * decides whether any of this works — find out whether libnocturne.so
     * loaded over there.
     */
    private fun handshake(svc: INocturneService) {
        val answer = try {
            svc.dbgCmd("""{"op":"svc.hello"}""")
        } catch (t: Throwable) {
            onMain {
                service = null
                stage = ShizukuStage.BIND_FAILED
                detail = "The privileged process did not answer: " + describe(t)
            }
            return
        }
        val o = try {
            JSONObject(answer ?: "{}")
        } catch (t: Throwable) {
            JSONObject()
        }
        val uid = o.optInt("uid", -1)
        val machine = o.optString("machine")
        val secontext = o.optString("selinux")
        val err = o.optString("engineError")
        val swept = o.optInt("swept", 0)
        val line = buildString {
            append("uid ").append(uid)
            append(if (uid == 0) " (root)" else " (shell)")
            if (machine.isNotEmpty()) append(" · ").append(machine)
            if (secontext.isNotEmpty()) append(" · ").append(secontext)
            if (swept > 0) append(" · swept ").append(swept).append(" stale file(s)")
        }
        onMain {
            serverUid = if (uid >= 0) uid else serverUid
            serviceLine = line
            if (err.isNotEmpty()) {
                stage = ShizukuStage.BIND_FAILED
                detail = "The privileged process started but the analysis engine did not load in " +
                    "it: " + err + " — see docs/SHIZUKU.md."
            } else {
                stage = ShizukuStage.BOUND
                detail = "Privileged debugger running."
            }
        }
    }

    // --------------------------------------------------------- transport --

    /**
     * Send one debugger command to the privileged process.
     *
     * Blocking; call it off the main thread. It never throws: a dead binder or
     * a stripped interface comes back as `{"ok":false,"error":...}` so the
     * existing parser and the existing event log handle it like any other
     * failed command, and the message says which of the two it was.
     */
    fun cmd(json: String): String {
        val svc = service ?: return errJson(
            "shizuku",
            "no privileged debugger is connected — pick the backend and press Connect"
        )
        return try {
            svc.dbgCmd(json) ?: errJson("shizuku", "the privileged process answered with nothing")
        } catch (dead: DeadObjectException) {
            binderDied()
            errJson("shizuku", "the privileged process died while the command was in flight")
        } catch (t: Throwable) {
            errJson("shizuku", describe(t))
        }
    }

    private fun binderDied() {
        service = null
        onMain {
            serviceLine = ""
            stagedPath = ""
            stagedToken = ""
            stage = ShizukuStage.BINDER_DEAD
            detail = "The privileged debugger process died. Reconnect to start a new one."
        }
    }

    // ----------------------------------------------------------- staging --

    /** What [stageSample] found out. [path] is empty unless [ok]. */
    class Staged(
        val ok: Boolean,
        val path: String,
        val note: String,
        val machine: String
    )

    /**
     * Copy [file] into /data/local/tmp in the privileged process, make it
     * executable, and check it is something that can actually be exec'd.
     *
     * The bytes go over the Binder in [CHUNK]-sized pieces rather than as a
     * path, and that is not a stylistic choice: a shell-uid process cannot read
     * /data/user/0/com.trickhook at all, so there is no path it could open.
     *
     * Blocking; call it off the main thread. A previous staged file is removed
     * first, so the tmp directory holds at most one sample at a time.
     */
    fun stageSample(file: File): Staged {
        val svc = service ?: return Staged(false, "", "no privileged debugger is connected", "")
        if (!file.isFile) return Staged(false, "", file.absolutePath + " is not a file any more", "")
        unstage()
        val begin = try {
            JSONObject(
                svc.dbgCmd(
                    JSONObject()
                        .put("op", "svc.stageBegin")
                        .put("name", file.name)
                        .put("size", file.length())
                        .toString()
                ) ?: "{}"
            )
        } catch (t: Throwable) {
            return Staged(false, "", "staging could not start: " + describe(t), "")
        }
        if (!begin.optBoolean("ok")) {
            return Staged(false, "", begin.optString("error").ifEmpty { "staging was refused" }, "")
        }
        val token = begin.optString("token")
        if (token.isEmpty()) return Staged(false, "", "staging returned no token", "")

        val chunkHeader = svcJson("svc.stageChunk", "token", token)
        try {
            file.inputStream().use { ins ->
                val buf = ByteArray(CHUNK)
                while (true) {
                    val n = ins.read(buf)
                    if (n <= 0) break
                    val payload = if (n == buf.size) buf else buf.copyOf(n)
                    val r = JSONObject(svc.stageChunk(chunkHeader, payload) ?: "{}")
                    if (!r.optBoolean("ok")) {
                        drop(svc, token)
                        return Staged(
                            false, "",
                            r.optString("error").ifEmpty { "a chunk was rejected" }, ""
                        )
                    }
                }
            }
        } catch (t: Throwable) {
            drop(svc, token)
            return Staged(false, "", "the transfer failed: " + describe(t), "")
        }

        val end = try {
            JSONObject(
                svc.dbgCmd(
                    JSONObject()
                        .put("op", "svc.stageEnd")
                        .put("token", token)
                        .put("size", file.length())
                        .toString()
                ) ?: "{}"
            )
        } catch (t: Throwable) {
            drop(svc, token)
            return Staged(false, "", "staging could not finish: " + describe(t), "")
        }
        if (!end.optBoolean("ok")) {
            drop(svc, token)
            return Staged(false, "", end.optString("error").ifEmpty { "staging failed" }, "")
        }
        val path = end.optString("path")
        val machine = end.optString("machine")
        if (!end.optBoolean("runnable", true)) {
            drop(svc, token)
            return Staged(false, "", end.optString("note").ifEmpty { "not runnable here" }, machine)
        }
        stagedToken = token
        onMain { stagedPath = path }
        return Staged(true, path, end.optString("note"), machine)
    }

    /**
     * Delete the staged sample. Called when a session ends and when another is
     * staged, so /data/local/tmp does not accumulate executables — the service
     * also sweeps on connect and on destroy, because neither of those paths can
     * be relied on alone.
     */
    fun unstage() {
        val svc = service ?: return
        val token = stagedToken
        if (token.isEmpty()) return
        stagedToken = ""
        onMain { stagedPath = "" }
        drop(svc, token)
    }

    private fun drop(svc: INocturneService, token: String) {
        try {
            svc.dbgCmd(svcJson("svc.unstage", "token", token))
        } catch (t: Throwable) {
            // The service sweeps on its next connect and on destroy.
        }
    }

    // -------------------------------------------------------------- misc --

    private fun installed(): Boolean {
        val ctx = app ?: return false
        return try {
            ctx.packageManager.getPackageInfo(MANAGER_PACKAGE, 0)
            true
        } catch (t: Throwable) {
            // NameNotFoundException, or the <queries> entry is missing on
            // API 30+ — either way we cannot see it.
            false
        }
    }

    private fun isPreV11(): Boolean = try {
        Shizuku.isPreV11()
    } catch (t: Throwable) {
        false
    }

    private fun intOf(block: () -> Int): Int = try {
        block()
    } catch (t: Throwable) {
        -1
    }

    private fun svcJson(op: String, key: String, value: String): String =
        JSONObject().put("op", op).put(key, value).toString()

    private fun errJson(kind: String, why: String): String =
        JSONObject().put("ok", false).put("error", kind + ": " + why).toString()

    private fun describe(t: Throwable): String {
        val m = t.message
        return if (m.isNullOrBlank()) t.javaClass.simpleName else t.javaClass.simpleName + ": " + m
    }

    private fun onMain(block: () -> Unit) {
        if (Looper.myLooper() === Looper.getMainLooper()) block() else main.post(block)
    }
}
