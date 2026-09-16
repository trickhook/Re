package com.trickhook.mcp

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.trickhook.vm.StudioViewModel
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * NOT AN AI FEATURE.
 *
 * Nothing in this package talks to a language model, holds an API key, or sends
 * a byte of the open binary anywhere on its own. It is the OTHER end of the
 * wire: a control port that an MCP client on a desktop — Claude Desktop, Claude
 * Code, anything that speaks the protocol — can drive the analysis engine
 * through. The model lives in that client, on that machine, and reaches this
 * app only through the typed tools in [McpTools].
 *
 * If you are ever tempted to add an outbound call to a model from in here, that
 * is the line. The in-app assistant was removed deliberately; this exists
 * precisely so it does not have to come back.
 *
 * ---------------------------------------------------------------------------
 *
 * THE THREAT MODEL, because everything below follows from it.
 *
 * This listener binds a real network address by default, so that a desktop can
 * reach it over Wi-Fi with no cable and no platform-tools. That is a different
 * world from a loopback port. On loopback an attacker needed code already
 * running on the device, and the token was a second lock behind that. On a
 * network the token is the ONLY lock, and anyone on the same Wi-Fi can reach
 * the port and start guessing.
 *
 * So: the token is 256 bits from [SecureRandom], minted per start, compared in
 * constant time, never written to disk. Bad tokens are answered slowly, counted
 * and — past [BAD_TOKEN_LIMIT] — the listener shuts itself down, because a
 * sustained run of them means the network is hostile and there is nothing else
 * between an attacker and this port. The traffic itself is plaintext HTTP; see
 * docs/MCP.md for exactly what that means and when to use [MODE_LOOPBACK]
 * instead.
 *
 * ---------------------------------------------------------------------------
 *
 * The state the server, the notification and the sheet all read. It is a
 * singleton because the listener outlives any one composition and is owned by a
 * Service, while the screen that shows it is owned by an Activity.
 *
 * Every field is Compose snapshot state so the sheet redraws itself, and every
 * write is marshalled onto the main thread by [onMain]: the writers are socket
 * threads on `Dispatchers.IO`, and a value a composition reads should change at
 * a frame boundary rather than halfway through one.
 */
object McpRuntime {

    enum class Status { STOPPED, STARTING, RUNNING, FAILED }

    /** One line in the sheet's live log: what the client asked for, and how it went. */
    class CallLog(
        val id: Long,
        val at: Long,
        val tool: String,
        val detail: String,
        val ok: Boolean,
        val ms: Long
    )

    /**
     * The port. Fixed rather than configurable so the URL in the sheet, the QR
     * code and docs/MCP.md are all the same line every time.
     */
    const val PORT: Int = 8765

    /** The one path the server answers on. */
    const val PATH: String = "/mcp"

    /** Bind one named network interface, reachable from the same Wi-Fi. */
    const val MODE_LAN = "lan"

    /** Bind 127.0.0.1 only, reachable through `adb forward` and nothing else. */
    const val MODE_LOOPBACK = "loopback"

    /** Token size. The whole of the security boundary on a network, so: 256 bits. */
    const val TOKEN_BITS = 256

    /**
     * Stop after this long with no request at all.
     *
     * Thirty minutes. An analysis session with an assistant is bursty — a long
     * decompile, then a human reading it, then another burst — so anything much
     * under half an hour would cut real work short, and anything much over it
     * leaves a forgotten listener on a phone that has since walked into a café.
     * The listener is meant to be up while someone is using it and down the
     * rest of the time; this is what enforces that when a person forgets.
     */
    const val IDLE_STOP_MS: Long = 30L * 60L * 1000L

    /**
     * Refused tokens before the listener gives up and shuts down.
     *
     * Twenty. A 256-bit token is not going to be guessed, so this is not about
     * exhausting the keyspace: twenty failures means something on this network
     * is probing the port, and continuing to sit there answering it is the
     * wrong default on a device the user carries around.
     */
    const val BAD_TOKEN_LIMIT: Int = 20

    private const val LOG_LIMIT = 240
    private const val LOG_TRIM = 60

    private val main = Handler(Looper.getMainLooper())
    private val seq = AtomicLong(0L)

    var status by mutableStateOf(Status.STOPPED); private set

    /** Why the last start failed, in words a user can act on. "" when it did not. */
    var failure by mutableStateOf(""); private set

    /** Why the listener stopped by itself, if it did. Cleared on the next start. */
    var stopReason by mutableStateOf(""); private set

    /**
     * The bearer token for the RUNNING server, minted per start. Held in memory
     * only: never written to disk, never logged, cleared when the server stops.
     */
    var token by mutableStateOf(""); private set

    /** [MODE_LAN] or [MODE_LOOPBACK]. Settable only while stopped. */
    var bindMode by mutableStateOf(MODE_LAN); private set

    /** The address actually bound, once running. */
    var host by mutableStateOf(""); private set
    var iface by mutableStateOf(""); private set
    var networkKind by mutableStateOf(""); private set

    /** False when the bound address is routable from the internet. Worth a shout. */
    var privateNetwork by mutableStateOf(true); private set

    /**
     * Read-only mode. True means the three tools that write to the project
     * database are not advertised and cannot be called.
     *
     * Only settable while the server is stopped. The tool list is fixed at start
     * time and a client caches it; flipping the mode underneath a connected
     * client would leave it holding a list that no longer matches the server.
     */
    var readOnly by mutableStateOf(true); private set

    /** Live connections, capped by the server itself. */
    var connections by mutableIntStateOf(0); private set

    /** What the client called itself in `initialize`. Empty until one does. */
    var client by mutableStateOf(""); private set

    /** When the last request of any kind arrived, or 0. */
    var lastRequestAt by mutableLongStateOf(0L); private set

    /** When the listener came up, for the sheet's uptime line. */
    var startedAt by mutableLongStateOf(0L); private set

    var toolCalls by mutableIntStateOf(0); private set

    /**
     * Requests refused before they reached a tool: a missing or wrong bearer
     * token, a foreign Origin, an oversized body. Shown in the sheet because a
     * rising number here is how a user learns that something on this network is
     * knocking on the port.
     */
    var rejected by mutableIntStateOf(0); private set

    val log = mutableStateListOf<CallLog>()

    /**
     * The analysis session the tools operate on. Registered by
     * [StudioViewModel] itself, so its lifetime is exactly the lifetime of the
     * work there is to expose; with no ViewModel attached every tool answers
     * that there is nothing open rather than guessing.
     */
    @Volatile
    var session: StudioViewModel? = null; private set

    private var appContext: Context? = null

    // ---------------------------------------------------------- addresses --

    val running: Boolean get() = status == Status.RUNNING

    /** `http://192.168.1.42:8765/mcp` — what goes in a client config. */
    val url: String get() = if (host.isEmpty()) "" else "http://$host:$PORT$PATH"

    /**
     * What the QR code carries: the URL plus the token in the fragment. A
     * fragment is never sent to a server, so this string is a carrier for the
     * two values a client needs and nothing more.
     */
    val pairingText: String get() = if (url.isEmpty() || token.isEmpty()) "" else "$url#token=$token"

    /** The `adb forward` line, which is only meaningful in loopback mode. */
    val adbForward: String get() = "adb forward tcp:$PORT tcp:$PORT"

    // ------------------------------------------------------------- token --

    /**
     * A fresh [TOKEN_BITS]-bit token from [SecureRandom], base64url without
     * padding — 43 characters, safe in a URL, a header and a shell argument.
     *
     * On a network this is the entire security boundary, which is why it is
     * this large and why it is regenerated on every start rather than stored.
     */
    private fun newToken(): String {
        val raw = ByteArray(TOKEN_BITS / 8)
        SecureRandom().nextBytes(raw)
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val sb = StringBuilder(44)
        var i = 0
        while (i < raw.size) {
            val b0 = raw[i].toInt() and 0xFF
            val b1 = if (i + 1 < raw.size) raw[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < raw.size) raw[i + 2].toInt() and 0xFF else 0
            val n = (b0 shl 16) or (b1 shl 8) or b2
            sb.append(alphabet[(n ushr 18) and 0x3F])
            sb.append(alphabet[(n ushr 12) and 0x3F])
            if (i + 1 < raw.size) sb.append(alphabet[(n ushr 6) and 0x3F])
            if (i + 2 < raw.size) sb.append(alphabet[n and 0x3F])
            i += 3
        }
        return sb.toString()
    }

    // -------------------------------------------------------- lifecycle --

    /** Called by the service before it binds. Returns the token it minted. */
    fun markStarting(context: Context): String {
        val fresh = newToken()
        appContext = context.applicationContext
        onMain {
            status = Status.STARTING
            failure = ""
            stopReason = ""
            token = fresh
            host = ""
            iface = ""
            networkKind = ""
            privateNetwork = true
            connections = 0
            client = ""
            lastRequestAt = 0L
            toolCalls = 0
            rejected = 0
            log.clear()
        }
        return fresh
    }

    fun markRunning(endpoint: McpNetwork.Endpoint) = onMain {
        status = Status.RUNNING
        startedAt = System.currentTimeMillis()
        host = endpoint.host
        iface = endpoint.iface
        networkKind = endpoint.kind
        privateNetwork = endpoint.privateAddress
    }

    fun markFailed(why: String) = onMain {
        status = Status.FAILED
        failure = why
        token = ""
        startedAt = 0L
        connections = 0
    }

    fun markStopped(reason: String) = onMain {
        status = Status.STOPPED
        failure = ""
        stopReason = reason
        token = ""
        startedAt = 0L
        connections = 0
        client = ""
        host = ""
        iface = ""
        networkKind = ""
    }

    /**
     * Read-only is a start-time decision, so this refuses to move while the
     * listener is up. The sheet only offers the row while it is stopped, for
     * the same reason.
     */
    fun applyReadOnly(on: Boolean) = onMain {
        if (status != Status.RUNNING && status != Status.STARTING) readOnly = on
    }

    /** Which address to bind. Also a start-time decision. */
    fun applyBindMode(mode: String) = onMain {
        if (status != Status.RUNNING && status != Status.STARTING) {
            bindMode = if (mode == MODE_LOOPBACK) MODE_LOOPBACK else MODE_LAN
        }
    }

    // ----------------------------------------------------------- traffic --

    fun connectionOpened() = onMain { connections += 1 }

    fun connectionClosed() = onMain { if (connections > 0) connections -= 1 }

    fun sawRequest() = onMain { lastRequestAt = System.currentTimeMillis() }

    fun sawClient(name: String) = onMain { if (name.isNotBlank()) client = name }

    fun refused(why: String) = onMain {
        rejected += 1
        append(CallLog(seq.incrementAndGet(), System.currentTimeMillis(), "refused", why, false, 0L))
    }

    fun called(tool: String, detail: String, ok: Boolean, ms: Long) = onMain {
        toolCalls += 1
        append(CallLog(seq.incrementAndGet(), System.currentTimeMillis(), tool, detail, ok, ms))
    }

    /** A protocol-level event worth showing: initialize, tools/list, a bad method. */
    fun noted(what: String, detail: String) = onMain {
        append(CallLog(seq.incrementAndGet(), System.currentTimeMillis(), what, detail, true, 0L))
    }

    private fun append(line: CallLog) {
        log.add(line)
        // removeRange, never removeFirst(): MutableList.removeFirst resolves to
        // the API 35 java.util.List method and throws NoSuchMethodError on every
        // device below it. Same rule as the console in StudioViewModel.
        if (log.size > LOG_LIMIT) log.removeRange(0, LOG_TRIM)
    }

    // ----------------------------------------------------------- session --

    fun attach(vm: StudioViewModel) {
        session = vm
    }

    /**
     * The analysis session went away, which means the Activity was finished.
     * Nothing can be analysed and nobody can read the token off a screen that
     * no longer exists, so the listener goes down with it rather than sitting
     * on a network port waiting for a client it can only disappoint.
     */
    fun detach(vm: StudioViewModel) {
        if (session !== vm) return
        session = null
        val ctx = appContext
        if (ctx != null && status != Status.STOPPED) {
            McpService.stop(ctx, "Nocturne's analysis screen was closed")
        }
    }

    private fun onMain(block: () -> Unit) {
        if (Looper.myLooper() === Looper.getMainLooper()) block() else main.post(block)
    }
}
