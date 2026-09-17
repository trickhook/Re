package com.trickhook.mcp

import com.trickhook.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicInteger

/**
 * The listener: HTTP/1.1 framing by hand over a [ServerSocket], JSON-RPC 2.0 on
 * top of it, and MCP's Streamable HTTP shape on top of that.
 *
 * TRANSPORT. Streamable HTTP, not the deprecated HTTP+SSE transport, because it
 * is what the clients people actually use accept: Claude Code speaks it
 * natively (`claude mcp add --transport http …`), and Claude Desktop reaches it
 * through `mcp-remote`, which proxies stdio to Streamable HTTP. Implementing
 * the deprecated transport as well would mean a second endpoint and a permanent
 * server-to-client stream for no client that needs one.
 *
 * Every answer this server produces is immediate, so POST replies with
 * `application/json` rather than opening an SSE stream, and GET — the
 * spec's optional server-to-client stream — answers 405, which the
 * specification names as the correct reply from a server that does not offer
 * one.
 *
 * SECURITY. This can be asked to bind a real network interface — [McpRuntime]
 * defaults to loopback but [McpRuntime.MODE_LAN] is one tap away, and in that
 * mode the controls here are the only thing between an attacker on the same
 * Wi-Fi and the analysis engine. So none of them is conditional on the mode:
 *
 *  - one bound address, never 0.0.0.0, chosen by [McpNetwork]
 *  - a 256-bit bearer token on every single request, compared in constant time
 *  - a growing delay per failed token, a per-address block after
 *    [ADDRESS_BLOCK_AT] failures, and a shutdown of the whole listener after
 *    [McpRuntime.BAD_TOKEN_LIMIT]
 *  - `Origin` rejected unless it is loopback or this device, so a page in a
 *    browser on this network cannot reach the port by rebinding DNS
 *  - [MAX_BODY] on a request body, [MAX_CONNECTIONS] at once, [IDLE_MS] on an
 *    idle connection, and a whole-listener idle stop in the watchdog
 */
class McpServer(
    private val endpoint: McpNetwork.Endpoint,
    private val token: String,
    allowWrites: Boolean,
    private val onSelfStop: (String) -> Unit
) {

    companion object {
        /** Protocol revisions this server will negotiate, newest first. */
        private val PROTOCOL_VERSIONS = listOf(
            "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"
        )

        private const val MAX_BODY = 1 shl 20
        private const val MAX_HEADERS = 64
        private const val MAX_HEADER_BYTES = 32 * 1024
        private const val MAX_LINE = 8 * 1024
        private const val MAX_CONNECTIONS = 4
        private const val MAX_REQUESTS_PER_CONNECTION = 512
        private const val BACKLOG = 8

        /** A connection with nothing to say for this long is closed. */
        private const val IDLE_MS = 30_000

        /** Failures from one address before it is refused outright. */
        private const val ADDRESS_BLOCK_AT = 6

        /** Base delay per failed token; multiplied by the failure count. */
        private const val AUTH_FAIL_DELAY_MS = 300L
        private const val AUTH_FAIL_DELAY_MAX_MS = 5_000L

        /** How often the watchdog looks at the clock. */
        private const val WATCHDOG_TICK_MS = 30_000L
    }

    private val tools = McpTools(allowWrites)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val slots = Semaphore(MAX_CONNECTIONS)
    private val badTokens = AtomicInteger(0)
    private val failuresByAddress = HashMap<String, Int>()

    /** SHA-256 of the real token, so the comparison is over fixed-length input. */
    private val tokenDigest = sha256(token)

    private var server: ServerSocket? = null

    @Volatile private var closed = false
    @Volatile private var sessionId: String? = null
    @Volatile private var lastActivity = System.currentTimeMillis()

    /**
     * Bind and start accepting. Throws when the address is gone or the port is
     * taken, which the service turns into a sentence the user can act on.
     * Call from `Dispatchers.IO`.
     */
    fun start() {
        val socket = ServerSocket(McpRuntime.PORT, BACKLOG, endpoint.address)
        server = socket
        lastActivity = System.currentTimeMillis()
        scope.launch { acceptLoop(socket) }
        scope.launch { watchdog() }
    }

    fun stop() {
        closed = true
        try {
            server?.close()
        } catch (e: Exception) {
            // Closing the listening socket is what unblocks accept(); a failure
            // here only means it was already shut.
        }
        server = null
        scope.cancel()
    }

    // ------------------------------------------------------------ accept --

    private fun acceptLoop(listening: ServerSocket) {
        var consecutiveFailures = 0
        while (!closed) {
            val socket = try {
                listening.accept()
            } catch (e: Exception) {
                if (closed || listening.isClosed) return
                consecutiveFailures += 1
                if (consecutiveFailures >= 10) {
                    onSelfStop("the listening socket stopped accepting connections")
                    return
                }
                continue
            }
            consecutiveFailures = 0
            if (closed) {
                closeQuietly(socket)
                return
            }
            val remote = socket.inetAddress?.hostAddress ?: "?"
            if (blockedAddress(remote)) {
                McpRuntime.refused("$remote is blocked after repeated bad tokens")
                closeQuietly(socket)
                continue
            }
            if (!slots.tryAcquire()) {
                McpRuntime.refused("more than $MAX_CONNECTIONS connections at once")
                try {
                    writeResponse(
                        socket.getOutputStream(),
                        errorResponse(503, "Service Unavailable", "too many connections")
                    )
                } catch (e: Exception) {
                    // The peer is already gone; nothing to say to it.
                }
                closeQuietly(socket)
                continue
            }
            McpRuntime.connectionOpened()
            scope.launch {
                try {
                    serve(socket, remote)
                } catch (e: Exception) {
                    // A dropped connection is ordinary. Nothing here should take
                    // the listener down with it.
                } finally {
                    closeQuietly(socket)
                    slots.release()
                    McpRuntime.connectionClosed()
                }
            }
        }
    }

    private suspend fun watchdog() {
        while (!closed) {
            delay(WATCHDOG_TICK_MS)
            if (closed) return
            val idle = System.currentTimeMillis() - lastActivity
            if (idle >= McpRuntime.IDLE_STOP_MS) {
                onSelfStop("nothing connected for ${McpRuntime.IDLE_STOP_MS / 60000} minutes")
                return
            }
        }
    }

    // ----------------------------------------------------------- connection --

    private suspend fun serve(socket: Socket, remote: String) {
        socket.soTimeout = IDLE_MS
        socket.tcpNoDelay = true
        val input = BufferedInputStream(socket.getInputStream(), 8192)
        val output = BufferedOutputStream(socket.getOutputStream(), 8192)
        var served = 0
        while (!closed && served < MAX_REQUESTS_PER_CONNECTION) {
            var incoming: Request? = null
            try {
                incoming = readRequest(input)
            } catch (e: TooBig) {
                writeResponse(output, errorResponse(413, "Payload Too Large", e.message ?: "too large"))
                McpRuntime.refused(e.message ?: "oversized request")
                return
            } catch (e: Exception) {
                // Read timeout, reset, or a peer that hung up mid-request.
                return
            }
            // Null is a clean end of stream: the client closed a keep-alive
            // connection it was finished with.
            val request = incoming ?: return

            lastActivity = System.currentTimeMillis()
            McpRuntime.sawRequest()
            val response = authorize(request, remote) ?: handle(request)
            writeResponse(output, response)
            served += 1
            if (response.close) return
        }
    }

    /** Null when the request may proceed; a 401/403 response when it may not. */
    private suspend fun authorize(request: Request, remote: String): Response? {
        val origin = request.header("origin")
        if (origin != null && !allowedOrigin(origin)) {
            McpRuntime.refused("Origin $origin refused")
            return errorResponse(
                403, "Forbidden",
                "this server answers MCP clients, not browsers on this network"
            )
        }
        if (tokenOk(request.header("authorization"))) {
            synchronized(failuresByAddress) { failuresByAddress.remove(remote) }
            return null
        }
        val failures = synchronized(failuresByAddress) {
            val n = (failuresByAddress[remote] ?: 0) + 1
            failuresByAddress[remote] = n
            n
        }
        val total = badTokens.incrementAndGet()
        McpRuntime.refused(
            (if (request.header("authorization") == null) "no bearer token from " else "wrong token from ") +
                remote + " (" + failures + ")"
        )
        // A growing pause on every failure. The token cannot be guessed at 256
        // bits, so this is not about the keyspace — it is about making a
        // sustained probe slow, quiet and visible rather than free.
        delay(minOf(AUTH_FAIL_DELAY_MS * failures, AUTH_FAIL_DELAY_MAX_MS))
        if (total >= McpRuntime.BAD_TOKEN_LIMIT) {
            onSelfStop("$total requests arrived with a bad token — the network is not friendly")
        }
        val body = jsonBody(
            JSONObject().put(
                "error",
                JSONObject().put("code", -32001).put(
                    "message",
                    "Unauthorized. Send the bearer token Nocturne is showing on the device."
                )
            )
        )
        return Response(
            401, "Unauthorized", body, "application/json",
            listOf(Pair("WWW-Authenticate", "Bearer realm=\"nocturne\"")), true
        )
    }

    private fun blockedAddress(remote: String): Boolean =
        synchronized(failuresByAddress) { (failuresByAddress[remote] ?: 0) >= ADDRESS_BLOCK_AT }

    /**
     * Constant-time bearer check.
     *
     * Both sides are hashed first so the comparison runs over two 32-byte
     * arrays whatever was presented: [MessageDigest.isEqual] is time-constant
     * for equal-length input, and hashing means the LENGTH of the guess leaks
     * nothing either.
     */
    private fun tokenOk(header: String?): Boolean {
        if (header == null) return false
        if (header.length < 8) return false
        if (!header.regionMatches(0, "Bearer ", 0, 7, ignoreCase = true)) return false
        val presented = header.substring(7).trim()
        return MessageDigest.isEqual(sha256(presented), tokenDigest)
    }

    private fun allowedOrigin(origin: String): Boolean {
        val o = origin.trim().lowercase()
        if (o == "null") return false
        val hostPart = o.removePrefix("http://").removePrefix("https://").substringBefore('/')
        val bare = hostPart.substringBefore(':')
        return bare == "127.0.0.1" || bare == "localhost" || bare == "[::1]" ||
            bare == endpoint.host
    }

    // -------------------------------------------------------------- HTTP --

    private class Request(
        val method: String,
        val path: String,
        private val headers: Map<String, String>,
        val body: ByteArray
    ) {
        fun header(name: String): String? = headers[name]
    }

    private class Response(
        val status: Int,
        val reason: String,
        val body: ByteArray,
        val contentType: String?,
        val extra: List<Pair<String, String>>,
        val close: Boolean
    )

    private class TooBig(message: String) : Exception(message)

    private fun readRequest(input: InputStream): Request? {
        val line = readLine(input) ?: return null
        if (line.isEmpty()) return null
        val parts = line.split(' ')
        // A request line this server cannot parse is not worth a reply: close.
        if (parts.size < 2) return null
        val method = parts[0].uppercase()
        val path = parts[1].substringBefore('?')
        val headers = HashMap<String, String>()
        var headerBytes = 0
        while (true) {
            val h = readLine(input) ?: return null
            if (h.isEmpty()) break
            headerBytes += h.length
            if (headers.size >= MAX_HEADERS || headerBytes > MAX_HEADER_BYTES) {
                throw TooBig("too many request headers")
            }
            val colon = h.indexOf(':')
            if (colon <= 0) continue
            headers[h.substring(0, colon).trim().lowercase()] = h.substring(colon + 1).trim()
        }
        if (headers.containsKey("transfer-encoding")) {
            // No chunked decoder here on purpose. Every MCP client sends a
            // JSON string body with a Content-Length; anything else is either a
            // mistake or someone poking at the parser.
            throw TooBig("chunked request bodies are not accepted — send Content-Length")
        }
        // Parsed as a Long and checked against the cap before it becomes an Int:
        // a length above Int.MAX_VALUE would otherwise read back as "no body"
        // and leave the real bytes to be mistaken for the next request.
        val header = headers["content-length"]
        val declaredLong = if (header == null) 0L
        else header.toLongOrNull() ?: throw TooBig("Content-Length is not a number")
        if (declaredLong < 0L || declaredLong > MAX_BODY.toLong()) {
            throw TooBig("request body over ${MAX_BODY / 1024} KiB")
        }
        val declared = declaredLong.toInt()
        val body = ByteArray(declared)
        var off = 0
        while (off < declared) {
            val n = input.read(body, off, declared - off)
            if (n < 0) return null
            off += n
        }
        return Request(method, path, headers, body)
    }

    private fun readLine(input: InputStream): String? {
        val buf = ByteArrayOutputStream(128)
        while (true) {
            val b = input.read()
            if (b < 0) return if (buf.size() == 0) null else buf.toString("ISO-8859-1")
            if (b == 10) {
                var s = buf.toString("ISO-8859-1")
                if (s.endsWith("\r")) s = s.substring(0, s.length - 1)
                return s
            }
            buf.write(b)
            if (buf.size() > MAX_LINE) throw TooBig("request header line too long")
        }
    }

    private fun writeResponse(out: OutputStream, r: Response) {
        val head = StringBuilder(256)
        head.append("HTTP/1.1 ").append(r.status).append(' ').append(r.reason).append("\r\n")
        if (r.status != 204) {
            if (r.contentType != null) head.append("Content-Type: ").append(r.contentType).append("\r\n")
            head.append("Content-Length: ").append(r.body.size).append("\r\n")
        }
        head.append("Cache-Control: no-store\r\n")
        head.append("X-Content-Type-Options: nosniff\r\n")
        // No Access-Control-Allow-Origin, deliberately: a browser must not be
        // able to script this port, and the absence of CORS headers is what
        // stops it.
        for ((k, v) in r.extra) head.append(k).append(": ").append(v).append("\r\n")
        head.append("Connection: ").append(if (r.close) "close" else "keep-alive").append("\r\n")
        head.append("\r\n")
        out.write(head.toString().toByteArray(Charsets.ISO_8859_1))
        if (r.status != 204 && r.body.isNotEmpty()) out.write(r.body)
        out.flush()
    }

    private fun handle(request: Request): Response {
        if (request.path != McpRuntime.PATH && request.path != "/") {
            return errorResponse(404, "Not Found", "this server answers on ${McpRuntime.PATH}")
        }
        val declared = request.header("mcp-protocol-version")
        if (declared != null && declared.isNotEmpty() && declared !in PROTOCOL_VERSIONS) {
            return errorResponse(
                400, "Bad Request",
                "unsupported MCP-Protocol-Version \"$declared\" — this server speaks " +
                    PROTOCOL_VERSIONS.joinToString(", ")
            )
        }
        return when (request.method) {
            "POST" -> post(request)
            // The spec's optional server-to-client stream. Every answer here is
            // immediate, so there is nothing to stream, and 405 is what the
            // specification says a server without one must reply.
            "GET" -> errorResponse(
                405, "Method Not Allowed",
                "no server-to-client stream on this endpoint; POST JSON-RPC to ${McpRuntime.PATH}"
            ).withHeader("Allow", "POST, DELETE")

            "DELETE" -> {
                sessionId = null
                Response(204, "No Content", ByteArray(0), null, emptyList(), false)
            }

            else -> errorResponse(405, "Method Not Allowed", "use POST")
                .withHeader("Allow", "POST, DELETE")
        }
    }

    private fun Response.withHeader(name: String, value: String): Response =
        Response(status, reason, body, contentType, extra + Pair(name, value), close)

    private fun post(request: Request): Response {
        val presentedSession = request.header("mcp-session-id")
        val known = sessionId
        val text = String(request.body, Charsets.UTF_8)
        val trimmed = text.trim()
        if (trimmed.isEmpty()) {
            return jsonResponse(rpcError(JSONObject.NULL, -32700, "empty request body"))
        }

        val isInitialize = trimmed.contains("\"initialize\"")
        if (!isInitialize && known != null && presentedSession != null && presentedSession != known) {
            // The spec's answer for a session the server no longer holds: the
            // client is expected to start a new one.
            return errorResponse(404, "Not Found", "unknown Mcp-Session-Id; send initialize again")
        }

        val parsed: Any = try {
            if (trimmed.startsWith("[")) JSONArray(trimmed) else JSONObject(trimmed)
        } catch (e: Exception) {
            return jsonResponse(rpcError(JSONObject.NULL, -32700, "the body is not valid JSON"))
        }

        val headers = ArrayList<Pair<String, String>>()
        if (parsed is JSONArray) {
            // Batching left the specification in 2025-06-18, but an older client
            // may still send an array; answering one correctly costs nothing.
            val out = JSONArray()
            for (i in 0 until parsed.length()) {
                val item = parsed.optJSONObject(i) ?: continue
                val reply = message(item, headers)
                if (reply != null) out.put(reply)
            }
            if (out.length() == 0) return accepted()
            return jsonResponse(out.toString().toByteArray(Charsets.UTF_8), headers)
        }
        val reply = message(parsed as JSONObject, headers) ?: return accepted(headers)
        return jsonResponse(reply.toString().toByteArray(Charsets.UTF_8), headers)
    }

    /** Null when the message was a notification or a response — nothing to reply. */
    private fun message(o: JSONObject, headers: ArrayList<Pair<String, String>>): JSONObject? {
        val method = o.optString("method", "")
        if (method.isEmpty()) {
            // A response to a request this server never sends. Acknowledged and
            // dropped, which is what the spec asks for.
            return null
        }
        val hasId = o.has("id") && !o.isNull("id")
        val id: Any = if (hasId) o.get("id") else JSONObject.NULL
        if (!hasId) {
            if (method == "notifications/initialized") {
                McpRuntime.noted("initialized", "client finished the handshake")
            }
            return null
        }
        return when (method) {
            "initialize" -> initialize(o, id, headers)
            "ping" -> rpcResult(id, JSONObject())
            "tools/list" -> {
                McpRuntime.noted("tools/list", "${tools.names().size} tools offered")
                rpcResult(id, JSONObject().put("tools", tools.listJson()))
            }

            "tools/call" -> call(o, id)
            // Not advertised in `capabilities`, so a conforming client will not
            // ask. Some clients probe anyway; an empty list is a quieter answer
            // than an error and claims nothing that is not true.
            "resources/list" -> rpcResult(id, JSONObject().put("resources", JSONArray()))
            "resources/templates/list" ->
                rpcResult(id, JSONObject().put("resourceTemplates", JSONArray()))

            "prompts/list" -> rpcResult(id, JSONObject().put("prompts", JSONArray()))
            else -> {
                McpRuntime.noted("unknown method", method)
                rpcErrorObject(id, -32601, "this server has no method \"$method\"")
            }
        }
    }

    private fun initialize(
        o: JSONObject,
        id: Any,
        headers: ArrayList<Pair<String, String>>
    ): JSONObject {
        val params = o.optJSONObject("params")
        val asked = params?.optString("protocolVersion", "") ?: ""
        val negotiated = if (asked in PROTOCOL_VERSIONS) asked else PROTOCOL_VERSIONS[0]
        val info = params?.optJSONObject("clientInfo")
        val clientName = info?.optString("name", "") ?: ""
        val clientVersion = info?.optString("version", "") ?: ""
        McpRuntime.sawClient((clientName + " " + clientVersion).trim())
        McpRuntime.noted("initialize", "${clientName.ifEmpty { "a client" }} · MCP $negotiated")

        val fresh = newSessionId()
        sessionId = fresh
        headers.add(Pair("Mcp-Session-Id", fresh))

        val result = JSONObject()
            .put("protocolVersion", negotiated)
            .put(
                "capabilities",
                JSONObject().put("tools", JSONObject().put("listChanged", false))
            )
            .put(
                "serverInfo",
                JSONObject()
                    .put("name", "nocturne")
                    .put("title", "Nocturne")
                    .put("version", BuildConfig.VERSION_NAME)
            )
            .put("instructions", INSTRUCTIONS)
        return rpcResult(id, result)
    }

    private fun call(o: JSONObject, id: Any): JSONObject {
        val params = o.optJSONObject("params") ?: JSONObject()
        val name = params.optString("name", "")
        val args = params.optJSONObject("arguments") ?: JSONObject()
        if (!tools.has(name)) {
            val why = if (tools.hiddenByReadOnly(name)) {
                "\"$name\" writes to the project and this server was started read-only. " +
                    "The user can stop it, clear read-only in Nocturne's MCP sheet and start it again."
            } else {
                "no tool named \"$name\" — call tools/list"
            }
            McpRuntime.called(name.ifEmpty { "tools/call" }, why, false, 0L)
            return rpcErrorObject(id, -32602, why)
        }
        val started = System.currentTimeMillis()
        return try {
            val outcome = tools.invoke(name, args)
            val ms = System.currentTimeMillis() - started
            McpRuntime.called(name, outcome.summary, true, ms)
            // Compact JSON, not pretty-printed: this text lands in a model's
            // context and indentation is a third of it spent on whitespace.
            rpcResult(
                id,
                JSONObject()
                    .put("content", JSONArray().put(textContent(outcome.body.toString())))
                    .put("isError", false)
            )
        } catch (e: McpTools.Failure) {
            val ms = System.currentTimeMillis() - started
            val why = e.message ?: "the tool failed"
            McpRuntime.called(name, why, false, ms)
            // A tool that could not do its job is a RESULT with isError, not a
            // protocol error: the model is supposed to read it and try
            // something else.
            rpcResult(
                id,
                JSONObject()
                    .put("content", JSONArray().put(textContent(why)))
                    .put("isError", true)
            )
        } catch (e: Exception) {
            val ms = System.currentTimeMillis() - started
            val why = "the engine failed: " + (e.message ?: e.javaClass.simpleName)
            McpRuntime.called(name, why, false, ms)
            rpcResult(
                id,
                JSONObject()
                    .put("content", JSONArray().put(textContent(why)))
                    .put("isError", true)
            )
        }
    }

    private fun textContent(text: String): JSONObject =
        JSONObject().put("type", "text").put("text", text)

    // ------------------------------------------------------------ plumbing --

    private fun rpcResult(id: Any, result: JSONObject): JSONObject =
        JSONObject().put("jsonrpc", "2.0").put("id", id).put("result", result)

    private fun rpcErrorObject(id: Any, code: Int, message: String): JSONObject =
        JSONObject().put("jsonrpc", "2.0").put("id", id)
            .put("error", JSONObject().put("code", code).put("message", message))

    private fun rpcError(id: Any, code: Int, message: String): ByteArray =
        rpcErrorObject(id, code, message).toString().toByteArray(Charsets.UTF_8)

    private fun jsonBody(o: JSONObject): ByteArray = o.toString().toByteArray(Charsets.UTF_8)

    private fun jsonResponse(
        body: ByteArray,
        extra: List<Pair<String, String>> = emptyList()
    ): Response = Response(200, "OK", body, "application/json", extra, false)

    private fun accepted(extra: List<Pair<String, String>> = emptyList()): Response =
        Response(202, "Accepted", ByteArray(0), null, extra, false)

    private fun errorResponse(status: Int, reason: String, message: String): Response {
        val body = jsonBody(
            JSONObject().put("error", JSONObject().put("message", message))
        )
        return Response(status, reason, body, "application/json", emptyList(), true)
    }

    private fun closeQuietly(socket: Socket) {
        try {
            socket.close()
        } catch (e: Exception) {
            // Already closed, or the peer vanished. Either way there is nothing
            // left to do with it.
        }
    }

    private fun newSessionId(): String {
        val raw = ByteArray(16)
        SecureRandom().nextBytes(raw)
        val sb = StringBuilder(32)
        for (b in raw) {
            val v = b.toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4])
            sb.append("0123456789abcdef"[v and 0xF])
        }
        return sb.toString()
    }

    private fun sha256(text: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
}

/**
 * What the client is told at `initialize`, and therefore what a model reads
 * before it calls anything. Ground rules first, because every one of them is a
 * mistake it would otherwise make.
 */
private val INSTRUCTIONS = """
Nocturne is a reverse-engineering studio running on an Android device. These
tools drive its analysis engine on ONE binary: the file the person holding the
phone has already opened in the app. There is no tool that opens a file and none
that takes a filesystem path, by design — if you need a different binary, ask the
user to open it on the device.

Start with analysis_overview. It tells you the format, the architecture and how
much of everything there is. Then triage for one orientation pass — imports
grouped by interest, the hottest functions, the most notable strings — which is
the fastest way to decide where to dig.

Addresses are hex strings, with or without 0x ("0x2a10" or "2a10"). Take them
from list_functions rather than inventing them. An address inside a function
body resolves to the function that contains it and the answer says so.

Every list is paginated and every list answer carries total, count and
nextOffset. This binary can hold well over a thousand functions and twelve
thousand call edges: page deliberately, and filter with `query` rather than
raising `limit` and reading the lot.

A large binary keeps most of its functions unloaded, and list_functions searches
only the loaded ones by default — its answer says how many it did not see. Pass
scope="all" to walk or search the WHOLE function list straight from the engine,
and decompile_functions to pull a batch of functions' pseudo-C in one call
instead of one round trip each.

decompile_function with the Ghidra backend can take several seconds. xrefs runs
the same engine pass — use call_graph when you want to walk many functions
cheaply.

Renames, comments and bookmarks are stored in Nocturne's own project database
and never modify the binary on disk. They may not be offered at all: the user
can start this server read-only, and then only the reading tools exist.
""".trimIndent()
