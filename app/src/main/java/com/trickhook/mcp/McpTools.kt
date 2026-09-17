package com.trickhook.mcp

import com.trickhook.engine.NativeBridge
import com.trickhook.model.AnalysisMeta
import com.trickhook.model.CallEdge
import com.trickhook.model.FoundStr
import com.trickhook.model.FuncInfo
import com.trickhook.model.FunctionDetail
import com.trickhook.model.Detection
import com.trickhook.model.parseAddressXrefs
import com.trickhook.model.parseDetail
import com.trickhook.model.parseDetections
import com.trickhook.model.parseDexMethodXrefs
import com.trickhook.model.parseDexStrings
import com.trickhook.model.parseFunctionPage
import com.trickhook.model.parseSmali
import com.trickhook.ui.parseAddr
import com.trickhook.ui.xrefRows
import com.trickhook.vm.StudioViewModel
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.locks.ReentrantLock

/**
 * The tool surface an MCP client sees, and the only way into this app from the
 * outside.
 *
 * Two rules shape every tool in here.
 *
 * ONE: nothing takes a filesystem path. Every tool works on the binary the user
 * has already opened in the app, through the ViewModel and the JNI bridge. A
 * client cannot name a file, cannot open one, and cannot reach anything the
 * person holding the phone has not already chosen to look at. There is
 * deliberately no `open_file` tool — opening goes through the app's SAF picker,
 * where a human is the one choosing.
 *
 * TWO: every list is bounded. A binary here routinely carries 1,300+ functions
 * and 12,000+ call edges; a tool that answers with all of them has spent a
 * client's whole context on data nobody read. Each list tool takes `offset` and
 * `limit`, and every list answer carries `total`, `count` and `nextOffset` so
 * the model can page deliberately instead of guessing. Reaching the whole
 * binary and keeping answers bounded are not in tension: `list_functions`
 * scope=all and `decompile_functions` page the engine's entire function list
 * one bounded window at a time, so every function is in reach without any one
 * answer being unbounded.
 *
 * The three tools that write — [RENAME], [COMMENT], [BOOKMARK] — are separated
 * from the rest by [Tool.write] and are neither advertised nor callable unless
 * the user cleared read-only mode before starting the server. They write to
 * Nocturne's project database only; the binary on disk is never modified by
 * anything in this file.
 */
class McpTools(allowWrites: Boolean) {

    class Failure(message: String) : Exception(message)

    /** What one tool call produced: the JSON body, and a line for the sheet's log. */
    class Outcome(val body: JSONObject, val summary: String)

    private class Tool(
        val name: String,
        val title: String,
        val description: String,
        val schema: JSONObject,
        val write: Boolean,
        val handler: (JSONObject) -> Outcome
    )

    companion object {
        const val RENAME = "rename_function"
        const val COMMENT = "set_comment"
        const val BOOKMARK = "add_bookmark"

        /** Pseudo-C for one function, in characters. Well above any real function. */
        private const val PSEUDO_CAP = 60000

        /** Bytes one read_memory call may return. */
        private const val HEX_CAP = 4096

        /** Instructions one disassemble_function call may return. */
        private const val ASM_CAP = 400

        /**
         * Functions one whole-binary page (list_functions scope=all,
         * decompile_functions in range mode) may name. The engine's own
         * nativeFunctionPage allows far more; this is the cap that keeps one
         * answer readable in a client's transcript.
         */
        private const val WALK_CAP = 200

        /** Functions one decompile_functions call may decompile. */
        private const val BATCH_MAX = 20

        /**
         * Total pseudo-C a decompile_functions call may accumulate across the
         * whole batch. Each row is still capped at [PSEUDO_CAP]; this bounds the
         * sum so a handful of large functions cannot fill a client's context in
         * one call. Reported back as `stoppedForSize` with the offset to resume.
         */
        private const val BATCH_PSEUDO_CAP = 100000

        /**
         * Import-name substrings that put an import in a triage bucket, matched
         * case-insensitively. The crypto and anti-debug needles follow the
         * bundled crypto-finder and anti-debug-scanner plugins; the rest are the
         * obvious libc, TLS and loader entry points for each area. A match is a
         * lead to look at, not proof — an import can fall in more than one
         * bucket, and each bucket reports how many matched against the total.
         */
        private val TRIAGE_IMPORTS: List<Pair<String, List<String>>> = listOf(
            "crypto" to listOf(
                "aes", "sha1", "sha256", "sha512", "sha3", "md5", "rc4", "des_",
                "3des", "rsa", "hmac", "crypt", "cipher", "evp_", "chacha",
                "poly1305", "blowfish", "curve25519", "ed25519", "ecdsa", "ecdh",
                "bn_", "base64", "pbkdf", "scrypt", "argon2", "drbg"
            ),
            "antiDebug" to listOf(
                "ptrace", "getppid", "sysconf", "prctl", "personality", "kill"
            ),
            "jni" to listOf(
                "jni", "java_", "registernatives", "getjavavm", "findclass"
            ),
            "networking" to listOf(
                "socket", "connect", "getaddrinfo", "gethostbyname", "inet_",
                "recv", "send", "htons", "htonl", "ntoh", "ssl_", "mbedtls",
                "gnutls", "openssl", "curl_", "sendto", "recvfrom", "getsockopt",
                "setsockopt"
            ),
            "processExec" to listOf(
                "execve", "execl", "execv", "execvp", "posix_spawn", "fork",
                "vfork", "system", "popen", "waitpid", "wait4", "clone",
                "dlopen", "dlsym", "syscall"
            )
        )

        /** A printf-style conversion, the mark of a format string. */
        private val FORMAT_SPEC = Regex("%[#0-9.+ lhLzjt-]*[diouxXeEfgGaAcspn]")

        /** A run that reads as an embedded key or hash: long, all hex or all base64. */
        private val HEX_BLOB = Regex("^[0-9a-fA-F]{16,}$")
        private val BASE64_BLOB = Regex("^[A-Za-z0-9+/]{24,}={0,2}$")

        /**
         * One engine call at a time.
         *
         * The decompiler backend is a single global inside the engine — the
         * `backend` argument flips it and puts it back — and the native
         * analysis is shared mutable state. Serialising the MCP side means two
         * concurrent clients cannot interleave a flip with a decompile. The
         * app's own UI can still issue a call of its own; that is pre-existing
         * behaviour and not something this file can fix from here.
         */
        private val engineLock = ReentrantLock()

        private fun hx(v: Long): String = "0x" + java.lang.Long.toHexString(v)

        /** The key format ProjectDb and StudioViewModel use for annotations. */
        private fun annotationKey(addr: Long): String = "0x%08X".format(addr)
    }

    // ------------------------------------------------------------ schemas --

    private fun strProp(desc: String): JSONObject =
        JSONObject().put("type", "string").put("description", desc)

    private fun enumProp(desc: String, values: List<String>, def: String): JSONObject =
        JSONObject().put("type", "string").put("description", desc)
            .put("enum", JSONArray(values)).put("default", def)

    private fun intProp(desc: String, min: Int, max: Int, def: Int): JSONObject =
        JSONObject().put("type", "integer").put("description", desc)
            .put("minimum", min).put("maximum", max).put("default", def)

    private fun boolProp(desc: String, def: Boolean): JSONObject =
        JSONObject().put("type", "boolean").put("description", desc).put("default", def)

    private fun strListProp(desc: String): JSONObject =
        JSONObject().put("type", "array").put("description", desc)
            .put("items", JSONObject().put("type", "string"))

    private fun offsetProp(): JSONObject =
        JSONObject().put("type", "integer")
            .put("description", "Rows to skip. Pass the previous answer's nextOffset to continue.")
            .put("minimum", 0).put("default", 0)

    private fun limitProp(def: Int, max: Int): JSONObject =
        intProp("Rows to return. The answer carries total, count and nextOffset.", 1, max, def)

    private fun schema(required: List<String>, props: List<Pair<String, JSONObject>>): JSONObject {
        val p = JSONObject()
        for ((k, v) in props) p.put(k, v)
        val s = JSONObject().put("type", "object").put("properties", p)
        if (required.isNotEmpty()) s.put("required", JSONArray(required))
        s.put("additionalProperties", false)
        return s
    }

    private val addressProp = strProp(
        "Address in hex, with or without a 0x prefix (\"0x2a10\", \"2a10\"). " +
            "Take it from list_functions. An address inside a function body resolves " +
            "to the function that contains it, and the answer says so."
    )

    // ------------------------------------------------------------ session --

    private fun session(): StudioViewModel = McpRuntime.session
        ?: throw Failure(
            "Nocturne's analysis session is not open — its main screen has been closed on " +
                "the device. Reopen the app and the server picks the session back up."
        )

    private fun openMeta(): AnalysisMeta {
        val m = session().meta
            ?: throw Failure(
                "No binary is open in Nocturne. Open one on the device (overflow menu, " +
                    "\"Open binary…\"). For safety no tool here can open a file itself — " +
                    "the person holding the phone chooses what is exposed."
            )
        if (!m.ok) throw Failure(m.error ?: "the open file did not analyse")
        return m
    }

    private fun openPath(): String = session().currentPath
        ?: throw Failure("No binary is open in Nocturne.")

    // --------------------------------------------------------- arguments --

    private fun addressArg(args: JSONObject, name: String): Long {
        if (!args.has(name) || args.isNull(name)) throw Failure("`$name` is required.")
        val raw = args.get(name)
        if (raw is Number) return raw.toLong()
        val text = raw.toString()
        return parseAddr(text)
            ?: throw Failure("`$name` is not an address: \"$text\". Use hex, for example 0x2a10.")
    }

    private fun optionalAddress(args: JSONObject, name: String): Long? {
        if (!args.has(name) || args.isNull(name)) return null
        val text = args.get(name).toString()
        if (text.isBlank()) return null
        return addressArg(args, name)
    }

    private fun textArg(args: JSONObject, name: String, required: Boolean): String {
        if (!args.has(name) || args.isNull(name)) {
            if (required) throw Failure("`$name` is required.")
            return ""
        }
        return args.get(name).toString()
    }

    private fun intArg(args: JSONObject, name: String, def: Int, min: Int, max: Int): Int {
        if (!args.has(name) || args.isNull(name)) return def
        val v = args.optInt(name, def)
        return v.coerceIn(min, max)
    }

    private fun boolArg(args: JSONObject, name: String, def: Boolean): Boolean =
        if (!args.has(name) || args.isNull(name)) def else args.optBoolean(name, def)

    private fun enumArg(args: JSONObject, name: String, allowed: List<String>, def: String): String {
        val v = textArg(args, name, false).ifBlank { def }.lowercase()
        if (v !in allowed) {
            throw Failure("`$name` must be one of ${allowed.joinToString(", ")} — got \"$v\".")
        }
        return v
    }

    private class Window(val offset: Int, val limit: Int)

    private fun window(args: JSONObject, def: Int, max: Int) = Window(
        intArg(args, "offset", 0, 0, Int.MAX_VALUE),
        intArg(args, "limit", def, 1, max)
    )

    private fun <T> slice(all: List<T>, w: Window): List<T> {
        if (w.offset >= all.size) return emptyList()
        return all.subList(w.offset, minOf(all.size, w.offset + w.limit))
    }

    /** The same four fields on every list answer, so the model learns them once. */
    private fun paginate(out: JSONObject, total: Int, w: Window, count: Int) {
        out.put("total", total)
        out.put("offset", w.offset)
        out.put("count", count)
        val next = w.offset + count
        if (next < total) out.put("nextOffset", next) else out.put("nextOffset", JSONObject.NULL)
    }

    // ------------------------------------------------------------ engine --

    // One-entry memo of the last per-function analysis. A client normally asks
    // for the disassembly, the pseudo-C and the xrefs of the same address in a
    // row, and each of those is the same `nativeFunction` pass — several
    // seconds of Ghidra for the third time in a row otherwise. Keyed on path,
    // address and backend, so it can never answer for the wrong one.
    private var memoKey = ""
    private var memoValue: FunctionDetail? = null

    /**
     * Analyse one function. Must be called with [engineLock] held.
     *
     * A non-current backend is selected for the duration and put back in a
     * `finally`, which is the same dance StudioViewModel.loadAlternatePseudo
     * does for its comparison column: the engine keeps exactly one backend
     * selection for the whole process.
     */
    private fun functionDetail(addr: Long, backend: String): FunctionDetail {
        val vm = session()
        val path = openPath()
        val wanted = when (backend) {
            "ghidra" -> "ghidra"
            "ir" -> "ir"
            else -> vm.decompiler
        }
        if (wanted == "ghidra" && !vm.sleighReady) {
            throw Failure(
                "The Ghidra backend is not available on this device — the SLEIGH " +
                    "specifications are not installed" +
                    (if (vm.decompilerNote.isNotBlank()) " (${vm.decompilerNote})" else "") +
                    ". Pass backend=\"ir\" to use the built-in lifter."
            )
        }
        val key = "$path|$addr|$wanted"
        val hit = memoValue
        if (key == memoKey && hit != null) return hit
        val current = vm.decompiler
        val d = if (wanted == current) {
            parseDetail(NativeBridge.nativeFunction(path, addr))
        } else {
            NativeBridge.nativeSetDecompiler(wanted)
            try {
                parseDetail(NativeBridge.nativeFunction(path, addr))
            } finally {
                NativeBridge.nativeSetDecompiler(current)
            }
        }
        if (!d.ok) throw Failure(d.error ?: "the engine could not analyse ${hx(addr)}")
        memoKey = key
        memoValue = d
        return d
    }

    /** A function start for [addr], following containment, or a clear failure. */
    private fun resolveFunction(addr: Long): FuncInfo {
        val vm = session()
        openMeta()
        vm.functionAt(addr)?.let { return it }
        vm.functionContaining(addr)?.let { return it }
        throw Failure(
            "No function at or containing ${hx(addr)}. list_functions gives the addresses " +
                "the engine actually found."
        )
    }

    private fun effectiveName(addr: Long): String = session().effectiveFuncName(addr)

    // ------------------------------------------------------------- tools --

    private val tools: List<Tool> = buildList {
        add(Tool(
            "analysis_overview", "Analysis overview",
            "What Nocturne knows about the binary that is open in the app right now: " +
                "format, architecture, entry point, load base, size, the decompiler backend " +
                "in use, its sections and segments, and the totals for functions, strings, " +
                "imports, exports and call edges. Call this first — every other tool works on " +
                "this same open binary, and nothing here can open a file. Takes no arguments.",
            schema(emptyList(), emptyList()), false
        ) { overview() })

        add(Tool(
            "triage", "Triage the binary",
            "One orientation pass over the open binary — where to dig, before you decompile " +
                "anything. Built entirely from what the engine already holds (imports, " +
                "strings, cross-reference counts and the function list), so it runs cheap and " +
                "reads nothing new off the engine. It returns three things. First, imports " +
                "grouped by interest — crypto, anti-debug/ptrace, JNI, networking/sockets and " +
                "process/exec — matched by name the way the bundled crypto-finder and " +
                "anti-debug-scanner plugins do, plus any Java_ JNI entry points from the " +
                "function list. Second, the hottest functions by incoming cross-reference " +
                "count. Third, the most notable strings — URLs, filesystem paths, format " +
                "strings and likely keys or hashes. Every list is capped and reports its own " +
                "total, and the buckets ranked over loaded data rather than the whole binary " +
                "say so. A name match is a lead, not a verdict. Takes an optional per-list " +
                "`limit`.",
            schema(
                emptyList(),
                listOf(
                    "limit" to intProp(
                        "Rows each list returns before it is capped; every list still " +
                            "reports its full total.",
                        1, 50, 12
                    )
                )
            ), false
        ) { triage(it) })

        add(Tool(
            "list_functions", "List functions",
            "List or search the functions the engine found. `query` is a case-insensitive " +
                "substring matched against the symbol name, the demangled name and any name " +
                "recorded in this project. Each row's `address` is what disassemble_function, " +
                "decompile_function, xrefs, call_graph and emulate_function take.\n\n" +
                "`scope` decides how much of the binary is in view. `loaded` (the default) " +
                "searches and sorts the functions the app has already loaded — fast, and the " +
                "only scope that honours `sort`, but a large library keeps most of its " +
                "functions unloaded, and the answer says how many. `all` walks the WHOLE " +
                "function list straight from the engine in address order, paging with " +
                "`offset` and `nextOffset`, so every function is reachable and a name can be " +
                "ruled truly absent; `query` still filters, and the answer reports `scanned` " +
                "(rows walked, what `nextOffset` advances by) alongside `count` (rows that " +
                "matched). At most " + WALK_CAP + " functions per page in either scope.",
            schema(
                emptyList(),
                listOf(
                    "query" to strProp("Case-insensitive substring of the function name. Omit for all."),
                    "scope" to enumProp(
                        "`loaded` searches the functions the app holds and honours `sort`; " +
                            "`all` walks the whole binary in address order via the engine.",
                        listOf("loaded", "all"), "loaded"
                    ),
                    "sort" to enumProp(
                        "Row order, applied in scope=loaded only. `callers` and `callees` " +
                            "sort by call-graph degree, descending — the quickest way to the " +
                            "functions that matter.",
                        listOf("address", "name", "size", "callers", "callees"), "address"
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, WALK_CAP)
                )
            ), false
        ) { listFunctions(it) })

        add(Tool(
            "list_strings", "List strings",
            "Strings the engine recovered, with the address each was found at. `query` is a " +
                "case-insensitive substring of the string itself. Paginated. Values longer " +
                "than 240 characters are cut and the row says so.",
            schema(
                emptyList(),
                listOf(
                    "query" to strProp("Case-insensitive substring to match. Omit for all."),
                    "minLength" to intProp("Drop strings shorter than this.", 1, 4096, 1),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { listStrings(it) })

        add(Tool(
            "list_symbols", "List imports and exports",
            "The binary's imports (what it calls out to — libc, JNI, syscall wrappers) or its " +
                "exports (what it offers callers). `kind` picks which. Paginated.",
            schema(
                listOf("kind"),
                listOf(
                    "kind" to enumProp("Which table to read.", listOf("imports", "exports"), "imports"),
                    "query" to strProp("Case-insensitive substring of the symbol name."),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { listSymbols(it) })

        add(Tool(
            "disassemble_function", "Disassemble a function",
            "Disassemble one function: address, raw bytes, mnemonic, operands and the engine's " +
                "auto-comment per instruction, plus any comment recorded in this project at " +
                "that address. Long functions are paginated by instruction — at most " +
                "$ASM_CAP per call.",
            schema(
                listOf("address"),
                listOf(
                    "address" to addressProp,
                    "offset" to offsetProp(),
                    "limit" to limitProp(200, ASM_CAP)
                )
            ), false
        ) { disassemble(it) })

        add(Tool(
            "decompile_function", "Decompile a function",
            "Decompile one function to pseudo-C. `backend`: `current` uses whatever the user " +
                "has selected in the app; `ghidra` is the p-code decompiler — slower, with " +
                "types and structure; `ir` is the built-in lifter — faster, rougher, gotos " +
                "and raw registers. A backend other than `current` is selected for this one " +
                "call and put back afterwards. Ghidra can take several seconds on a large " +
                "function. Output is capped at $PSEUDO_CAP characters.",
            schema(
                listOf("address"),
                listOf(
                    "address" to addressProp,
                    "backend" to enumProp(
                        "Which decompiler to run for this call.",
                        listOf("current", "ghidra", "ir"), "current"
                    )
                )
            ), false
        ) { decompile(it) })

        add(Tool(
            "decompile_functions", "Decompile many functions",
            "Decompile a batch of functions to pseudo-C in one call, so a sweep is one round " +
                "trip instead of twenty. Each row is exactly what decompile_function returns " +
                "for that address — same engine pass, same $PSEUDO_CAP-character per-row cap, " +
                "same `truncated` flag — because it runs that identical path per function.\n\n" +
                "Name the functions one of two ways: `addresses`, an explicit list of function " +
                "addresses in hex, or `offset`+`count`, a window over the WHOLE function list " +
                "in address order (the same walk list_functions scope=all pages), which is how " +
                "you sweep a binary front to back. At most " + BATCH_MAX + " functions per " +
                "call, and the batch also stops once its pseudo-C passes a total size cap — " +
                "either way the answer reports `count`, `requested` and, in range mode, " +
                "`nextOffset` to continue. A function that fails to decompile comes back as a " +
                "row with an `error` instead of failing the batch. This holds the engine for " +
                "its whole run, like any decompile does; it is not parallel.",
            schema(
                emptyList(),
                listOf(
                    "addresses" to strListProp(
                        "Function addresses in hex. Overrides offset/count when present. " +
                            "An address inside a body resolves to its function."
                    ),
                    "offset" to intProp(
                        "Start index into the whole-binary function list (address order). " +
                            "Used when `addresses` is omitted.",
                        0, Int.MAX_VALUE, 0
                    ),
                    "count" to intProp(
                        "How many functions from `offset` to decompile.", 1, BATCH_MAX, 8
                    ),
                    "backend" to enumProp(
                        "Which decompiler to run, as in decompile_function.",
                        listOf("current", "ghidra", "ir"), "current"
                    )
                )
            ), false
        ) { decompileBatch(it) })

        add(Tool(
            "xrefs", "Cross-references",
            "Who references a function (`in`), and what it references (`out`). Each row gives " +
                "the referencing address, the function that address belongs to, the reference " +
                "type, and the address to follow next. Answers come from the engine's " +
                "per-function analysis where it has one and from the whole-binary call graph " +
                "otherwise — the same rule the app's own xref sheet follows, so the two can " +
                "never disagree. Note this runs the same engine pass as decompile_function; " +
                "call_graph is the cheaper tool for walking many functions. Paginated.",
            schema(
                listOf("address"),
                listOf(
                    "address" to addressProp,
                    "direction" to enumProp(
                        "`in` is callers, `out` is callees.",
                        listOf("in", "out", "both"), "both"
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { xrefs(it) })

        add(Tool(
            "find_string_xrefs", "References to a string or datum",
            "Given the ADDRESS of a string or other datum — not a function — the functions " +
                "that reference it. This is the direct route from a string to the routine that " +
                "uses it: take the address of \"pinned public key\" from list_strings and get " +
                "the SSL-pinning function, instead of decompiling candidates one by one. Each " +
                "row is a referencing SITE — the instruction address, the function that " +
                "contains it, and the reference type. `targetKind` reports whether the address " +
                "is a `string`, other `data`, or `code`; a `code` address has no data to " +
                "reference it, so the answer degenerates to that function's callers, which is " +
                "what `xrefs` is for. Reads the reference map built at analysis time — the same " +
                "store the string-hunter plugin reads — so it is cheap and runs no decompiler. " +
                "Paginated, with an honest total when the engine's per-address cap drops rows.",
            schema(
                listOf("address"),
                listOf(
                    "address" to strProp(
                        "Address of the string or datum, in hex (\"0x2285f0\", \"2285f0\"). " +
                            "Take it from list_strings, or from any answer that carries an " +
                            "`address` for a string."
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { findStringXrefs(it) })

        add(Tool(
            "scan_protections", "Scan for anti-analysis & pinning",
            "Scan the open binary for likely security / anti-analysis routines and report " +
                "them grouped by category: ssl-pinning, root-detection, anti-debug, " +
                "anti-frida, emulator-detection and tamper-detection. This is the capstone " +
                "on find_string_xrefs and runs the same machinery: a category token names a " +
                "string, that string's referencing sites map to their containing functions " +
                "through the reference map built at analysis time, and a referencing function " +
                "under a category is a detection; a function whose own name contains a token " +
                "is a direct detection. Each detection carries a confidence and the exact " +
                "matched token(s) as evidence, so a broad token like \"frida\" is reported but " +
                "weighted low — judge it by its evidence. A matched string that nothing " +
                "references is still reported as an unattributed hit. READ-ONLY, cheap, runs " +
                "no decompiler. `counts` carries the whole-binary per-category totals even " +
                "when a page shows fewer. Paginated over the flat detection list.",
            schema(
                emptyList(),
                listOf(
                    "category" to enumProp(
                        "Restrict to one category. Omit (or `all`) for every category.",
                        listOf(
                            "all", "ssl-pinning", "root-detection", "anti-debug",
                            "anti-frida", "emulator-detection", "tamper-detection"
                        ),
                        "all"
                    ),
                    "minConfidence" to enumProp(
                        "Drop detections weaker than this. `low` (default) keeps all.",
                        listOf("low", "medium", "high"), "low"
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(100, 400)
                )
            ), false
        ) { scanProtections(it) })

        // ---- DEX / smali (only meaningful when a .dex is open) -------------
        add(Tool(
            "dex_method_smali", "Disassemble a DEX method to smali",
            "Decode one Dalvik method's bytecode to smali — the DEX equivalent of " +
                "disassemble_function, which only handles native machine code. `address` is a " +
                "method's code offset: take it from list_functions (a DEX method is a function " +
                "whose address is its codeOff) or from analysis_overview's DEX method list. Each " +
                "row is a decoded instruction — offset, code-unit bytes, mnemonic, operands (with " +
                "string/type/field/method references resolved to names) and a comment carrying the " +
                "raw pool index or the branch target. An opcode the decoder does not know renders " +
                "as an unknown marker, never a guess. Paginated by instruction; the method header " +
                "reports registers, ins, outs, tries and the call-graph degrees. Only works when " +
                "the open file is a DEX.",
            schema(
                listOf("address"),
                listOf(
                    "address" to strProp(
                        "The method's code offset in hex (\"0x2a10\", \"2a10\"). From " +
                            "list_functions or analysis_overview's DEX methods."
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(200, ASM_CAP)
                )
            ), false
        ) { dexMethodSmali(it) })

        add(Tool(
            "dex_strings", "Search the DEX string pool",
            "Search the DEX string pool — a case-insensitive substring over the string_ids the " +
                "loader read, which reaches far more than list_strings' first 3000. Each row is a " +
                "string with its pool index as `address`. `total` is matches over the whole pool; " +
                "`poolRead` < `poolTotal` means the loader capped the pool. Paginated. Only works " +
                "when the open file is a DEX.",
            schema(
                emptyList(),
                listOf(
                    "query" to strProp("Case-insensitive substring to match. Omit for all strings."),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { dexStrings(it) })

        add(Tool(
            "dex_find_method_xrefs", "Who invokes a DEX method",
            "Given a DEX method's code offset, the methods that invoke it (`callers`) and the " +
                "methods it invokes (`callees`). This runs no new scan: the engine built a DEX " +
                "call graph at analysis time by walking every method's invoke instructions, and " +
                "this surfaces the edges touching one method, each resolved to its Class.method " +
                "name and carrying the invoke site and how many call sites the edge stands for. " +
                "For a DEX method, `xrefs` and `call_graph` answer the same question from the same " +
                "graph; this is the DEX-framed view. Paginated. Only works when the open file is a " +
                "DEX.",
            schema(
                listOf("address"),
                listOf(
                    "address" to strProp(
                        "The method's code offset in hex. From list_functions or " +
                            "analysis_overview's DEX methods."
                    ),
                    "direction" to enumProp(
                        "`callers` is who invokes it, `callees` what it invokes.",
                        listOf("callers", "callees", "both"), "both"
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { dexFindMethodXrefs(it) })

        add(Tool(
            "call_graph", "Walk the call graph",
            "Walk the call graph around one function, or — with no `address` — report the " +
                "busiest functions in the binary. The whole graph runs to twelve thousand " +
                "edges here, which is useless in a transcript, so this answers with a bounded " +
                "neighbourhood: `depth` hops out from `address`, stopping at `limit` " +
                "functions. Each edge carries `sites`, how many distinct call instructions it " +
                "stands for. Reads the call-graph index built at analysis time, so it is " +
                "cheap and can be called repeatedly.",
            schema(
                emptyList(),
                listOf(
                    "address" to strProp(
                        "Function to walk out from, in hex. Omit for a whole-binary summary " +
                            "of the most-connected functions."
                    ),
                    "direction" to enumProp(
                        "Which way to walk from `address`.",
                        listOf("callers", "callees", "both"), "both"
                    ),
                    "depth" to intProp("Hops out from `address`.", 1, 4, 2),
                    "limit" to intProp("Maximum functions to return.", 1, 200, 60)
                )
            ), false
        ) { callGraph(it) })

        add(Tool(
            "read_memory", "Read bytes",
            "Read raw bytes of the open file as hex and as printable ASCII. Give either " +
                "`address` — a virtual address, translated through the section table for ELF " +
                "and PE — or `offset`, a byte offset into the file. Nocturne holds the first " +
                "8 MiB of the open file in memory and this reads only from that: it takes no " +
                "path and opens nothing. At most $HEX_CAP bytes per call.",
            schema(
                emptyList(),
                listOf(
                    "address" to strProp("Virtual address in hex. Use this or `offset`, not both."),
                    "offset" to intProp("Byte offset into the file.", 0, Int.MAX_VALUE, 0),
                    "length" to intProp("Bytes to read.", 1, HEX_CAP, 256)
                )
            ), false
        ) { readMemory(it) })

        add(Tool(
            "emulate_function", "Emulate a function",
            "Run one function under the engine's p-code emulator and report what it wrote to " +
                "memory. This is the tool for a decode or decrypt routine: pass an output " +
                "buffer as `buf:64`, run, and read the bytes back out of the `memory` array. " +
                "Arguments are positional and land in the target's argument registers — " +
                "`0x1` a plain scalar or an address inside the binary, `buf:N` N zeroed bytes " +
                "whose address is passed, `hex:aabbcc` a block holding those bytes, " +
                "`str:hello` the same but NUL-terminated. Every run is bounded by an " +
                "instruction budget, a wall clock, a page cap and a cap on stubbed imports, " +
                "and `stop` says which bound ended it. `approximate: true` means something " +
                "was modelled as zero that might not be, so treat the memory as plausible " +
                "rather than certain. This is the only tool that executes the analysed " +
                "binary's own instructions, and it does so inside the emulator — nothing is " +
                "run on the device's CPU.",
            schema(
                listOf("entry"),
                listOf(
                    "entry" to strProp("Function to run, in hex."),
                    "args" to strListProp(
                        "Positional arguments: \"0x1\", \"buf:64\", \"hex:aabbcc\", \"str:hello\"."
                    ),
                    "regs" to strListProp("Raw register overrides applied last, as \"x9=0x40\"."),
                    "write" to strListProp("Memory to place before the run, as \"0x4a100=aabb\"."),
                    "read" to strListProp("Extra windows to read back at exit, as \"0x4a100:64\"."),
                    "stopAt" to strProp("Halt before executing this address, in hex."),
                    "maxInstr" to intProp("Instruction budget.", 1000, 2000000, 200000),
                    "timeoutMs" to intProp("Wall clock for the run.", 100, 10000, 3000),
                    "maxPages" to intProp("4 KiB pages the run may dirty.", 16, 8192, 1024),
                    "maxCalls" to intProp("Stubbed imports it may call.", 16, 65536, 4096),
                    "strictUserops" to boolProp(
                        "Stop at the first p-code operation modelled as zero instead of noting it.",
                        false
                    )
                )
            ), false
        ) { emulate(it) })

        add(Tool(
            "list_annotations", "List project annotations",
            "What has been recorded against the open project: renames, comments, bookmarks " +
                "and notes, in address order. Read this before renaming anything, so you do " +
                "not overwrite work the user has already done. Paginated.",
            schema(
                emptyList(),
                listOf(
                    "kind" to enumProp(
                        "Which annotations to return.",
                        listOf("all", "renames", "comments", "bookmarks", "notes"), "all"
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(100, 200)
                )
            ), false
        ) { listAnnotations(it) })

        // ---- writes -------------------------------------------------------
        // Advertised only when the user cleared read-only mode before starting
        // the server. They write to Nocturne's SQLite project database through
        // the same ViewModel calls the app's own UI uses, so a client's rename
        // is undoable, exportable and visible exactly like a typed one. The
        // binary on disk is not touched by any of them.
        add(Tool(
            RENAME, "Rename a function",
            "Give a function a name. The name is stored in Nocturne's project database " +
                "against the address and appears everywhere in the app, in exports and in the " +
                "IDAPython/IDC scripts. The binary on disk is never modified. `address` must " +
                "be a function start — list_functions gives them.",
            schema(
                listOf("address", "name"),
                listOf(
                    "address" to addressProp,
                    "name" to strProp("The new name. Keep it to what the function does.")
                )
            ), true
        ) { rename(it) })

        add(Tool(
            COMMENT, "Comment an address",
            "Store a comment against an address in the open project. An empty `text` removes " +
                "the comment. Stored in Nocturne's project database; the binary on disk is " +
                "never modified.",
            schema(
                listOf("address", "text"),
                listOf(
                    "address" to addressProp,
                    "text" to strProp("The comment. An empty string removes the one that is there.")
                )
            ), true
        ) { comment(it) })

        add(Tool(
            BOOKMARK, "Bookmark an address",
            "Bookmark an address with a label so the user finds it in the app's bookmarks " +
                "list. Stored in Nocturne's project database; the binary on disk is never " +
                "modified.",
            schema(
                listOf("address", "label"),
                listOf(
                    "address" to addressProp,
                    "label" to strProp("Short label for the bookmark.")
                )
            ), true
        ) { bookmark(it) })
    }

    /** The tools this server will actually honour, read-only mode applied. */
    private val exposed: List<Tool> =
        if (allowWrites) tools else tools.filterNot { it.write }

    fun names(): List<String> = exposed.map { it.name }

    fun listJson(): JSONArray {
        val out = JSONArray()
        for (t in exposed) {
            val annotations = JSONObject()
                .put("title", t.title)
                .put("readOnlyHint", !t.write)
                .put("destructiveHint", false)
                .put("idempotentHint", true)
                .put("openWorldHint", false)
            out.put(
                JSONObject()
                    .put("name", t.name)
                    .put("title", t.title)
                    .put("description", t.description)
                    .put("inputSchema", t.schema)
                    .put("annotations", annotations)
            )
        }
        return out
    }

    fun has(name: String): Boolean = exposed.any { it.name == name }

    /** True for a tool this build knows but this server is not exposing. */
    fun hiddenByReadOnly(name: String): Boolean =
        tools.any { it.name == name } && exposed.none { it.name == name }

    /**
     * Run one tool. Blocking on purpose: the caller is already on
     * `Dispatchers.IO`, the engine calls below are blocking JNI, and the
     * project database is SQLite.
     */
    fun invoke(name: String, args: JSONObject): Outcome {
        val tool = exposed.firstOrNull { it.name == name }
            ?: throw Failure("No tool named \"$name\" is exposed by this server.")
        engineLock.lock()
        try {
            return tool.handler(args)
        } finally {
            engineLock.unlock()
        }
    }

    // ------------------------------------------------------- tool bodies --

    private fun overview(): Outcome {
        val vm = session()
        val m = openMeta()
        val out = JSONObject()
        out.put("name", m.name)
        out.put("format", m.format)
        out.put("arch", m.arch)
        out.put("entry", hx(m.entry))
        out.put("base", hx(m.base))
        out.put("sizeBytes", m.sizeBytes)
        out.put("truncated", m.truncated)
        out.put("loadMs", m.loadMs)
        out.put("engineBackend", m.backend)
        out.put("disassemblable", m.disassemblable)
        if (m.soName.isNotEmpty()) out.put("soName", m.soName)
        out.put("neededLibraries", JSONArray(m.needed))
        out.put(
            "addressing",
            if (m.format == "ELF" || m.format == "PE") "virtual addresses"
            else "file offsets — this format is read as a flat file, so an address is an offset"
        )

        // Two numbers per capped list, never one. `functions` is what this app
        // holds and can answer questions about; `functionsFound` is what the
        // engine discovered. They differ by a factor of eight on a large
        // library, and a model handed only the first has been told a floor is
        // a count -- which is exactly the failure this pair exists to stop.
        val counts = JSONObject()
        counts.put("functions", m.functions.size)
        counts.put("functionsFound", maxOf(m.functionsTotal, m.functions.size))
        counts.put("strings", m.strings.size)
        counts.put("stringsFound", maxOf(m.stringsTotal, m.strings.size))
        counts.put("imports", m.imports.size)
        counts.put("exports", m.exports.size)
        counts.put("sections", m.sections.size)
        counts.put("segments", m.segments.size)
        counts.put("callEdges", m.callEdges.size)
        counts.put("callEdgesFound", maxOf(m.callEdgesTotal, m.callEdges.size))
        counts.put("callSites", m.callSitesTotal)
        // The reference map caps at 200,000 and held 200,000 of 1,323,435 on a
        // real library. Above that every `callers`/`callees` this server emits
        // is a floor, and this pair is where a reader finds that out.
        counts.put("xrefsStored", m.xrefsStored)
        counts.put("xrefsFound", maxOf(m.xrefsTotal, m.xrefsStored))
        if (m.demangleFailed > 0) counts.put("demangleFailed", m.demangleFailed)
        if (m.dexClasses.isNotEmpty()) {
            counts.put("dexClasses", m.dexClasses.size)
            counts.put("dexClassesFound", maxOf(m.dexClassesTotal, m.dexClasses.size))
        }
        if (m.dexMethods.isNotEmpty()) {
            counts.put("dexMethods", m.dexMethods.size)
            counts.put("dexMethodsFound", maxOf(m.dexMethodsTotal, m.dexMethods.size))
        }
        if (m.xrefsAreFloors) {
            out.put(
                "referenceCountsAreFloors",
                "The engine's cross-reference map holds ${m.xrefsStored} of the " +
                    "${m.xrefsTotal} references it found, so every callers/callees " +
                    "count in this server's answers is a lower bound, not a total."
            )
        }
        out.put("counts", counts)

        val sections = JSONArray()
        for (s in m.sections.take(64)) {
            sections.put(
                JSONObject().put("name", s.name).put("type", s.type).put("flags", s.flags)
                    .put("address", hx(s.addr)).put("fileOffset", s.offset).put("size", s.size)
            )
        }
        out.put("sections", sections)

        val segments = JSONArray()
        for (s in m.segments.take(32)) {
            segments.put(
                JSONObject().put("type", s.type).put("flags", s.flags)
                    .put("vaddr", hx(s.vaddr)).put("fileOffset", s.offset)
                    .put("fileSize", s.filesz).put("memSize", s.memsz)
            )
        }
        out.put("segments", segments)

        val dec = JSONObject()
            .put("selected", vm.decompiler)
            .put("ghidraAvailable", vm.sleighReady)
        if (vm.decompilerNote.isNotBlank()) dec.put("note", vm.decompilerNote)
        out.put("decompiler", dec)

        val project = JSONObject()
            .put("renames", vm.renames.size)
            .put("comments", vm.comments.size)
            .put("bookmarks", vm.bookmarks.size)
            .put("notes", vm.notes().size)
            .put("writable", exposed.any { it.write })
        out.put("project", project)

        val mf = vm.manifest
        if (mf != null && mf.ok) {
            out.put(
                "androidManifest",
                JSONObject()
                    .put("package", mf.packageName)
                    .put("versionName", mf.versionName)
                    .put("versionCode", mf.versionCode)
                    .put("minSdk", mf.minSdk)
                    .put("targetSdk", mf.targetSdk)
                    .put("debuggable", mf.debuggable ?: JSONObject.NULL)
                    .put("permissions", JSONArray(mf.permissions))
                    .put("activities", mf.activities.size)
                    .put("services", mf.services.size)
                    .put("receivers", mf.receivers.size)
                    .put("providers", mf.providers.size)
            )
        }
        if (m.notes.isNotEmpty()) out.put("engineNotes", JSONArray(m.notes))

        val fnFound = maxOf(m.functionsTotal, m.functions.size)
        return Outcome(
            out,
            "${m.name} · ${m.format} ${m.arch} · " +
                (if (fnFound > m.functions.size) "${m.functions.size} of $fnFound functions"
                else "${m.functions.size} functions")
        )
    }

    /**
     * triage: one orientation pass, built only from what the engine already
     * holds — imports (complete), the loaded function list and its xref counts,
     * and the strings this analysis carries. It reads nothing new off the
     * engine, so it is cheap; the price is that the function and string buckets
     * see the loaded prefix of a large binary, and the answer says so.
     */
    private fun triage(args: JSONObject): Outcome {
        val m = openMeta()
        val cap = intArg(args, "limit", 12, 1, 50)

        // Imports grouped by interest. An import can land in more than one
        // bucket; each bucket carries its own total against the cap.
        val imports = JSONObject()
        for ((label, needles) in TRIAGE_IMPORTS) {
            val matched = m.imports.filter { imp ->
                val n = imp.name.lowercase()
                needles.any { n.contains(it) }
            }
            val syms = JSONArray()
            for (s in matched.take(cap)) {
                syms.put(JSONObject().put("name", s.name).put("address", hx(s.addr)))
            }
            imports.put(
                label,
                JSONObject().put("total", matched.size)
                    .put("count", minOf(matched.size, cap)).put("symbols", syms)
            )
        }

        // JNI entry points are Java_* in the function list, not named imports.
        val jniEntries = m.functions.filter { it.name.contains("Java_", ignoreCase = true) }
        val jniArr = JSONArray()
        for (f in jniEntries.take(cap)) {
            jniArr.put(JSONObject().put("address", hx(f.addr)).put("name", effectiveName(f.addr)))
        }

        // Hottest functions by incoming reference count.
        val hot = m.functions.sortedByDescending { it.nCallers }.take(cap)
        val hotArr = JSONArray()
        for (f in hot) {
            hotArr.put(
                JSONObject().put("address", hx(f.addr)).put("name", effectiveName(f.addr))
                    .put("callers", f.nCallers).put("callees", f.nCallees).put("size", f.size)
            )
        }

        // Notable strings, sorted into four leads.
        val urls = ArrayList<FoundStr>()
        val paths = ArrayList<FoundStr>()
        val formats = ArrayList<FoundStr>()
        val keys = ArrayList<FoundStr>()
        for (s in m.strings) {
            val v = s.value
            val isUrl = v.contains("://")
            if (isUrl) urls.add(s)
            if (!isUrl && isPathish(v)) paths.add(s)
            if (!isUrl && FORMAT_SPEC.containsMatchIn(v)) formats.add(s)
            if (isKeyish(v)) keys.add(s)
        }
        val notable = JSONObject()
            .put("urls", stringBucket(urls, cap))
            .put("paths", stringBucket(paths, cap))
            .put("formatStrings", stringBucket(formats, cap))
            .put("likelyKeys", stringBucket(keys, cap))

        val fnFound = maxOf(m.functionsTotal, m.functions.size)
        val strFound = maxOf(m.stringsTotal, m.strings.size)
        val out = JSONObject()
        out.put("imports", imports)
        out.put("importsScanned", m.imports.size)
        out.put(
            "jniEntryPoints",
            JSONObject().put("total", jniEntries.size)
                .put("count", minOf(jniEntries.size, cap)).put("functions", jniArr)
        )
        out.put("hotFunctions", hotArr)
        out.put("hotFunctionsRanked", m.functions.size)
        out.put("functionsTotal", fnFound)
        out.put("notableStrings", notable)
        out.put("stringsScanned", m.strings.size)
        out.put("stringsTotal", strFound)

        val caveats = JSONArray()
        if (fnFound > m.functions.size) caveats.put(
            "Hot functions and JNI entry points are drawn from the ${m.functions.size} " +
                "functions loaded, of $fnFound the engine found, the same set call_graph's " +
                "busiest list ranks over. list_functions scope=\"all\" reaches the rest in " +
                "address order (it does not rank by callers)."
        )
        if (strFound > m.strings.size) caveats.put(
            "Notable strings are drawn from the ${m.strings.size} strings this analysis holds, " +
                "of $strFound found."
        )
        if (m.xrefsAreFloors) caveats.put(
            "Caller counts are floors: the reference map holds ${m.xrefsStored} of ${m.xrefsTotal}."
        )
        if (caveats.length() > 0) out.put("coverage", caveats)
        out.put(
            "note",
            "Name matches are leads, not verdicts. Imports are complete; the function and " +
                "string buckets are what the analysis holds. Start from the fullest bucket."
        )

        val crypto = imports.getJSONObject("crypto").getInt("total")
        val anti = imports.getJSONObject("antiDebug").getInt("total")
        return Outcome(out, "triage · crypto $crypto, anti-debug $anti · ${hot.size} hot funcs")
    }

    /** One notable-strings bucket: total matched, and the first [cap] values. */
    private fun stringBucket(rows: List<FoundStr>, cap: Int): JSONObject {
        val arr = JSONArray()
        for (s in rows.take(cap)) {
            val o = JSONObject().put("address", hx(s.addr))
            if (s.value.length > 160) {
                o.put("value", s.value.take(160)).put("truncated", true).put("length", s.value.length)
            } else {
                o.put("value", s.value)
            }
            arr.put(o)
        }
        return JSONObject().put("total", rows.size).put("count", minOf(rows.size, cap)).put("values", arr)
    }

    /** A filesystem-path-looking string: a rooted path, or a known Android dir. */
    private fun isPathish(v: String): Boolean {
        if (v.length < 2 || v.length > 200) return false
        if (v.startsWith("/") && v.indexOf('/', 1) >= 0) return true
        return v.contains("/proc/") || v.contains("/system/") ||
            v.contains("/data/") || v.contains("/sdcard/") || v.contains("/dev/")
    }

    /** A string that reads as an embedded key, secret or hash. A lead, not proof. */
    private fun isKeyish(v: String): Boolean {
        val t = v.trim()
        if (t.length in 16..512 && (HEX_BLOB.matches(t) || BASE64_BLOB.matches(t))) return true
        val low = v.lowercase()
        return low.contains("secret") || low.contains("password") || low.contains("passwd") ||
            low.contains("api_key") || low.contains("apikey") || low.contains("private key") ||
            low.contains("-----begin") || low.contains("token") ||
            (low.contains("key") && (low.contains("=") || low.contains(":")))
    }

    private fun listFunctions(args: JSONObject): Outcome {
        val m = openMeta()
        val q = textArg(args, "query", false).trim()
        val scope = enumArg(args, "scope", listOf("loaded", "all"), "loaded")
        if (scope == "all") return listFunctionsWholeBinary(args, m, q)
        val sort = enumArg(args, "sort", listOf("address", "name", "size", "callers", "callees"), "address")

        var rows = m.functions
        if (q.isNotEmpty()) {
            rows = rows.filter { f ->
                f.name.contains(q, true) ||
                    (f.demangled?.contains(q, true) == true) ||
                    effectiveName(f.addr).contains(q, true)
            }
        }
        rows = when (sort) {
            // xor with the sign bit is unsigned order: a top-bit-set address is
            // a high address, not a negative one.
            "address" -> rows.sortedBy { it.addr xor Long.MIN_VALUE }
            "name" -> rows.sortedBy { effectiveName(it.addr).lowercase() }
            "size" -> rows.sortedByDescending { it.size }
            "callers" -> rows.sortedByDescending { it.nCallers }
            else -> rows.sortedByDescending { it.nCallees }
        }

        val w = window(args, 50, 200)
        val page = slice(rows, w)
        val arr = JSONArray()
        for (f in page) {
            val name = effectiveName(f.addr)
            val row = JSONObject()
                .put("address", hx(f.addr))
                .put("name", name)
                .put("size", f.size)
                .put("source", f.from)
                .put("callers", f.nCallers)
                .put("callees", f.nCallees)
            if (f.name.isNotEmpty() && f.name != name) row.put("originalName", f.name)
            f.demangled?.takeIf { it.isNotBlank() }?.let { row.put("demangled", it) }
            arr.put(row)
        }
        val out = JSONObject().put("functions", arr)
        paginate(out, rows.size, w, page.size)
        if (q.isNotEmpty()) out.put("query", q)
        // `total` above counts the rows this app HOLDS. When the engine found
        // more than have been loaded, a query that returns nothing does not
        // mean the binary has nothing -- say so rather than let the absence
        // read as an answer.
        val found = maxOf(m.functionsTotal, m.functions.size)
        if (found > m.functions.size) {
            out.put("functionsLoaded", m.functions.size)
            out.put("functionsFound", found)
            out.put(
                "coverage",
                "Searched the ${m.functions.size} functions loaded; the engine found $found. " +
                    "Pass scope=\"all\" to walk or search the whole binary before concluding " +
                    "a name is absent."
            )
        }
        val note = if (q.isEmpty()) "" else " matching \"$q\""
        return Outcome(out, "${page.size} of ${rows.size}" + note)
    }

    /**
     * list_functions scope=all: the WHOLE function list, paged straight from the
     * engine in address order, so no function is out of reach. Never mutates the
     * app's loaded set — the page is read and dropped, unlike the app's own
     * loadMoreFunctions which appends.
     *
     * The engine's rows carry their own names; a rename recorded in this project
     * overrides one, but the app's effectiveFuncName would turn an UNLOADED
     * row's name into "sub_…" (it only knows loaded functions), so names here go
     * through [pagedName] instead.
     *
     * `count` is rows returned after `query`; `scanned` is rows walked, and
     * `nextOffset` advances by `scanned`. With no query the two are equal.
     */
    private fun listFunctionsWholeBinary(args: JSONObject, m: AnalysisMeta, q: String): Outcome {
        val w = window(args, 50, WALK_CAP)
        val page = parseFunctionPage(
            NativeBridge.nativeFunctionPage(openPath(), w.offset.toLong(), w.limit.toLong())
        )
        if (!page.ok) throw Failure(page.error ?: "the engine could not page the function list.")
        val total = maxOf(page.functionsTotal, m.functionsTotal, m.functions.size)
        val matched = if (q.isEmpty()) page.functions
            else page.functions.filter { f ->
                f.name.contains(q, true) ||
                    (f.demangled?.contains(q, true) == true) ||
                    pagedName(f).contains(q, true)
            }
        val arr = JSONArray()
        for (f in matched) {
            val name = pagedName(f)
            val row = JSONObject()
                .put("address", hx(f.addr))
                .put("name", name)
                .put("size", f.size)
                .put("source", f.from)
                .put("callers", f.nCallers)
                .put("callees", f.nCallees)
            if (f.name.isNotEmpty() && f.name != name) row.put("originalName", f.name)
            f.demangled?.takeIf { it.isNotBlank() }?.let { row.put("demangled", it) }
            arr.put(row)
        }
        val scanned = page.count
        val out = JSONObject().put("scope", "all").put("functions", arr)
        out.put("total", total)
        out.put("offset", w.offset)
        out.put("scanned", scanned)
        out.put("count", matched.size)
        out.put("functionsTotal", total)
        out.put("pageCap", WALK_CAP)
        val next = w.offset + scanned
        if (scanned > 0 && next < total) out.put("nextOffset", next)
        else out.put("nextOffset", JSONObject.NULL)
        if (q.isNotEmpty()) {
            out.put("query", q)
            out.put(
                "coverage",
                "Walked $scanned of $total functions from offset ${w.offset}; " +
                    "${matched.size} matched \"$q\". Page on with nextOffset until it is null."
            )
        }
        val note = if (q.isEmpty()) "" else " matching \"$q\""
        return Outcome(out, "whole binary · ${matched.size} of $total at ${w.offset}" + note)
    }

    /**
     * The name to show for an engine function row: a project rename if one is
     * recorded at that address, otherwise the engine's own name, otherwise the
     * synthetic sub_ form. Works for a row the app never loaded, which is why it
     * reads the row's own name rather than looking the address up.
     */
    private fun pagedName(f: FuncInfo): String {
        val key = annotationKey(f.addr)
        return session().renames[key]
            ?: f.name.ifBlank { "sub_" + key.removePrefix("0x").lowercase() }
    }

    private fun listStrings(args: JSONObject): Outcome {
        val m = openMeta()
        val q = textArg(args, "query", false).trim()
        val minLength = intArg(args, "minLength", 1, 1, 4096)
        var rows = m.strings
        if (minLength > 1) rows = rows.filter { it.value.length >= minLength }
        if (q.isNotEmpty()) rows = rows.filter { it.value.contains(q, true) }
        val w = window(args, 50, 200)
        val page = slice(rows, w)
        val arr = JSONArray()
        for (s in page) {
            val row = JSONObject().put("address", hx(s.addr))
            if (s.value.length > 240) {
                row.put("value", s.value.take(240)).put("truncated", true)
                    .put("length", s.value.length)
            } else {
                row.put("value", s.value)
            }
            arr.put(row)
        }
        val out = JSONObject().put("strings", arr)
        paginate(out, rows.size, w, page.size)
        if (q.isNotEmpty()) out.put("query", q)
        val found = maxOf(m.stringsTotal, m.strings.size)
        if (found > m.strings.size) {
            out.put("stringsLoaded", m.strings.size)
            out.put("stringsFound", found)
            out.put(
                "coverage",
                "Searched the ${m.strings.size} strings this analysis carries; " +
                    "the engine found $found."
            )
        }
        val note = if (q.isEmpty()) "" else " matching \"$q\""
        return Outcome(out, "${page.size} of ${rows.size}" + note)
    }

    private fun listSymbols(args: JSONObject): Outcome {
        val m = openMeta()
        val kind = enumArg(args, "kind", listOf("imports", "exports"), "imports")
        val q = textArg(args, "query", false).trim()
        var rows = if (kind == "imports") m.imports else m.exports
        if (q.isNotEmpty()) rows = rows.filter { it.name.contains(q, true) }
        val w = window(args, 50, 200)
        val page = slice(rows, w)
        val arr = JSONArray()
        for (s in page) {
            arr.put(JSONObject().put("name", s.name).put("address", hx(s.addr)))
        }
        val out = JSONObject().put("kind", kind).put("symbols", arr)
        paginate(out, rows.size, w, page.size)
        return Outcome(out, "$kind: ${page.size} of ${rows.size}")
    }

    private fun disassemble(args: JSONObject): Outcome {
        val vm = session()
        val asked = addressArg(args, "address")
        val fn = resolveFunction(asked)
        val d = functionDetail(fn.addr, "current")
        val w = window(args, 200, ASM_CAP)
        val page = slice(d.asm, w)
        val arr = JSONArray()
        for (line in page) {
            val row = JSONObject()
                .put("address", hx(line.addr))
                .put("bytes", line.bytes)
                .put("mnemonic", line.mnem)
                .put("operands", line.ops)
            if (line.comment.isNotEmpty()) row.put("autoComment", line.comment)
            vm.comments[annotationKey(line.addr)]?.let { row.put("comment", it) }
            arr.put(row)
        }
        val out = JSONObject()
            .put("function", hx(fn.addr))
            .put("name", effectiveName(fn.addr))
            .put("size", fn.size)
            .put("arch", d.arch)
            .put("blocks", d.blocks.size)
            .put("blocksFound", maxOf(d.blocksTotal, d.blocks.size))
            .put("instructions", arr)
        if (asked != fn.addr) {
            out.put("note", "${hx(asked)} is inside this function, which starts at ${hx(fn.addr)}.")
        }
        // `total` from paginate() is the number of instructions this listing
        // HAS, and the listing is a window: a body larger than the engine's asm
        // window stops early. Without this a caller reads the last instruction
        // it was given as the last instruction of the function.
        if (d.asmTruncated) {
            out.put("listingTruncated", true)
            out.put("bytesDisassembled", d.asmBytes)
            out.put(
                "coverage",
                "The disassembler covered ${d.asmBytes} of this function's ${d.size} bytes; " +
                    "the instructions here stop before the end of it."
            )
        }
        paginate(out, d.asm.size, w, page.size)
        return Outcome(out, "${effectiveName(fn.addr)} · ${page.size} of ${d.asm.size} instructions")
    }

    private fun decompile(args: JSONObject): Outcome {
        val asked = addressArg(args, "address")
        val backend = enumArg(args, "backend", listOf("current", "ghidra", "ir"), "current")
        val fn = resolveFunction(asked)
        val d = functionDetail(fn.addr, backend)
        val out = JSONObject()
            .put("function", hx(fn.addr))
            .put("name", effectiveName(fn.addr))
            .put("engineName", d.displayName)
            .put("size", d.size)
            .put("backend", d.backend)
            .put("arch", d.arch)
            .put("pseudoMode", d.pseudoMode)
            .put("blocks", d.blocks.size)
            .put("blocksFound", maxOf(d.blocksTotal, d.blocks.size))
            .put("callers", maxOf(d.nCallers, d.xrefsInTotal))
            .put("callees", maxOf(d.nCallees, d.xrefsOutTotal))
        d.irStats?.let {
            out.put(
                "irStats",
                JSONObject().put("statements", it.stmts).put("whiles", it.whiles)
                    .put("ifs", it.ifs).put("gotos", it.gotos).put("calls", it.calls)
            )
        }
        val text = d.pseudo
        if (text.length > PSEUDO_CAP) {
            out.put("pseudoC", text.take(PSEUDO_CAP))
            out.put("truncated", true)
            out.put("totalCharacters", text.length)
        } else {
            out.put("pseudoC", text)
            out.put("truncated", false)
        }
        if (asked != fn.addr) {
            out.put("note", "${hx(asked)} is inside this function, which starts at ${hx(fn.addr)}.")
        }
        return Outcome(out, "${effectiveName(fn.addr)} · ${d.backend} · ${text.length} chars")
    }

    /**
     * decompile_functions: a batch of functions down the exact same
     * [functionDetail] path decompile_function uses, so a row here cannot drift
     * from a single-function row. Bounded twice over — at most [BATCH_MAX]
     * functions, and it stops once the pseudo-C it has gathered passes
     * [BATCH_PSEUDO_CAP] — and it reports how far it got either way.
     *
     * Range mode reads its addresses from [nativeFunctionPage], the same
     * whole-binary walk list_functions scope=all uses, without ever adding them
     * to the app's loaded set. A function the engine cannot decompile becomes a
     * row with an `error`, not a failed call.
     */
    private fun decompileBatch(args: JSONObject): Outcome {
        val m = openMeta()
        val backend = enumArg(args, "backend", listOf("current", "ghidra", "ir"), "current")

        val explicit = addressList(args, "addresses")
        val rangeMode = explicit == null

        val targets: List<Long>
        val requested: Int
        var offset = 0
        var functionsTotal = 0
        if (rangeMode) {
            offset = intArg(args, "offset", 0, 0, Int.MAX_VALUE)
            val count = intArg(args, "count", 8, 1, BATCH_MAX)
            val page = parseFunctionPage(
                NativeBridge.nativeFunctionPage(openPath(), offset.toLong(), count.toLong())
            )
            if (!page.ok) throw Failure(page.error ?: "the engine could not page the function list.")
            functionsTotal = maxOf(page.functionsTotal, m.functionsTotal, m.functions.size)
            targets = page.functions.map { it.addr }
            requested = count
        } else {
            requested = explicit!!.size
            targets = explicit.take(BATCH_MAX)
        }

        val arr = JSONArray()
        var decompiled = 0
        var failed = 0
        var usedChars = 0
        var stoppedForSize = false
        for (addr in targets) {
            if (arr.length() > 0 && usedChars >= BATCH_PSEUDO_CAP) { stoppedForSize = true; break }
            val row = JSONObject().put("address", hx(addr))
            try {
                // Range rows are function starts from the engine; an explicit
                // address may point inside a body, so resolve it the way
                // decompile_function does, falling back to the address itself
                // when it names a function the app has not loaded.
                val start = if (rangeMode) addr
                    else try { resolveFunction(addr).addr } catch (e: Failure) { addr }
                val d = functionDetail(start, backend)
                if (start != addr) row.put("function", hx(start))
                row.put("name", session().renames[annotationKey(start)]
                    ?: d.name.ifBlank { "sub_" + annotationKey(start).removePrefix("0x").lowercase() })
                row.put("size", d.size)
                row.put("backend", d.backend)
                row.put("pseudoMode", d.pseudoMode)
                val text = d.pseudo
                if (text.length > PSEUDO_CAP) {
                    row.put("pseudoC", text.take(PSEUDO_CAP)).put("truncated", true)
                        .put("totalCharacters", text.length)
                    usedChars += PSEUDO_CAP
                } else {
                    row.put("pseudoC", text).put("truncated", false)
                    usedChars += text.length
                }
                decompiled += 1
            } catch (e: Exception) {
                // One function the engine cannot decompile is a row with an
                // error, never a failed batch. Failure is an Exception too, so
                // its clean message rides the same path.
                row.put("error", e.message ?: "could not decompile this address")
                failed += 1
            }
            arr.put(row)
        }

        val consumed = arr.length()
        val out = JSONObject()
            .put("mode", if (rangeMode) "range" else "addresses")
            .put("backend", backend)
            .put("requested", requested)
            .put("count", consumed)
            .put("decompiled", decompiled)
            .put("failed", failed)
            .put("functions", arr)
        if (stoppedForSize) out.put("stoppedForSize", true)
        if (rangeMode) {
            out.put("offset", offset)
            out.put("functionsTotal", functionsTotal)
            val next = offset + consumed
            if (consumed > 0 && next < functionsTotal) out.put("nextOffset", next)
            else out.put("nextOffset", JSONObject.NULL)
            if (stoppedForSize) out.put(
                "coverage",
                "Stopped after $consumed functions at the $BATCH_PSEUDO_CAP-character pseudo-C " +
                    "budget. Continue from nextOffset."
            )
        } else if (consumed < requested) {
            // Address mode leaves the rest to the caller, whether the BATCH_MAX
            // ceiling or the size budget is what stopped it.
            out.put(
                "coverage",
                "Returned $consumed of $requested requested" +
                    (if (stoppedForSize) ", stopping at the $BATCH_PSEUDO_CAP-character pseudo-C budget"
                    else "; at most $BATCH_MAX functions per call") +
                    " — send the remaining addresses in a follow-up call."
            )
        }
        return Outcome(out, "$decompiled decompiled, $failed failed" +
            (if (stoppedForSize) " (size cap)" else ""))
    }

    /** Address list from a string array argument, or null when absent or empty. */
    private fun addressList(args: JSONObject, name: String): List<Long>? {
        if (!args.has(name) || args.isNull(name)) return null
        val v = args.optJSONArray(name) ?: return null
        val out = ArrayList<Long>()
        for (i in 0 until v.length()) {
            val s = v.optString(i, "").trim()
            if (s.isEmpty()) continue
            out.add(parseAddr(s) ?: throw Failure("`$name`[$i] is not an address: \"$s\"."))
        }
        return if (out.isEmpty()) null else out
    }

    private fun xrefs(args: JSONObject): Outcome {
        val asked = addressArg(args, "address")
        val direction = enumArg(args, "direction", listOf("in", "out", "both"), "both")
        val fn = resolveFunction(asked)
        val vm = session()
        val d = functionDetail(fn.addr, "current")
        val out = JSONObject()
            .put("function", hx(fn.addr))
            .put("name", effectiveName(fn.addr))
        val w = window(args, 50, 200)
        var shown = 0
        var total = 0
        if (direction == "in" || direction == "both") {
            val rows = xrefRows(vm, d, true)
            val page = slice(rows, w)
            out.put("incoming", xrefArray(page))
            out.put("incomingTotal", maxOf(rows.size, vm.xrefInCount(d)))
            shown += page.size
            total += rows.size
        }
        if (direction == "out" || direction == "both") {
            val rows = xrefRows(vm, d, false)
            val page = slice(rows, w)
            out.put("outgoing", xrefArray(page))
            out.put("outgoingTotal", maxOf(rows.size, vm.xrefOutCount(d)))
            shown += page.size
            total += rows.size
        }
        paginate(out, total, w, shown)
        return Outcome(out, "${effectiveName(fn.addr)} · $direction · $shown of $total")
    }

    /**
     * The functions that reference a DATA address. Where [xrefs] resolves the
     * asked address to a function first — and so cannot serve a string, which
     * belongs to none — this hands the exact address to the engine's data-aware
     * reference map and maps each referencing site to its function. Paginates
     * over the rows the engine returned; when its per-address cap dropped some,
     * `referencesFound` names the honest total beside them, the same way
     * list_strings names `stringsFound`.
     */
    private fun findStringXrefs(args: JSONObject): Outcome {
        val addr = addressArg(args, "address")
        openMeta()
        val path = openPath()
        val x = parseAddressXrefs(NativeBridge.nativeXrefsTo(path, addr))
        if (!x.ok) throw Failure(x.error ?: "the engine could not read references to ${hx(addr)}")
        val vm = session()
        val w = window(args, 50, 200)
        val page = slice(x.refs, w)
        val arr = JSONArray()
        for (r in page) {
            val row = JSONObject().put("site", hx(r.from)).put("type", r.type)
            if (r.funcAddr != 0L) {
                row.put("function", hx(r.funcAddr))
                // A user rename in the app wins; otherwise the engine's
                // demangled name, which the app carries too. Same source of
                // truth as the `xrefs` tool, so the two never name one
                // function two ways.
                row.put(
                    "name",
                    if (vm.functionAt(r.funcAddr) != null) effectiveName(r.funcAddr)
                    else r.funcDisplay.ifBlank { r.funcName }.ifBlank { hx(r.funcAddr) }
                )
            } else {
                row.put("function", JSONObject.NULL)
                row.put("name", JSONObject.NULL)
                row.put("note", "outside any known function")
            }
            arr.put(row)
        }
        val out = JSONObject()
            .put("target", hx(x.target))
            .put("targetKind", x.targetKind)
        if (x.value != null) {
            if (x.value.length > 240) {
                out.put("value", x.value.take(240)).put("valueTruncated", true)
                    .put("valueLength", x.value.length)
            } else out.put("value", x.value)
        }
        out.put("references", arr)
        // `total` here paginates the rows that exist; the engine's own total can
        // be larger when its 500-row per-address cap dropped some, and that is
        // named separately so nextOffset never promises a row that was dropped.
        paginate(out, x.refs.size, w, page.size)
        if (x.total > x.refs.size) {
            out.put("referencesFound", x.total)
            out.put(
                "coverage",
                "The engine counted ${x.total} references to ${hx(addr)} and returned " +
                    "the first ${x.refs.size}."
            )
        }
        val tail = when (x.targetKind) {
            "code" -> " · code address, so these are its callers — xrefs is the tool for a function"
            "data" -> if (x.total == 0) " · nothing references this address" else ""
            else -> if (x.total == 0) " · nothing references this string" else ""
        }
        return Outcome(out, "${x.targetKind} ${hx(addr)} · ${page.size} of ${x.total}$tail")
    }

    /**
     * The anti-analysis / pinning scan, grouped by category. Mirrors
     * [findStringXrefs]: it hands the open binary to the engine's read-only
     * scan (Engine::detect, which reuses the reference map [findStringXrefs]
     * uses) and paginates over the flat detection list, grouping the page by
     * category. `counts` carries the whole-binary per-category totals so paging
     * never hides a category, and a function's name comes from the SAME source
     * of truth as every other tool — a user rename wins, else the demangled
     * name — so a detection never names a function differently from `xrefs`.
     */
    private fun scanProtections(args: JSONObject): Outcome {
        openMeta()
        val path = openPath()
        val res = parseDetections(NativeBridge.nativeDetect(path))
        if (!res.ok) throw Failure(res.error ?: "the engine could not scan the open binary")
        val vm = session()

        val cat = enumArg(
            args, "category",
            listOf(
                "all", "ssl-pinning", "root-detection", "anti-debug",
                "anti-frida", "emulator-detection", "tamper-detection"
            ),
            "all"
        )
        val minConf = enumArg(args, "minConfidence", listOf("low", "medium", "high"), "low")
        val minRank = confRank(minConf)

        val filtered = res.detections.filter {
            (cat == "all" || it.category == cat) && confRank(it.confidence) >= minRank
        }
        val w = window(args, 100, 400)
        val page = slice(filtered, w)

        // Group the page by category, keeping the engine's category order.
        val grouped = LinkedHashMap<String, MutableList<Detection>>()
        for (d in page) grouped.getOrPut(d.category) { mutableListOf() }.add(d)

        val cats = JSONArray()
        for ((category, list) in grouped) {
            val arr = JSONArray()
            for (d in list) {
                val row = JSONObject()
                    .put("confidence", d.confidence)
                    .put("evidence", d.evidence)
                    .put("source", d.source)
                    .put("tokens", JSONArray(d.tokens))
                if (d.funcAddr != 0L) {
                    row.put("function", hx(d.funcAddr))
                    row.put(
                        "name",
                        if (vm.functionAt(d.funcAddr) != null) effectiveName(d.funcAddr)
                        else d.funcDisplay.ifBlank { d.funcName }.ifBlank { hx(d.funcAddr) }
                    )
                    row.put("site", hx(d.site))
                } else {
                    row.put("function", JSONObject.NULL)
                    row.put("name", JSONObject.NULL)
                    row.put("note", "unattributed — a matched string nothing references")
                }
                if (d.stringAddr != 0L) row.put("stringAddress", hx(d.stringAddr))
                val v = d.value
                if (v != null) {
                    if (v.length > 160) row.put("value", v.take(160)).put("valueTruncated", true)
                    else row.put("value", v)
                }
                arr.put(row)
            }
            cats.put(
                JSONObject()
                    .put("category", category)
                    .put("count", res.counts[category] ?: list.size)
                    .put("detections", arr)
            )
        }

        val out = JSONObject().put("categories", cats)
        // Whole-binary per-category totals, so a page never hides a category.
        val countsObj = JSONObject()
        for ((k, n) in res.counts) countsObj.put(k, n)
        out.put("counts", countsObj)
        out.put("unattributed", res.unattributed)
        if (res.total > res.detections.size) {
            out.put("detectionsFound", res.total)
            out.put(
                "coverage",
                "The engine found ${res.total} detections and returned the first ${res.detections.size}."
            )
        }
        paginate(out, filtered.size, w, page.size)
        val tail = buildString {
            if (cat != "all") append(" · $cat")
            if (minConf != "low") append(" · >= $minConf")
            if (filtered.isEmpty()) append(" · nothing matched")
        }
        return Outcome(out, "${page.size} of ${filtered.size} detections$tail")
    }

    // ------------------------------------------------------------ DEX / smali --

    /** The open binary as a DEX, or a clear failure when it is not one. */
    private fun openDex(): AnalysisMeta {
        val m = openMeta()
        if (m.format != "DEX") throw Failure(
            "The open file is ${m.format.ifBlank { "not a DEX" }}, and this tool decodes Dalvik " +
                "bytecode. Open a .dex — or an APK, whose classes.dex is extracted for you."
        )
        return m
    }

    private fun dexMethodSmali(args: JSONObject): Outcome {
        openDex()
        val addr = addressArg(args, "address")
        val s = parseSmali(NativeBridge.nativeDexSmali(openPath(), addr))
        if (!s.ok) throw Failure(s.error ?: "the engine could not decode a method at ${hx(addr)}")
        val w = window(args, 200, ASM_CAP)
        val page = slice(s.lines, w)
        val arr = JSONArray()
        for (l in page) {
            val row = JSONObject()
                .put("offset", hx(l.off))
                .put("unit", l.unit)
                .put("bytes", l.bytes)
                .put("mnemonic", l.mnem)
                .put("operands", l.ops)
            if (l.comment.isNotEmpty()) row.put("comment", l.comment)
            arr.put(row)
        }
        val method = JSONObject()
            .put("address", hx(s.addr))
            .put("name", s.name)
            .put("class", s.clazz)
            .put("method", s.method)
            .put("proto", s.proto)
            .put("registers", s.registers)
            .put("ins", s.ins)
            .put("outs", s.outs)
            .put("tries", s.tries)
            .put("instructions", s.lines.size)
            .put("insnBytes", s.insnBytes)
            .put("callers", s.nCallers)
            .put("callees", s.nCallees)
        val out = JSONObject().put("method", method).put("smali", arr)
        if (s.truncated) {
            out.put("listingTruncated", true)
            out.put("coverage", "The decode stopped early; the smali here is not the whole method.")
        }
        paginate(out, s.lines.size, w, page.size)
        return Outcome(out, "${s.name} · ${page.size} of ${s.lines.size} smali lines")
    }

    private fun dexStrings(args: JSONObject): Outcome {
        openDex()
        val q = textArg(args, "query", false).trim()
        val w = window(args, 50, 200)
        val page = parseDexStrings(
            NativeBridge.nativeDexStrings(openPath(), q, w.offset.toLong(), w.limit.toLong())
        )
        if (!page.ok) throw Failure(page.error ?: "the engine could not search the DEX string pool")
        val arr = JSONArray()
        for (s in page.rows) {
            val row = JSONObject().put("address", hx(s.addr))
            if (s.value.length > 240) {
                row.put("value", s.value.take(240)).put("truncated", true).put("length", s.value.length)
            } else {
                row.put("value", s.value)
            }
            arr.put(row)
        }
        val out = JSONObject().put("strings", arr)
        if (q.isNotEmpty()) out.put("query", q)
        out.put("total", page.total)
        out.put("offset", page.offset)
        out.put("count", page.rows.size)
        val next = page.offset + page.rows.size
        if (next < page.total) out.put("nextOffset", next) else out.put("nextOffset", JSONObject.NULL)
        out.put("poolRead", page.poolRead)
        out.put("poolTotal", page.poolTotal)
        if (page.poolTotal > page.poolRead) out.put(
            "coverage",
            "Searched ${page.poolRead} of ${page.poolTotal} string_ids; the loader capped the pool."
        )
        val note = if (q.isEmpty()) "" else " matching \"$q\""
        return Outcome(out, "${page.rows.size} of ${page.total}$note")
    }

    private fun dexFindMethodXrefs(args: JSONObject): Outcome {
        openDex()
        val addr = addressArg(args, "address")
        val dir = enumArg(args, "direction", listOf("callers", "callees", "both"), "both")
        val x = parseDexMethodXrefs(NativeBridge.nativeDexMethodXrefs(openPath(), addr))
        if (!x.ok) throw Failure(x.error ?: "the engine could not read xrefs for ${hx(addr)}")
        val w = window(args, 50, 200)
        val out = JSONObject().put("method", x.name).put("address", hx(x.addr))
        var shown = 0
        var total = 0
        if (dir == "callers" || dir == "both") {
            val page = slice(x.callers, w)
            out.put("callers", dexEdgeArray(page))
            out.put("callersTotal", x.callersTotal)
            shown += page.size; total += x.callers.size
        }
        if (dir == "callees" || dir == "both") {
            val page = slice(x.callees, w)
            out.put("callees", dexEdgeArray(page))
            out.put("calleesTotal", x.calleesTotal)
            shown += page.size; total += x.callees.size
        }
        paginate(out, total, w, shown)
        return Outcome(out, "${x.name} · $dir · callers ${x.callersTotal}, callees ${x.calleesTotal}")
    }

    private fun dexEdgeArray(edges: List<com.trickhook.model.DexXrefEdge>): JSONArray {
        val arr = JSONArray()
        for (e in edges) {
            arr.put(
                JSONObject().put("address", hx(e.addr)).put("name", e.name)
                    .put("site", hx(e.site)).put("sites", e.sites)
            )
        }
        return arr
    }

    private fun confRank(c: String): Int = when (c) {
        "high" -> 2
        "medium" -> 1
        else -> 0
    }

    private fun xrefArray(rows: List<com.trickhook.ui.XrefRow>): JSONArray {
        val arr = JSONArray()
        for (r in rows) {
            val row = JSONObject()
                .put("site", hx(r.site))
                .put("name", r.label)
                .put("type", r.type)
            row.put("address", if (r.target != null) hx(r.target) else JSONObject.NULL)
            if (r.note.isNotEmpty()) row.put("note", r.note)
            arr.put(row)
        }
        return arr
    }

    private fun callGraph(args: JSONObject): Outcome {
        val vm = session()
        val m = openMeta()
        val limit = intArg(args, "limit", 60, 1, 200)
        val root = optionalAddress(args, "address")

        if (root == null) {
            val hubs = m.functions
                .sortedByDescending { it.nCallers + it.nCallees }
                .take(limit)
            val arr = JSONArray()
            for (f in hubs) {
                arr.put(
                    JSONObject().put("address", hx(f.addr)).put("name", effectiveName(f.addr))
                        .put("callers", f.nCallers).put("callees", f.nCallees)
                        .put("size", f.size)
                )
            }
            // "busiest" is ranked over the functions this app HOLDS, and the
            // ranking key is a degree taken from a capped reference map. Both
            // caveats belong in the answer: the real busiest function of a
            // 98,022-function binary may well be in a page nobody loaded.
            val fnFound = maxOf(m.functionsTotal, m.functions.size)
            val out = JSONObject()
                .put("scope", "whole binary")
                .put("functionsRanked", m.functions.size)
                .put("functionsTotal", fnFound)
                .put("callEdgesFound", maxOf(m.callEdgesTotal, m.callEdges.size))
                .put("callSitesTotal", m.callSitesTotal)
                .put("busiestFunctions", arr)
                .put(
                    "note",
                    "The whole graph is too large to return. Pass `address` to walk a " +
                        "neighbourhood of one function." +
                        (if (fnFound > m.functions.size)
                            " Ranked over the ${m.functions.size} functions loaded, of $fnFound found."
                        else "") +
                        (if (m.xrefsAreFloors)
                            " Caller and callee counts are floors: the reference map holds " +
                                "${m.xrefsStored} of ${m.xrefsTotal}."
                        else "")
                )
            return Outcome(out, "whole binary · ${hubs.size} busiest of ${m.functions.size}")
        }

        val fn = resolveFunction(root)
        val direction = enumArg(args, "direction", listOf("callers", "callees", "both"), "both")
        val depth = intArg(args, "depth", 2, 1, 4)

        val seen = LinkedHashMap<Long, Int>()
        val edgeKeys = HashSet<String>()
        val edges = ArrayList<CallEdge>()
        seen[fn.addr] = 0
        var frontier = listOf(fn.addr)
        var hop = 0
        var capped = false
        while (hop < depth && frontier.isNotEmpty() && !capped) {
            val next = ArrayList<Long>()
            for (addr in frontier) {
                val touching = ArrayList<CallEdge>()
                if (direction == "callers" || direction == "both") touching.addAll(vm.callersOf(addr))
                if (direction == "callees" || direction == "both") touching.addAll(vm.calleesOf(addr))
                for (e in touching) {
                    val key = "${e.from}>${e.to}"
                    if (edgeKeys.add(key)) edges.add(e)
                    val other = if (e.from == addr) e.to else e.from
                    if (!seen.containsKey(other)) {
                        if (seen.size >= limit) { capped = true; break }
                        seen[other] = hop + 1
                        next.add(other)
                    }
                }
                if (capped) break
            }
            frontier = next
            hop += 1
        }

        val nodes = JSONArray()
        for ((addr, d) in seen) {
            val info = vm.functionAt(addr)
            val node = JSONObject()
                .put("address", hx(addr))
                .put("name", effectiveName(addr))
                .put("depth", d)
            if (info != null) {
                node.put("callers", info.nCallers).put("callees", info.nCallees)
                    .put("size", info.size).put("source", info.from)
            } else {
                node.put("note", "referenced but not a function the engine mapped")
            }
            nodes.put(node)
        }
        val edgeArr = JSONArray()
        for (e in edges) {
            edgeArr.put(
                JSONObject()
                    .put("from", hx(e.from))
                    .put("to", hx(e.to))
                    .put("fromName", effectiveName(e.from))
                    .put("toName", if (vm.functionAt(e.to) != null) effectiveName(e.to) else e.toName)
                    .put("kind", e.kind.ifEmpty { "call" })
                    .put("site", hx(e.callSite))
                    .put("sites", e.sites)
            )
        }
        val out = JSONObject()
            .put("root", hx(fn.addr))
            .put("rootName", effectiveName(fn.addr))
            .put("direction", direction)
            .put("depth", depth)
            .put("functions", nodes)
            .put("edges", edgeArr)
            .put("truncated", capped)
        if (capped) {
            out.put(
                "note",
                "Stopped at the $limit-function cap before the walk finished. Raise `limit` " +
                    "or lower `depth`."
            )
        }
        return Outcome(out, "${effectiveName(fn.addr)} · ${seen.size} functions, ${edges.size} edges")
    }

    private fun readMemory(args: JSONObject): Outcome {
        val vm = session()
        val m = openMeta()
        val bytes = vm.hexData
            ?: throw Failure("Nocturne is not holding the open file's bytes — reopen the binary.")
        val length = intArg(args, "length", 256, 1, HEX_CAP)
        val virtual = optionalAddress(args, "address")
        val offset: Long
        var note = ""
        if (virtual != null) {
            val mapped = if (m.format == "ELF" || m.format == "PE") vm.fileOffsetOf(virtual) else virtual
            offset = mapped ?: throw Failure(
                "${hx(virtual)} is not inside any mapped section of this binary, so it has no " +
                    "place in the file. analysis_overview lists the sections and their address ranges."
            )
            if (m.format != "ELF" && m.format != "PE") {
                note = "This format is read as a flat file, so the address was used as a file offset."
            }
        } else {
            offset = args.optLong("offset", -1L)
            if (offset < 0) throw Failure("Give either `address` or `offset`.")
        }
        if (offset >= bytes.size) {
            throw Failure(
                "Offset ${offset} is past the ${bytes.size} bytes Nocturne holds" +
                    (if (m.sizeBytes > bytes.size) " (the first 8 MiB of a ${m.sizeBytes}-byte file)" else "") +
                    "."
            )
        }
        val start = offset.toInt()
        val end = minOf(bytes.size, start + length)
        val hex = StringBuilder((end - start) * 2)
        val ascii = StringBuilder(end - start)
        for (i in start until end) {
            val b = bytes[i].toInt() and 0xFF
            hex.append("0123456789abcdef"[b ushr 4])
            hex.append("0123456789abcdef"[b and 0xF])
            ascii.append(if (b in 0x20..0x7E) b.toChar() else '.')
        }
        val out = JSONObject()
            .put("fileOffset", start)
            .put("length", end - start)
            .put("hex", hex.toString())
            .put("ascii", ascii.toString())
            .put("bytesHeld", bytes.size)
        if (virtual != null) out.put("address", hx(virtual))
        if (note.isNotEmpty()) out.put("note", note)
        return Outcome(out, "${end - start} bytes at file offset $start")
    }

    private fun emulate(args: JSONObject): Outcome {
        val path = openPath()
        openMeta()
        val entry = addressArg(args, "entry")
        val request = JSONObject()
        request.put("entry", hx(entry))
        joinList(args, "args")?.let { request.put("args", it) }
        joinList(args, "regs")?.let { request.put("regs", it) }
        joinList(args, "write")?.let { request.put("write", it) }
        joinList(args, "read")?.let { request.put("read", it) }
        optionalAddress(args, "stopAt")?.let { request.put("stopAt", hx(it)) }
        request.put("maxInstr", intArg(args, "maxInstr", 200000, 1000, 2000000))
        request.put("timeoutMs", intArg(args, "timeoutMs", 3000, 100, 10000))
        request.put("maxPages", intArg(args, "maxPages", 1024, 16, 8192))
        request.put("maxCalls", intArg(args, "maxCalls", 4096, 16, 65536))
        request.put("strictUserops", if (boolArg(args, "strictUserops", false)) 1 else 0)

        val raw = NativeBridge.nativeEmulate(path, request.toString())
        val parsed = try {
            JSONObject(raw)
        } catch (e: Exception) {
            throw Failure("The emulator answered with something that is not JSON: ${raw.take(300)}")
        }
        val out = JSONObject()
        // useropsDropped rides along with the rest: the emulator's name table
        // holds 64 distinct p-code operations and silently discarded the 65th,
        // so `userops` below was itself a floor. It counts them now.
        for (k in listOf(
            "ok", "stop", "detail", "approximate", "instructions", "ms", "backend",
            "retReg", "ret", "dirtyBytes", "memoryTruncated", "callsTotal", "useropsDropped"
        )) {
            if (parsed.has(k)) out.put(k, parsed.get(k))
        }
        parsed.optJSONObject("limits")?.let { out.put("limits", it) }
        out.put("entry", hx(entry))
        copyArray(parsed, out, "args", 32, 0)
        copyArray(parsed, out, "regs", 64, 0)
        copyArray(parsed, out, "memory", 24, 8192)
        copyArray(parsed, out, "dirtyRanges", 64, 0)
        copyArray(parsed, out, "calls", 80, 0)
        copyArray(parsed, out, "userops", 40, 0)
        copyArray(parsed, out, "tail", 64, 0)
        val stop = parsed.optString("stop", "?")
        val ok = parsed.optBoolean("ok", false)
        val ran = if (ok) "" else " (did not complete)"
        return Outcome(out, "${hx(entry)} · $stop" + ran)
    }

    /** ';'-joined list for the flat emulator request, or null when absent. */
    private fun joinList(args: JSONObject, name: String): String? {
        if (!args.has(name) || args.isNull(name)) return null
        val v = args.get(name)
        val parts = ArrayList<String>()
        if (v is JSONArray) {
            for (i in 0 until v.length()) {
                val s = v.optString(i, "").trim()
                if (s.isNotEmpty()) parts.add(s)
            }
        } else {
            val s = v.toString().trim()
            if (s.isNotEmpty()) parts.add(s)
        }
        return if (parts.isEmpty()) null else parts.joinToString(";")
    }

    /**
     * Copy one array from the engine's answer, capped at [rows] elements and,
     * when [textCap] is non-zero, with each element's long string fields cut to
     * that many characters. A 1 MiB memory dump helps nobody read a transcript.
     */
    private fun copyArray(from: JSONObject, to: JSONObject, name: String, rows: Int, textCap: Int) {
        val src = from.optJSONArray(name) ?: return
        val dst = JSONArray()
        val n = minOf(src.length(), rows)
        for (i in 0 until n) {
            val item = src.opt(i)
            if (item is JSONObject && textCap > 0) {
                val copy = JSONObject()
                for (k in item.keys()) {
                    val value = item.get(k)
                    if (value is String && value.length > textCap) {
                        copy.put(k, value.take(textCap))
                        copy.put(k + "Truncated", true)
                    } else {
                        copy.put(k, value)
                    }
                }
                dst.put(copy)
            } else {
                dst.put(item)
            }
        }
        to.put(name, dst)
        if (src.length() > n) to.put(name + "Truncated", src.length() - n)
    }

    private fun listAnnotations(args: JSONObject): Outcome {
        val vm = session()
        openMeta()
        val kind = enumArg(
            args, "kind", listOf("all", "renames", "comments", "bookmarks", "notes"), "all"
        )
        val w = window(args, 100, 200)
        val out = JSONObject()
        var shown = 0
        var total = 0
        if (kind == "all" || kind == "renames") {
            val rows = vm.renames.entries
                .map { Pair(parseAddr(it.key) ?: 0L, it.value) }
                .sortedBy { it.first xor Long.MIN_VALUE }
            val page = slice(rows, w)
            val arr = JSONArray()
            for ((addr, name) in page) {
                arr.put(
                    JSONObject().put("address", hx(addr)).put("name", name)
                        .put("originalName", vm.functionAt(addr)?.name ?: JSONObject.NULL)
                )
            }
            out.put("renames", arr); shown += page.size; total += rows.size
        }
        if (kind == "all" || kind == "comments") {
            val rows = vm.comments.entries
                .map { Pair(parseAddr(it.key) ?: 0L, it.value) }
                .sortedBy { it.first xor Long.MIN_VALUE }
            val page = slice(rows, w)
            val arr = JSONArray()
            for ((addr, text) in page) {
                arr.put(JSONObject().put("address", hx(addr)).put("text", text))
            }
            out.put("comments", arr); shown += page.size; total += rows.size
        }
        if (kind == "all" || kind == "bookmarks") {
            val rows = vm.bookmarks
            val page = slice(rows, w)
            val arr = JSONArray()
            for (b in page) {
                arr.put(JSONObject().put("address", b.addr).put("label", b.label))
            }
            out.put("bookmarks", arr); shown += page.size; total += rows.size
        }
        if (kind == "all" || kind == "notes") {
            val rows = vm.notes()
            val page = slice(rows, w)
            val arr = JSONArray()
            for (n in page) {
                arr.put(JSONObject().put("title", n.title).put("body", n.body))
            }
            out.put("notes", arr); shown += page.size; total += rows.size
        }
        paginate(out, total, w, shown)
        return Outcome(out, "$kind · $shown of $total")
    }

    // ------------------------------------------------------------ writes --
    // These call the same ViewModel entry points the app's own UI calls, so a
    // rename from a client lands in ProjectDb, shows up in every panel, exports
    // to IDA and is rolled into the app's own undo — it is indistinguishable
    // from one typed on the device, which is the point.
    //
    // They run on the socket's IO thread rather than the main thread: SQLite is
    // file I/O and does not belong on the main thread, and the Compose snapshot
    // state these touch is safe to write from any thread — the recomposition it
    // schedules lands on the main thread by itself.

    private fun rename(args: JSONObject): Outcome {
        val vm = session()
        val ctx = McpService.appContextOrNull()
            ?: throw Failure("The server is not running, so there is nothing to write with.")
        openMeta()
        val asked = addressArg(args, "address")
        val name = textArg(args, "name", true).trim()
        if (name.isEmpty()) throw Failure("`name` cannot be empty.")
        if (name.length > 200) throw Failure("`name` is longer than 200 characters.")
        val fn = vm.functionAt(asked)
            ?: throw Failure(
                "${hx(asked)} is not a function start. Rename the function that contains it " +
                    "instead — disassemble_function reports which one that is."
            )
        val before = effectiveName(fn.addr)
        vm.renameFunction(ctx, fn.addr, name)
        val out = JSONObject()
            .put("address", hx(fn.addr))
            .put("previousName", before)
            .put("name", name)
            .put("storedIn", "Nocturne project database — the binary on disk is unchanged")
        return Outcome(out, "${hx(fn.addr)} $before -> $name")
    }

    private fun comment(args: JSONObject): Outcome {
        val vm = session()
        val ctx = McpService.appContextOrNull()
            ?: throw Failure("The server is not running, so there is nothing to write with.")
        openMeta()
        val addr = addressArg(args, "address")
        val text = textArg(args, "text", true)
        if (text.length > 4000) throw Failure("`text` is longer than 4000 characters.")
        vm.addComment(ctx, addr, text)
        val out = JSONObject()
            .put("address", hx(addr))
            .put("removed", text.isBlank())
            .put("text", text)
        val verb = if (text.isBlank()) " comment removed" else " commented"
        return Outcome(out, hx(addr) + verb)
    }

    private fun bookmark(args: JSONObject): Outcome {
        val vm = session()
        val ctx = McpService.appContextOrNull()
            ?: throw Failure("The server is not running, so there is nothing to write with.")
        openMeta()
        val addr = addressArg(args, "address")
        val label = textArg(args, "label", true).trim()
        if (label.isEmpty()) throw Failure("`label` cannot be empty.")
        if (label.length > 200) throw Failure("`label` is longer than 200 characters.")
        vm.addBookmark(ctx, addr, label)
        return Outcome(
            JSONObject().put("address", hx(addr)).put("label", label),
            "${hx(addr)} bookmarked as \"$label\""
        )
    }
}
